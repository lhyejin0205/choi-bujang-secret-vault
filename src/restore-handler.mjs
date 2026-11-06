import { createHash } from 'node:crypto';

// 10단계: 시험 계정 B의 가상 메모 한 건만 비공개 사본(public.notes_restore_backup)에서 되돌리는 경로입니다.
//   서비스: notes(자료 API 서버 함수)   경로: POST /api/restore  (vercel.json → /api/notes?zone=restore)
// - 대상은 아래 RESTORE_TARGET 한 건으로 고정합니다. 요청 본문·쿼리로 다른 메모를 고를 수 없습니다.
// - 사본의 ID·소유자·내용 해시를 먼저 대조하고, 맞지 않으면 아무것도 바꾸지 않고 중단합니다.
// - 그 한 건만 id 조건으로 되돌리며, 다른 메모와 감사 기록(public.restore_audit)은 지우거나 고치지 않습니다.
// - 호출은 검증된 로그인 사용자 가운데 메모 주인(B) 본인이나 심판 토큰만 할 수 있습니다.
// - 응답과 기록에는 메모 제목·본문·토큰·사용자 번호를 넣지 않습니다.
export const RESTORE_TARGET = Object.freeze({
  id: '7cd005ec-cbad-47d4-9100-3a48e0f04269',
  ownerId: 'a6a7947a-0843-4aa2-801f-0c0a9e15b616',
});
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

// SQL의 encode(sha256(convert_to(title || E'\n' || content, 'UTF8')), 'hex')와 같은 값입니다.
export function contentHash(title, content) {
  return createHash('sha256').update(`${title}\n${content}`, 'utf8').digest('hex');
}

function sendJson(response, status, body) {
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('cache-control', 'no-store');
  return response.status(status).json(body);
}

function supabaseOrigin(value) {
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) return null;
  return url.origin;
}

const validRow = row => row && typeof row === 'object' && typeof row.id === 'string'
  && typeof row.owner_id === 'string' && typeof row.title === 'string' && typeof row.content === 'string';

export async function handleRestoreRequest(request, response, options = {}) {
  const { env = process.env, fetchImpl = globalThis.fetch, verifyLogin, log = () => {} } = options;
  const target = RESTORE_TARGET;
  const note = (status, body, reason) => {
    log({ event: 'restore', zone: 'note', reason });
    return sendJson(response, status, body);
  };
  if (request.method !== 'POST') {
    response.setHeader('allow', 'POST');
    return note(405, { error: 'METHOD_NOT_ALLOWED' }, 'method');
  }

  let user;
  try {
    if (typeof verifyLogin !== 'function') throw new TypeError('missing_verifier');
    user = await verifyLogin(request.headers?.authorization);
  } catch {
    return sendJson(response, 503, { error: 'AUTH_NOT_CONFIGURED' });
  }
  if (!user || typeof user.userId !== 'string' || user.userId.length === 0) {
    response.setHeader('www-authenticate', 'Bearer');
    return note(401, { error: 'UNAUTHORIZED' }, 'no_valid_login');
  }
  const actorKind = user.kind === 'judge' ? 'judge'
    : (user.kind === 'student' && UUID.test(user.userId) && user.userId.toLowerCase() === target.ownerId ? 'owner' : null);
  if (!actorKind) return note(403, { error: 'NOT_RESTORE_OWNER' }, 'not_owner');

  const origin = supabaseOrigin(env.SUPABASE_URL);
  const secretKey = env.SUPABASE_SECRET_KEY;
  if (!origin || typeof secretKey !== 'string' || secretKey.length === 0) {
    return sendJson(response, 503, { error: 'NOTES_NOT_CONFIGURED' });
  }
  const upstream = (table, method, params, body, prefer) => {
    const url = new URL(`/rest/v1/${table}`, origin);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    const headers = { apikey: secretKey, authorization: `Bearer ${secretKey}`, accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (prefer) headers.prefer = prefer;
    return fetchImpl(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error', signal: AbortSignal.timeout(10000) });
  };
  const rowsOf = async (result) => {
    if (!result.ok) return null;
    const rows = await result.json();
    return Array.isArray(rows) && rows.every(validRow) ? rows : null;
  };
  const one = { id: `eq.${target.id}` };
  const select = 'id,owner_id,title,content';
  const fail = reason => note(502, { error: 'RESTORE_FAILED' }, reason);

  try {
    // 1) 비공개 사본을 다시 읽어 ID·소유자·내용 해시를 대조합니다. 하나라도 다르면 중단합니다.
    const backups = await rowsOf(await upstream('notes_restore_backup', 'GET',
      { select: `${select},content_sha256`, limit: '2', ...one }));
    if (!backups) return fail('backup_read_failed');
    const [backup] = backups;
    if (backups.length !== 1 || backup.id !== target.id || backup.owner_id !== target.ownerId
        || typeof backup.content_sha256 !== 'string'
        || contentHash(backup.title, backup.content) !== backup.content_sha256) {
      return note(409, { error: 'BACKUP_MISMATCH' }, 'backup_mismatch');
    }

    // 2) 지금 상태를 봅니다(없음·같음·변조됨). 다른 메모는 읽지 않습니다.
    const current = await rowsOf(await upstream('notes', 'GET', { select, limit: '2', ...one }));
    if (!current || current.length > 1) return fail('current_read_failed');
    const now = current[0];
    const same = now && now.owner_id === backup.owner_id && contentHash(now.title, now.content) === backup.content_sha256;
    const beforeState = !now ? 'deleted' : (same ? 'unchanged' : 'tampered');

    // 3) 그 한 건만 되돌립니다. 지워졌으면 같은 id로 다시 넣고, 바뀌었으면 id 조건으로 고칩니다.
    const restoredFields = { owner_id: backup.owner_id, title: backup.title, content: backup.content };
    if (beforeState === 'deleted') {
      const inserted = await rowsOf(await upstream('notes', 'POST', {}, { id: backup.id, ...restoredFields },
        'return=representation'));
      if (!inserted || inserted.length !== 1) return fail('insert_failed');
    } else if (beforeState === 'tampered') {
      const patched = await rowsOf(await upstream('notes', 'PATCH', { select, ...one }, restoredFields,
        'return=representation'));
      if (!patched || patched.length !== 1) return fail('patch_failed');
    }

    // 4) 되돌린 행을 다시 읽어 사본과 같은지 확인합니다.
    const after = await rowsOf(await upstream('notes', 'GET', { select, limit: '2', ...one }));
    const row = after?.length === 1 ? after[0] : null;
    const check = {
      idMatches: row?.id === backup.id,
      ownerMatches: row?.owner_id === backup.owner_id,
      contentHashMatches: Boolean(row) && contentHash(row.title, row.content) === backup.content_sha256,
    };
    const ok = check.idMatches && check.ownerMatches && check.contentHashMatches;

    // 5) 감사 기록은 덧붙이기만 합니다. 기록에 실패해도 이미 되돌린 메모는 그대로 둡니다.
    const audit = await upstream('restore_audit', 'POST', {}, {
      note_id: backup.id, actor_kind: actorKind, before_state: beforeState, result: ok ? 'restored' : 'verify_failed',
    }, 'return=minimal').catch(() => null);
    const audited = Boolean(audit?.ok);
    log({ event: 'restore', zone: 'note', reason: ok ? `restored_from_${beforeState}` : 'verify_failed', audited });
    if (!ok) return sendJson(response, 502, { error: 'RESTORE_VERIFY_FAILED', ...check, audited });
    return sendJson(response, 200, { restored: backup.id, beforeState, ...check, audited });
  } catch {
    return fail('upstream_error');
  }
}
