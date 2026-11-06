import { randomUUID } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };
import safePolicy from '../policy-backup/safe-policy.json' with { type: 'json' };
import { RULE_IDS } from './decider.mjs';
import { BURST_LIMIT, BURST_WINDOW_MS } from './detect.mjs';
import { hashSnapshot } from './policy-backup.mjs';
import { RESTORE_TARGET } from './restore-handler.mjs';

// 12단계: 탈환 작전실 요약 GET /api/ops (로그인 + 승인된 기기 서명이 있어야 응답).
// 항목마다 출처를 붙입니다.
//   api     = 이 요청에서 서버가 DB를 실제로 읽은 결과
//   code    = 검사한 커밋의 코드·설정에 정해진 값(실행 결과가 아님)
//   not_run = 아직 실행·연결되지 않아 결과가 없음
// 메모 제목·본문, 사용자 번호(owner_id), 토큰, 키는 응답에 넣지 않습니다. 기기 지문은 앞 12자리만 보입니다.
// 화면의 수치는 같은 응답의 records 배열에서 세며, records 는 가린 서버 기록 그대로입니다.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const RECENT = 50;

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

const countBy = (rows, key) => rows.reduce((counts, row) => ({ ...counts, [row[key]]: (counts[row[key]] ?? 0) + 1 }), {});

export async function handleOpsRequest(request, response, options = {}) {
  const { env = process.env, fetchImpl = globalThis.fetch, verifyLogin, requireDevice, log = () => {} } = options;
  const deny = (status, error, reason) => {
    log({ event: 'api_denied', zone: 'ops', method: request.method, reason });
    return sendJson(response, status, { error });
  };
  if (request.method !== 'GET') {
    response.setHeader('allow', 'GET');
    return deny(405, 'METHOD_NOT_ALLOWED', 'method');
  }
  let user;
  try {
    if (typeof verifyLogin !== 'function') throw new TypeError('missing_verifier');
    user = await verifyLogin(request.headers?.authorization);
  } catch {
    return sendJson(response, 503, { error: 'AUTH_NOT_CONFIGURED' });
  }
  if (!user || user.kind !== 'student' || typeof user.userId !== 'string' || !UUID.test(user.userId)) {
    response.setHeader('www-authenticate', 'Bearer');
    return deny(401, 'UNAUTHORIZED', 'no_valid_login');
  }
  if (typeof requireDevice !== 'function') return sendJson(response, 503, { error: 'DEVICES_NOT_CONFIGURED' });
  const device = await requireDevice(user);
  if (!device.ok) return deny(device.status ?? 403, device.error, device.reason);

  const origin = supabaseOrigin(env.SUPABASE_URL);
  const secretKey = env.SUPABASE_SECRET_KEY;
  if (!origin || typeof secretKey !== 'string' || secretKey.length === 0) {
    return sendJson(response, 503, { error: 'OPS_NOT_CONFIGURED' });
  }
  // 정해진 칸만 고르는 읽기 전용 요청입니다. 본문이 들어 있는 칸(title·content)은 고르지 않습니다.
  const read = async (table, params) => {
    const url = new URL(`/rest/v1/${table}`, origin);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    try {
      const result = await fetchImpl(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { apikey: secretKey, authorization: `Bearer ${secretKey}`, accept: 'application/json' } });
      if (!result.ok) return null;
      const rows = await result.json();
      return Array.isArray(rows) ? rows : null;
    } catch {
      return null;
    }
  };
  const [devices, audits, backups] = await Promise.all([
    read('device_approvals', { select: 'key_thumbprint,owner_id,status,requested_at,decided_at',
      order: 'requested_at.desc', limit: String(RECENT) }),
    read('restore_audit', { select: 'seq,at,actor_kind,before_state,result', order: 'seq.desc', limit: String(RECENT) }),
    read('notes_restore_backup', { select: 'id,content_sha256,captured_at', id: `eq.${RESTORE_TARGET.id}` }),
  ]);

  const deviceRecords = devices?.map(row => ({
    device: String(row.key_thumbprint).slice(0, 12), mine: row.owner_id === user.userId,
    status: row.status, requestedAt: row.requested_at, decidedAt: row.decided_at ?? null,
  })) ?? null;
  const auditRecords = audits?.map(row => ({
    seq: row.seq, at: row.at, actor: row.actor_kind, beforeState: row.before_state, result: row.result,
  })) ?? null;
  const backup = backups?.length === 1 ? backups[0] : null;

  const body = {
    requestId: randomUUID(),
    checkedAt: new Date().toISOString(),
    decider: {
      source: 'code',
      ruleIds: [...RULE_IDS],
      allowedRoutes: [...config.allowedRoutes],
      note: '검사한 커밋의 판정기 규칙 이름과 허용 경로입니다. 운영 엔진의 실제 판정 기록은 이 서버가 받지 않습니다.',
    },
    detection: {
      source: 'not_run',
      rule: { reasonCode: 'burst_read', limit: BURST_LIMIT, windowMinutes: BURST_WINDOW_MS / 60000 },
      events: null,
      note: '운영 반 엔진의 사건 전달이 연결되지 않아 실제 탐지 사건이 없습니다. 규칙은 npm run detect:test 가상 사건으로만 연습했습니다.',
    },
    revocation: deviceRecords ? {
      source: 'api',
      counts: { pending: 0, approved: 0, revoked: 0, ...countBy(deviceRecords, 'status') },
      total: deviceRecords.length,
      records: deviceRecords,
      note: `기기 승인 표(device_approvals)의 최근 ${RECENT}건입니다. 회수는 status = revoked 입니다. 다른 사람 기기는 mine=false로만 표시합니다.`,
    } : { source: 'not_run', records: null, note: '기기 승인 표를 읽지 못했습니다.' },
    recovery: {
      policy: {
        source: 'code',
        version: safePolicy.version,
        sourceCommit: String(safePolicy.sourceCommit).slice(0, 7),
        createdAt: safePolicy.createdAt,
        sha256: hashSnapshot(safePolicy),
      },
      noteBackup: backup ? {
        source: 'api', noteId: backup.id, contentSha256Prefix: String(backup.content_sha256).slice(0, 12),
        capturedAt: backup.captured_at,
      } : { source: 'not_run', noteId: RESTORE_TARGET.id, note: '복원 사본을 읽지 못했습니다.' },
      audit: auditRecords ? {
        source: 'api',
        counts: countBy(auditRecords, 'result'),
        total: auditRecords.length,
        records: auditRecords,
      } : { source: 'not_run', records: null, note: '복원 감사 기록을 읽지 못했습니다.' },
    },
  };
  return sendJson(response, 200, body);
}
