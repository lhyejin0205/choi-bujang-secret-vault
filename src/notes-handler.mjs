import { randomUUID } from 'node:crypto';

// 자료 API. 모든 요청은 먼저 verifyLogin(src/verify-login.mjs)으로 토큰을 검사합니다.
// 사용자 번호는 검사를 통과한 토큰에서만 얻습니다. URL·본문의 userId·role·owner_id는 믿지 않습니다.
// 4단계: 읽기·추가·수정·삭제 모두 검증된 사용자 번호와 DB의 owner_id가 같을 때만 허용합니다.
// 남의 메모는 없는 메모와 똑같이 404로 답해, 그런 id가 있는지도 알려 주지 않습니다.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const MAX_TITLE = 200;
const MAX_BODY = 5000;

function sendJson(response, status, body) {
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('cache-control', 'no-store');
  return response.status(status).json(body);
}

function supabaseOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) return null;
  return url.origin;
}

// Vercel이 /api/notes/:id 를 /api/notes?id=:id 로 넘겨 줍니다 (vercel.json의 rewrites).
function routeId(request) {
  const query = request.query;
  if (!query || typeof query !== 'object' || !Object.hasOwn(query, 'id')) return undefined;
  return typeof query.id === 'string' ? query.id : '';
}

function jsonBody(request) {
  let body = request.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

function noteFields(body) {
  if (!body || typeof body.title !== 'string' || typeof body.body !== 'string') return null;
  const title = body.title.trim();
  if (!title || title.length > MAX_TITLE || body.body.length > MAX_BODY) return null;
  return { title, content: body.body };
}

const validRow = row => row && typeof row === 'object' && UUID.test(row.id ?? '')
  && typeof row.title === 'string' && typeof row.content === 'string';
// 본문에 주인을 바꾸려는 값이 들어 있는지 봅니다. 값은 쓰지 않고, 본인이 아니면 거부에만 씁니다.
const OWNER_KEYS = ['owner_id', 'ownerId', 'userId', 'user_id'];
const triesOtherOwner = (body, userId) => OWNER_KEYS.some(key => body
  && Object.hasOwn(body, key) && body[key] !== userId);
const noteOut = row => ({ id: row.id, title: row.title, body: row.content });

export async function handleNotesRequest(request, response, options = {}) {
  const { env = process.env, fetchImpl = globalThis.fetch, verifyLogin } = options;
  const id = routeId(request);
  const allowed = id === undefined ? ['GET', 'POST'] : ['GET', 'PUT', 'DELETE'];
  if (!allowed.includes(request.method)) {
    response.setHeader('allow', allowed.join(', '));
    return sendJson(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }

  // 1) 로그인 검사. 토큰이 없거나 검사에 실패하면 자료 없이 거부합니다.
  let user;
  try {
    if (typeof verifyLogin !== 'function') throw new TypeError('missing_verifier');
    user = await verifyLogin(request.headers?.authorization);
  } catch {
    return sendJson(response, 503, { error: 'AUTH_NOT_CONFIGURED' });
  }
  if (!user || typeof user.userId !== 'string' || !UUID.test(user.userId)) {
    response.setHeader('www-authenticate', 'Bearer');
    return sendJson(response, 401, { error: 'UNAUTHORIZED' });
  }

  // 2) 데이터베이스 설정
  const origin = supabaseOrigin(env.SUPABASE_URL);
  const secretKey = env.SUPABASE_SECRET_KEY;
  if (!origin || typeof secretKey !== 'string' || secretKey.length === 0) {
    return sendJson(response, 503, { error: 'NOTES_NOT_CONFIGURED' });
  }
  const upstream = async (method, params, body, prefer) => {
    const url = new URL('/rest/v1/notes', origin);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    const headers = { apikey: secretKey, authorization: `Bearer ${secretKey}`, accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (prefer) headers.prefer = prefer;
    return fetchImpl(url, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
  };
  const fail = () => sendJson(response, 502, { error: 'NOTES_UPSTREAM_FAILED' });
  // DB가 돌려준 행도 다시 확인합니다. 주인이 본인이 아닌 행이 섞이면 자료를 내주지 않습니다.
  const readRows = async (result) => {
    const rows = await result.json();
    return Array.isArray(rows) && rows.every(row => validRow(row) && row.owner_id === user.userId)
      ? rows : null;
  };
  const select = 'id,title,content,owner_id';
  const mine = { owner_id: `eq.${user.userId}` };

  try {
    // 목록: 로그인 사용자 본인의 메모만
    if (id === undefined && request.method === 'GET') {
      const result = await upstream('GET', { select, order: 'id.asc', ...mine });
      if (!result.ok) return fail();
      const rows = await readRows(result);
      return rows ? sendJson(response, 200, rows.map(noteOut)) : fail();
    }

    // 추가: 주인은 서버가 확인한 사용자 번호로만 저장합니다. 본문의 owner_id·userId는 쓰지 않습니다.
    if (id === undefined && request.method === 'POST') {
      const body = jsonBody(request);
      const fields = noteFields(body);
      const wantedId = body?.id;
      if (!fields || (wantedId !== undefined && (typeof wantedId !== 'string' || !UUID.test(wantedId)))) {
        return sendJson(response, 400, { error: 'INVALID_BODY' });
      }
      const result = await upstream('POST', {}, {
        id: wantedId ?? randomUUID(), owner_id: user.userId, ...fields,
      }, 'return=representation');
      // 다른 사람 메모의 id를 골라 보내도 덮어쓰지 않고 409로 끝납니다.
      if (result.status === 409) return sendJson(response, 409, { error: 'ID_ALREADY_EXISTS' });
      if (!result.ok) return fail();
      const rows = await readRows(result);
      return rows?.length === 1 ? sendJson(response, 201, { id: rows[0].id }) : fail();
    }

    // 한 건: 형식이 맞지 않는 id는 없는 메모와 같게 404로 답합니다.
    if (!UUID.test(id)) return sendJson(response, 404, { error: 'NOT_FOUND' });
    // 한 건 요청은 항상 "이 id이면서 주인이 본인인 행"만 대상으로 합니다.
    const target = { id: `eq.${id}`, ...mine };

    if (request.method === 'GET') {
      const result = await upstream('GET', { select, limit: '1', ...target });
      if (!result.ok) return fail();
      const rows = await readRows(result);
      if (!rows) return fail();
      return rows.length ? sendJson(response, 200, noteOut(rows[0])) : sendJson(response, 404, { error: 'NOT_FOUND' });
    }

    if (request.method === 'PUT') {
      const body = jsonBody(request);
      const fields = noteFields(body);
      if (!fields) return sendJson(response, 400, { error: 'INVALID_BODY' });
      // 주인 바꾸기는 거부합니다.
      if (triesOtherOwner(body, user.userId)) return sendJson(response, 403, { error: 'OWNER_CHANGE_FORBIDDEN' });
      // 기존 행: 필터로 본인 행만 고릅니다. 새 행: owner_id를 본인으로 다시 적고, 돌려받은 행도 확인합니다.
      const result = await upstream('PATCH', { select, ...target },
        { ...fields, owner_id: user.userId }, 'return=representation');
      if (!result.ok) return fail();
      const rows = await readRows(result);
      if (!rows) return fail();
      return rows.length ? sendJson(response, 200, noteOut(rows[0])) : sendJson(response, 404, { error: 'NOT_FOUND' });
    }

    // DELETE
    const result = await upstream('DELETE', { select, ...target }, undefined, 'return=representation');
    if (!result.ok) return fail();
    const rows = await readRows(result);
    if (!rows) return fail();
    return rows.length ? sendJson(response, 200, { id }) : sendJson(response, 404, { error: 'NOT_FOUND' });
  } catch {
    return fail();
  }
}
