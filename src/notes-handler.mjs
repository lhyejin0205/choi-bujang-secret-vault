import { randomUUID } from 'node:crypto';

// 자료 API. 모든 요청은 먼저 verifyLogin(src/verify-login.mjs)으로 토큰을 검사합니다.
// 사용자 번호는 검사를 통과한 토큰에서만 얻습니다. 요청 본문의 userId·role·owner_id는 읽지 않습니다.
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
  const readRows = async (result) => {
    const rows = await result.json();
    return Array.isArray(rows) && rows.every(validRow) ? rows : null;
  };
  const select = 'id,title,content';

  try {
    // 목록: 로그인 사용자의 메모와 주인이 없는 가상 메모
    if (id === undefined && request.method === 'GET') {
      const result = await upstream('GET', {
        select, order: 'id.asc', or: `(owner_id.eq.${user.userId},owner_id.is.null)`,
      });
      if (!result.ok) return fail();
      const rows = await readRows(result);
      return rows ? sendJson(response, 200, rows.map(noteOut)) : fail();
    }

    // 추가: 주인은 서버가 확인한 사용자 번호로만 저장합니다.
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
      if (result.status === 409) return sendJson(response, 409, { error: 'ID_ALREADY_EXISTS' });
      if (!result.ok) return fail();
      const rows = await readRows(result);
      return rows?.length === 1 ? sendJson(response, 201, { id: rows[0].id }) : fail();
    }

    // 한 건: 형식이 맞지 않는 id는 없는 메모와 같게 404로 답합니다.
    if (!UUID.test(id)) return sendJson(response, 404, { error: 'NOT_FOUND' });
    const target = { id: `eq.${id}` };

    if (request.method === 'GET') {
      const result = await upstream('GET', { select, limit: '1', ...target });
      if (!result.ok) return fail();
      const rows = await readRows(result);
      if (!rows) return fail();
      return rows.length ? sendJson(response, 200, noteOut(rows[0])) : sendJson(response, 404, { error: 'NOT_FOUND' });
    }

    if (request.method === 'PUT') {
      const fields = noteFields(jsonBody(request));
      if (!fields) return sendJson(response, 400, { error: 'INVALID_BODY' });
      const result = await upstream('PATCH', { select, ...target }, fields, 'return=representation');
      if (!result.ok) return fail();
      const rows = await readRows(result);
      if (!rows) return fail();
      return rows.length ? sendJson(response, 200, noteOut(rows[0])) : sendJson(response, 404, { error: 'NOT_FOUND' });
    }

    // DELETE
    const result = await upstream('DELETE', { select: 'id', ...target }, undefined, 'return=representation');
    if (!result.ok) return fail();
    const rows = await result.json();
    if (!Array.isArray(rows)) return fail();
    return rows.length ? sendJson(response, 200, { id }) : sendJson(response, 404, { error: 'NOT_FOUND' });
  } catch {
    return fail();
  }
}
