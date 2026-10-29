// 로그인·로그아웃을 서버 함수에서 처리합니다. 화면 코드에는 Supabase 주소나 키가 없습니다.
// - 비밀번호는 Supabase Auth로만 넘기고 기록하거나 응답에 싣지 않습니다.
// - 브라우저에는 짧게 쓰는 접근 토큰만 돌려주고, 오래 쓰는 refresh token은 돌려주지 않습니다.
// - 서버 전용 키(SUPABASE_SECRET_KEY)는 서버에서 Auth를 부를 때만 쓰고 응답에 싣지 않습니다.
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;
const MAX_EMAIL = 320;
const MAX_PASSWORD = 1024;

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

function jsonBody(request) {
  let body = request.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

function settings(env) {
  const origin = supabaseOrigin(env.SUPABASE_URL);
  const key = env.SUPABASE_SECRET_KEY;
  return origin && typeof key === 'string' && key.length > 0 ? { origin, key } : null;
}

function onlyPost(request, response) {
  if (request.method === 'POST') return false;
  response.setHeader('allow', 'POST');
  sendJson(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  return true;
}

// Supabase Auth가 돌려준 오류 코드를 화면이 이해하는 고정 코드로만 바꿉니다.
const LOGIN_ERRORS = {
  invalid_credentials: [401, 'INVALID_CREDENTIALS'],
  email_not_confirmed: [401, 'EMAIL_NOT_CONFIRMED'],
  user_banned: [403, 'USER_BANNED'],
  over_request_rate_limit: [429, 'RATE_LIMITED'],
};

export async function handleLogin(request, response, options = {}) {
  const { env = process.env, fetchImpl = globalThis.fetch, now = () => Date.now() } = options;
  if (onlyPost(request, response)) return undefined;
  const body = jsonBody(request);
  const email = typeof body?.email === 'string' ? body.email.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';
  if (!email || !password || email.length > MAX_EMAIL || password.length > MAX_PASSWORD) {
    return sendJson(response, 400, { error: 'INVALID_BODY' });
  }
  const config = settings(env);
  if (!config) return sendJson(response, 503, { error: 'AUTH_NOT_CONFIGURED' });

  let result;
  let data;
  try {
    const url = new URL('/auth/v1/token', config.origin);
    url.searchParams.set('grant_type', 'password');
    result = await fetchImpl(url, {
      method: 'POST',
      headers: { apikey: config.key, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ email, password }),
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    data = await result.json().catch(() => null);
  } catch {
    return sendJson(response, 502, { error: 'AUTH_UPSTREAM_FAILED' });
  }

  if (!result.ok) {
    const code = data?.error_code ?? data?.code;
    const mapped = LOGIN_ERRORS[code] ?? (result.status === 429 ? LOGIN_ERRORS.over_request_rate_limit : null);
    if (mapped) return sendJson(response, mapped[0], { error: mapped[1] });
    return sendJson(response, result.status === 400 ? 401 : 502,
      { error: result.status === 400 ? 'INVALID_CREDENTIALS' : 'AUTH_UPSTREAM_FAILED' });
  }

  const token = data?.access_token;
  const seconds = Number(data?.expires_in);
  if (typeof token !== 'string' || !BEARER.test(`Bearer ${token}`) || !Number.isFinite(seconds) || seconds <= 0) {
    return sendJson(response, 502, { error: 'AUTH_UPSTREAM_FAILED' });
  }
  return sendJson(response, 200, {
    accessToken: token,
    expiresAt: now() + Math.min(seconds, 24 * 60 * 60) * 1000,
    email: typeof data?.user?.email === 'string' ? data.user.email : email,
  });
}

// 로그아웃: 이 로그인 세션을 Supabase에서 끝냅니다. 브라우저는 결과와 관계없이 토큰을 버립니다.
export async function handleLogout(request, response, options = {}) {
  const { env = process.env, fetchImpl = globalThis.fetch } = options;
  if (onlyPost(request, response)) return undefined;
  const authorization = request.headers?.authorization;
  const config = settings(env);
  if (config && typeof authorization === 'string' && authorization.length <= 8192 && BEARER.test(authorization)) {
    try {
      const url = new URL('/auth/v1/logout', config.origin);
      url.searchParams.set('scope', 'local');
      await fetchImpl(url, {
        method: 'POST', headers: { apikey: config.key, authorization },
        redirect: 'error', signal: AbortSignal.timeout(10000),
      });
    } catch {
      // 서버 쪽 정리에 실패해도 브라우저 토큰은 버립니다. 이미 발급된 토큰은 만료 때까지 유효합니다.
    }
  }
  return sendJson(response, 200, { ok: true });
}
