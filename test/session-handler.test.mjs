import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { handleLogin, handleLogout } from '../src/session-handler.mjs';

const env = { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SECRET_KEY: 'test-secret-not-a-real-key' };
const TOKEN = 'aaaaaaaaaa.bbbbbbbbbb.cccccccccc';

function recorder() {
  const headers = new Map();
  return {
    headers, statusCode: undefined, body: undefined,
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

function upstream(status, body) {
  const calls = [];
  return { calls, fetchImpl: async (url, init) => { calls.push({ url: new URL(url), init }); return new Response(JSON.stringify(body), { status }); } };
}

async function login(body, store, extra = {}) {
  const response = recorder();
  await handleLogin({ method: 'POST', headers: {}, body }, response, { env, fetchImpl: store.fetchImpl, now: () => 1000, ...extra });
  return response;
}

test('로그인 성공: 서버가 Supabase Auth 비밀번호 로그인을 부르고 접근 토큰만 돌려준다', async () => {
  const store = upstream(200, { access_token: TOKEN, refresh_token: 'refresh-should-not-leak', expires_in: 3600,
    user: { email: 'a@example.test' } });
  const response = await login({ email: ' a@example.test ', password: 'pw' }, store);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { accessToken: TOKEN, expiresAt: 1000 + 3600 * 1000, email: 'a@example.test' });
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const { url, init } = store.calls[0];
  assert.equal(url.origin + url.pathname, 'https://project.supabase.co/auth/v1/token');
  assert.equal(url.searchParams.get('grant_type'), 'password');
  assert.equal(init.method, 'POST');
  assert.equal(init.redirect, 'error');
  assert.deepEqual(JSON.parse(init.body), { email: 'a@example.test', password: 'pw' });
  const text = JSON.stringify(response.body);
  assert.equal(text.includes('refresh'), false);
  assert.equal(text.includes(env.SUPABASE_SECRET_KEY), false);
  assert.equal(text.includes('pw'), false);
});

test('로그인 실패 이유는 고정 코드로만 돌려주고 비밀번호·키를 싣지 않는다', async () => {
  const cases = [
    [{ error_code: 'invalid_credentials', msg: 'Invalid login credentials' }, 400, 401, 'INVALID_CREDENTIALS'],
    [{ error_code: 'email_not_confirmed' }, 400, 401, 'EMAIL_NOT_CONFIRMED'],
    [{ error_code: 'over_request_rate_limit' }, 429, 429, 'RATE_LIMITED'],
    [{ message: 'boom secret detail' }, 500, 502, 'AUTH_UPSTREAM_FAILED'],
  ];
  for (const [body, upstreamStatus, status, code] of cases) {
    const response = await login({ email: 'a@example.test', password: 'secret-pw' }, upstream(upstreamStatus, body));
    assert.equal(response.statusCode, status);
    assert.deepEqual(response.body, { error: code });
  }
  const thrown = await login({ email: 'a@example.test', password: 'pw' }, { fetchImpl: async () => { throw new Error(env.SUPABASE_SECRET_KEY); } });
  assert.equal(thrown.statusCode, 502);
  assert.equal(JSON.stringify(thrown.body).includes(env.SUPABASE_SECRET_KEY), false);
  const weird = await login({ email: 'a@example.test', password: 'pw' }, upstream(200, { access_token: 'not-a-jwt', expires_in: 3600 }));
  assert.equal(weird.statusCode, 502);
});

test('로그인 입력이 틀리거나 설정이 없으면 Auth를 부르지 않는다', async () => {
  for (const body of [undefined, 'text', {}, { email: 'a@example.test' }, { password: 'pw' }, { email: 1, password: 'pw' },
    { email: 'x'.repeat(321), password: 'pw' }, { email: 'a@example.test', password: 'x'.repeat(1025) }]) {
    const store = upstream(200, {});
    const response = await login(body, store);
    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.body, { error: 'INVALID_BODY' });
    assert.equal(store.calls.length, 0);
  }
  const store = upstream(200, {});
  const response = await login({ email: 'a@example.test', password: 'pw' }, store, { env: {} });
  assert.equal(response.statusCode, 503);
  assert.equal(store.calls.length, 0);
});

test('로그인·로그아웃은 POST만 받는다', async () => {
  for (const handler of [handleLogin, handleLogout]) {
    const response = recorder();
    await handler({ method: 'GET', headers: {} }, response, { env, fetchImpl: async () => { throw new Error('called'); } });
    assert.equal(response.statusCode, 405);
    assert.equal(response.headers.get('allow'), 'POST');
  }
});

test('로그아웃은 그 토큰의 세션만 끝내고, 토큰이 없거나 이상해도 200으로 답한다', async () => {
  const store = upstream(204, {});
  const response = recorder();
  await handleLogout({ method: 'POST', headers: { authorization: `Bearer ${TOKEN}` } }, response, { env, fetchImpl: store.fetchImpl });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { ok: true });
  const { url, init } = store.calls[0];
  assert.equal(url.origin + url.pathname, 'https://project.supabase.co/auth/v1/logout');
  assert.equal(url.searchParams.get('scope'), 'local');
  assert.equal(init.headers.authorization, `Bearer ${TOKEN}`);
  for (const headers of [{}, { authorization: 'Bearer x' }, { authorization: 'Basic abc' }]) {
    const quiet = upstream(204, {});
    const answer = recorder();
    await handleLogout({ method: 'POST', headers }, answer, { env, fetchImpl: quiet.fetchImpl });
    assert.equal(answer.statusCode, 200);
    assert.equal(quiet.calls.length, 0);
  }
});

test('화면 코드에는 Supabase 공개 키·주소·SDK가 없다', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /sb_publishable_|supabase\.co|supabase-js|eyJ[A-Za-z0-9_-]{10,}/u);
  assert.match(html, /\/api\/login/u);
  assert.match(html, /\/api\/logout/u);
});

test('api/notes.js 하나가 session=login·logout을 로그인·로그아웃 처리기로 넘긴다', async () => {
  const saved = { ...process.env };
  const originalFetch = globalThis.fetch;
  try {
    Object.assign(process.env, env);
    const calls = [];
    globalThis.fetch = async (url) => { calls.push(new URL(url).pathname); return new Response(JSON.stringify({ error_code: 'invalid_credentials' }), { status: 400 }); };
    const { default: handler } = await import('../api/notes.js');
    const loginResponse = recorder();
    await handler({ method: 'POST', headers: {}, query: { session: 'login' }, body: { email: 'a@example.test', password: 'pw' } }, loginResponse);
    assert.equal(loginResponse.statusCode, 401);
    assert.deepEqual(loginResponse.body, { error: 'INVALID_CREDENTIALS' });
    const logoutResponse = recorder();
    await handler({ method: 'POST', headers: {}, query: { session: 'logout' } }, logoutResponse);
    assert.equal(logoutResponse.statusCode, 200);
    assert.deepEqual(calls, ['/auth/v1/token']);
  } finally {
    globalThis.fetch = originalFetch;
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
  }
});
