import assert from 'node:assert/strict';
import { test } from 'node:test';
import { handleNotesRequest } from '../src/notes-handler.mjs';

const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const SEED = 'e6dd7a63-84ca-4c03-9c14-c3be10c82201';
const configured = { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SECRET_KEY: 'test-secret-not-a-real-key' };

function recorder() {
  const headers = new Map();
  return {
    headers, statusCode: undefined, body: undefined,
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

// 토큰 문자열 "A"는 사용자 A, "B"는 사용자 B로 검사를 통과하는 가짜 검사기입니다.
const fakeVerify = async (authorization) => {
  if (authorization === 'Bearer A') return { kind: 'student', userId: USER_A };
  if (authorization === 'Bearer B') return { kind: 'student', userId: USER_B };
  return null;
};

// PostgREST를 흉내 내는 메모리 저장소입니다. 요청 모양을 기록하고 필터를 적용합니다.
function fakeStore(initial = []) {
  const rows = initial.map(row => ({ ...row }));
  const calls = [];
  const fetchImpl = async (url, options) => {
    const u = new URL(url);
    calls.push({ method: options.method, url: u, options });
    const eq = u.searchParams.get('id')?.replace(/^eq\./u, '');
    const json = (status, body) => new Response(JSON.stringify(body), { status });
    if (options.method === 'GET') {
      let found = rows;
      if (eq) found = found.filter(row => row.id === eq);
      const or = u.searchParams.get('or');
      if (or) {
        const owner = /owner_id\.eq\.([0-9a-f-]+)/u.exec(or)[1];
        found = found.filter(row => row.owner_id === owner || row.owner_id === null);
      }
      return json(200, found.map(({ id, title, content }) => ({ id, title, content })));
    }
    if (options.method === 'POST') {
      const row = JSON.parse(options.body);
      if (rows.some(existing => existing.id === row.id)) return json(409, { code: '23505' });
      rows.push(row);
      return json(201, [row]);
    }
    const index = rows.findIndex(row => row.id === eq);
    if (options.method === 'PATCH') {
      if (index < 0) return json(200, []);
      Object.assign(rows[index], JSON.parse(options.body));
      return json(200, [rows[index]]);
    }
    if (index < 0) return json(200, []);
    const [removed] = rows.splice(index, 1);
    return json(200, [{ id: removed.id }]);
  };
  return { rows, calls, fetchImpl };
}

async function call(store, request, options = {}) {
  const response = recorder();
  await handleNotesRequest({ headers: {}, ...request }, response,
    { env: configured, fetchImpl: store.fetchImpl, verifyLogin: fakeVerify, ...options });
  return response;
}

test('로그인 토큰이 없거나 검사에 실패하면 자료 없이 401로 거부하고 DB를 부르지 않는다', async () => {
  for (const headers of [{}, { authorization: 'Bearer X' }, { authorization: 'Basic abc' }]) {
    for (const request of [{ method: 'GET' }, { method: 'POST', body: { title: 't', body: 'b' } },
      { method: 'GET', query: { id: SEED } }, { method: 'PUT', query: { id: SEED }, body: { title: 't', body: 'b' } },
      { method: 'DELETE', query: { id: SEED } }]) {
      const store = fakeStore([{ id: SEED, owner_id: null, title: '가상', content: '가상' }]);
      const response = await call(store, { ...request, headers });
      assert.equal(response.statusCode, 401);
      assert.deepEqual(response.body, { error: 'UNAUTHORIZED' });
      assert.equal(response.headers.get('www-authenticate'), 'Bearer');
      assert.equal(store.calls.length, 0);
    }
  }
});

test('검사기가 없거나 오류를 내면 503이고 비밀 정보를 싣지 않는다', async () => {
  const store = fakeStore();
  const missing = await call(store, { method: 'GET', headers: { authorization: 'Bearer A' } }, { verifyLogin: undefined });
  const broken = await call(store, { method: 'GET', headers: { authorization: 'Bearer A' } },
    { verifyLogin: async () => { throw new Error(configured.SUPABASE_SECRET_KEY); } });
  for (const response of [missing, broken]) {
    assert.equal(response.statusCode, 503);
    assert.deepEqual(response.body, { error: 'AUTH_NOT_CONFIGURED' });
    assert.equal(JSON.stringify(response.body).includes(configured.SUPABASE_SECRET_KEY), false);
  }
  assert.equal(store.calls.length, 0);
});

test('허용하지 않는 방식은 405이고 Allow에 허용 방식을 알려 준다', async () => {
  const store = fakeStore();
  const listPatch = await call(store, { method: 'PATCH', headers: { authorization: 'Bearer A' } });
  const onePost = await call(store, { method: 'POST', query: { id: SEED }, headers: { authorization: 'Bearer A' } });
  assert.equal(listPatch.statusCode, 405);
  assert.equal(listPatch.headers.get('allow'), 'GET, POST');
  assert.equal(onePost.statusCode, 405);
  assert.equal(onePost.headers.get('allow'), 'GET, PUT, DELETE');
  assert.equal(store.calls.length, 0);
});

test('목록은 로그인 사용자의 메모와 주인 없는 가상 메모만 {id,title,body}로 돌려준다', async () => {
  const store = fakeStore([
    { id: SEED, owner_id: null, title: '가상 제목', content: '가상 내용' },
    { id: '33333333-3333-4333-8333-333333333333', owner_id: USER_A, title: 'A 제목', content: 'A 내용' },
    { id: '44444444-4444-4444-8444-444444444444', owner_id: USER_B, title: 'B 제목', content: 'B 내용' },
  ]);
  const response = await call(store, { method: 'GET', headers: { authorization: 'Bearer A' } });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body.map(note => note.title), ['가상 제목', 'A 제목']);
  assert.deepEqual(Object.keys(response.body[0]).sort(), ['body', 'id', 'title']);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const { options, url } = store.calls[0];
  assert.equal(url.origin + url.pathname, 'https://project.supabase.co/rest/v1/notes');
  assert.equal(options.headers.apikey, configured.SUPABASE_SECRET_KEY);
  assert.equal(options.redirect, 'error');
  assert.equal(JSON.stringify(response.body).includes(configured.SUPABASE_SECRET_KEY), false);
});

test('추가는 서버가 확인한 사용자 번호를 owner_id로 저장하고 본문의 userId·role·owner_id는 믿지 않는다', async () => {
  const store = fakeStore();
  const response = await call(store, {
    method: 'POST', headers: { authorization: 'Bearer A' },
    body: { title: ' 제목 ', body: '내용', userId: USER_B, role: 'admin', owner_id: USER_B },
  });
  assert.equal(response.statusCode, 201);
  assert.deepEqual(Object.keys(response.body), ['id']);
  assert.match(response.body.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.equal(store.rows.length, 1);
  assert.deepEqual(store.rows[0], { id: response.body.id, owner_id: USER_A, title: '제목', content: '내용' });
  assert.equal('role' in store.rows[0] || 'userId' in store.rows[0], false);
});

test('추가는 클라이언트가 준 UUID를 쓰고, 중복은 409, 잘못된 입력은 400이다', async () => {
  const store = fakeStore();
  const wanted = '55555555-5555-4555-8555-555555555555';
  const created = await call(store, { method: 'POST', headers: { authorization: 'Bearer A' }, body: { id: wanted, title: 't', body: 'b' } });
  assert.equal(created.statusCode, 201);
  assert.deepEqual(created.body, { id: wanted });
  const again = await call(store, { method: 'POST', headers: { authorization: 'Bearer A' }, body: { id: wanted, title: 't', body: 'b' } });
  assert.equal(again.statusCode, 409);
  for (const body of [undefined, 'text', [], {}, { title: '', body: 'b' }, { title: 't' }, { title: 't', body: 1 },
    { title: 'x'.repeat(201), body: 'b' }, { title: 't', body: 'x'.repeat(5001) }, { id: 'not-a-uuid', title: 't', body: 'b' }]) {
    const response = await call(store, { method: 'POST', headers: { authorization: 'Bearer A' }, body });
    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.body, { error: 'INVALID_BODY' });
  }
  assert.equal(store.rows.length, 1);
});

test('추가·한 건 읽기·수정·삭제 흐름: 삭제 뒤 GET은 404', async () => {
  const store = fakeStore();
  const auth = { authorization: 'Bearer A' };
  const { body: { id } } = await call(store, { method: 'POST', headers: auth, body: { title: '처음', body: '내용' } });
  const one = await call(store, { method: 'GET', query: { id }, headers: auth });
  assert.equal(one.statusCode, 200);
  assert.deepEqual(one.body, { id, title: '처음', body: '내용' });

  const updated = await call(store, { method: 'PUT', query: { id }, headers: auth, body: { title: '고침', body: '새 내용' } });
  assert.equal(updated.statusCode, 200);
  assert.deepEqual(updated.body, { id, title: '고침', body: '새 내용' });
  assert.equal(store.rows[0].owner_id, USER_A);
  const patch = store.calls.find(entry => entry.method === 'PATCH');
  assert.deepEqual(Object.keys(JSON.parse(patch.options.body)).sort(), ['content', 'title']);

  const removed = await call(store, { method: 'DELETE', query: { id }, headers: auth });
  assert.equal(removed.statusCode, 200);
  assert.deepEqual(removed.body, { id });
  const gone = await call(store, { method: 'GET', query: { id }, headers: auth });
  assert.equal(gone.statusCode, 404);
  assert.deepEqual(gone.body, { error: 'NOT_FOUND' });
  const goneAgain = await call(store, { method: 'DELETE', query: { id }, headers: auth });
  assert.equal(goneAgain.statusCode, 404);
});

test('없는 id와 형식이 틀린 id는 404이고 형식이 틀린 id는 DB를 부르지 않는다', async () => {
  const store = fakeStore();
  const auth = { authorization: 'Bearer A' };
  const missing = '66666666-6666-4666-8666-666666666666';
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const response = await call(store, { method, query: { id: missing }, headers: auth, body: { title: 't', body: 'b' } });
    assert.equal(response.statusCode, 404);
  }
  const before = store.calls.length;
  for (const id of ['', 'abc', "x' or 1=1", ['a', 'b']]) {
    const response = await call(store, { method: 'GET', query: { id }, headers: auth });
    assert.equal(response.statusCode, 404);
  }
  assert.equal(store.calls.length, before);
});

test('3단계에는 소유자 검사가 없어 B가 A의 메모를 고칠 수 있다 (4단계에서 고칠 알려진 약점)', async () => {
  const id = '77777777-7777-4777-8777-777777777777';
  const store = fakeStore([{ id, owner_id: USER_A, title: 'A 메모', content: 'A 내용' }]);
  const response = await call(store, { method: 'PUT', query: { id }, headers: { authorization: 'Bearer B' }, body: { title: 'B가 고침', body: 'x' } });
  assert.equal(response.statusCode, 200);
  assert.equal(store.rows[0].title, 'B가 고침');
});

test('DB 설정이 없거나 DB가 실패해도 고정 오류만 돌려주고 비밀 키를 싣지 않는다', async () => {
  const auth = { authorization: 'Bearer A' };
  const unconfigured = await call(fakeStore(), { method: 'GET', headers: auth }, { env: {} });
  assert.equal(unconfigured.statusCode, 503);
  assert.deepEqual(unconfigured.body, { error: 'NOTES_NOT_CONFIGURED' });
  const throwing = { fetchImpl: async () => { throw new Error(configured.SUPABASE_SECRET_KEY); } };
  const notOk = { fetchImpl: async () => new Response('{"message":"secret detail"}', { status: 500 }) };
  const badShape = { fetchImpl: async () => new Response('[{"id":"nope"}]', { status: 200 }) };
  for (const store of [throwing, notOk, badShape]) {
    const response = await call(store, { method: 'GET', headers: auth });
    assert.equal(response.statusCode, 502);
    assert.deepEqual(response.body, { error: 'NOTES_UPSTREAM_FAILED' });
    assert.equal(JSON.stringify(response.body).includes(configured.SUPABASE_SECRET_KEY), false);
  }
});
