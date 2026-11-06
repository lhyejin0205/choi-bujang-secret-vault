import assert from 'node:assert/strict';
import { test } from 'node:test';
import { handleNotesRequest } from '../src/notes-handler.mjs';
import { handleNoticesRequest, NOTICES } from '../src/notices-handler.mjs';
import { resourceId } from '../src/resources.mjs';

const USER_A = '11111111-1111-4111-8111-111111111111';
const NOTE_ID = 'e6dd7a63-84ca-4c03-9c14-c3be10c82201';
const configured = { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SECRET_KEY: 'test-secret-not-a-real-key' };
const verifyLogin = async (authorization) => (authorization === 'Bearer A'
  ? { kind: 'student', userId: USER_A } : null);

function recorder() {
  const headers = new Map();
  return {
    headers, statusCode: undefined, body: undefined,
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

const emptyStore = async () => new Response('[]', { status: 200 });
const auth = { authorization: 'Bearer A' };

test('메모와 강사 공지는 서로 다른 자원 ID를 쓴다', () => {
  assert.equal(resourceId('note', NOTE_ID), `note:${NOTE_ID}`);
  assert.equal(resourceId('notice', 'n-001'), 'notice:n-001');
  assert.notEqual(resourceId('note'), resourceId('notice'));
  assert.throws(() => resourceId('admin', 'x'));
});

test('메모 요청에는 note 자원 ID가 붙고 응답 본문 모양은 그대로다', async () => {
  const list = recorder();
  await handleNotesRequest({ method: 'GET', headers: auth }, list,
    { env: configured, fetchImpl: emptyStore, verifyLogin });
  assert.equal(list.statusCode, 200);
  assert.equal(list.headers.get('x-resource-kind'), 'note');
  assert.equal(list.headers.get('x-resource-id'), 'note:list');
  assert.deepEqual(list.body, []);

  const one = recorder();
  await handleNotesRequest({ method: 'GET', query: { id: NOTE_ID }, headers: auth }, one,
    { env: configured, fetchImpl: emptyStore, verifyLogin });
  assert.equal(one.headers.get('x-resource-id'), `note:${NOTE_ID}`);

  const bad = recorder();
  await handleNotesRequest({ method: 'GET', query: { id: 'x\r\ny' }, headers: auth }, bad,
    { env: configured, fetchImpl: emptyStore, verifyLogin });
  assert.equal(bad.statusCode, 404);
  assert.equal(bad.headers.get('x-resource-kind'), 'note');
  assert.equal(bad.headers.has('x-resource-id'), false);
});

test('강사 공지는 notice 자원 ID로 로그인한 사용자만 읽는다', async () => {
  const anonymous = recorder();
  await handleNoticesRequest({ method: 'GET', headers: {} }, anonymous, { verifyLogin });
  assert.equal(anonymous.statusCode, 401);
  assert.equal(anonymous.body.length, undefined);

  const list = recorder();
  await handleNoticesRequest({ method: 'GET', headers: auth }, list, { verifyLogin });
  assert.equal(list.statusCode, 200);
  assert.equal(list.headers.get('x-resource-id'), 'notice:list');
  assert.deepEqual(list.body.map(item => item.id), NOTICES.map(item => item.id));

  const one = recorder();
  await handleNoticesRequest({ method: 'GET', query: { id: 'n-001' }, headers: auth }, one, { verifyLogin });
  assert.equal(one.statusCode, 200);
  assert.equal(one.headers.get('x-resource-kind'), 'notice');
  assert.equal(one.headers.get('x-resource-id'), 'notice:n-001');

  const missing = recorder();
  await handleNoticesRequest({ method: 'GET', query: { id: NOTE_ID }, headers: auth }, missing, { verifyLogin });
  assert.equal(missing.statusCode, 404);
});

test('학생 계정은 본문에 role을 넣어도 강사 공지를 고칠 수 없다', async () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    const logs = [];
    const response = recorder();
    await handleNoticesRequest({ method, query: { id: 'n-001' }, headers: auth,
      body: { title: '바꿈', body: '바꿈', role: 'instructor', isInstructor: true } }, response,
    { verifyLogin, env: {}, log: entry => logs.push(entry) });
    assert.equal(response.statusCode, 403, method);
    assert.deepEqual(response.body, { error: 'NOT_INSTRUCTOR' });
    assert.deepEqual(logs, [{ event: 'api_denied', zone: 'notice', method, reason: 'not_instructor' }]);
  }
  const anonymous = recorder();
  await handleNoticesRequest({ method: 'PUT', query: { id: 'n-001' }, headers: {} }, anonymous, { verifyLogin });
  assert.equal(anonymous.statusCode, 401);
  assert.equal(NOTICES[0].title, '[가상 공지] 3차 방어전 일정');
});

test('저장된 강사 목록에 있는 사용자만 강사로 보고, 저장소가 없어 수정은 받지 않는다', async () => {
  const response = recorder();
  await handleNoticesRequest({ method: 'PUT', query: { id: 'n-001' }, headers: auth,
    body: { title: '바꿈', body: '바꿈' } }, response,
  { verifyLogin, env: { INSTRUCTOR_USER_IDS: ` ${USER_A.toUpperCase()} , not-a-uuid` } });
  assert.equal(response.statusCode, 501);
  assert.deepEqual(response.body, { error: 'NOTICE_EDIT_NOT_AVAILABLE' });
  assert.equal(NOTICES[0].title, '[가상 공지] 3차 방어전 일정');

  const judgeToken = recorder();
  await handleNoticesRequest({ method: 'PUT', query: { id: 'n-001' }, headers: { authorization: 'Bearer J' } },
    judgeToken, { verifyLogin: async () => ({ kind: 'judge', userId: USER_A }),
      env: { INSTRUCTOR_USER_IDS: USER_A } });
  assert.equal(judgeToken.statusCode, 403);
});

test('다른 사람 메모 요청은 404로 같게 답하고 짧은 거부 사유만 기록한다', async () => {
  const logs = [];
  const response = recorder();
  await handleNotesRequest({ method: 'GET', query: { id: NOTE_ID }, headers: auth }, response,
    { env: configured, fetchImpl: emptyStore, verifyLogin, log: entry => logs.push(entry) });
  assert.equal(response.statusCode, 404);
  assert.deepEqual(response.body, { error: 'NOT_FOUND' });
  assert.deepEqual(logs, [{ event: 'api_denied', zone: 'note', method: 'GET', reason: 'not_owner_or_missing' }]);
  assert.equal(JSON.stringify(logs).includes(USER_A), false);
});
