import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RESTORE_TARGET, contentHash, handleRestoreRequest } from '../src/restore-handler.mjs';

const OWNER_B = RESTORE_TARGET.ownerId;
const USER_A = '11111111-1111-4111-8111-111111111111';
const OTHER_NOTE = 'e6dd7a63-84ca-4c03-9c14-c3be10c82201';
const env = { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SECRET_KEY: 'test-secret-not-a-real-key' };
const original = { id: RESTORE_TARGET.id, owner_id: OWNER_B, title: '가상 B 메모', content: '가상 B 내용' };
const backupRow = { ...original, content_sha256: contentHash(original.title, original.content) };

const verifyLogin = async auth => ({
  'Bearer B': { kind: 'student', userId: OWNER_B },
  'Bearer A': { kind: 'student', userId: USER_A },
  'Bearer J': { kind: 'judge', userId: 'judge-subject' },
})[auth] ?? null;

function recorder() {
  return { statusCode: 0, body: undefined, headers: new Map(),
    setHeader(name, value) { this.headers.set(name.toLowerCase(), value); },
    status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
}

// PostgREST 흉내: notes, notes_restore_backup, restore_audit 세 테이블을 메모리에 둡니다.
function fakeDb({ notes, backup = [backupRow] }) {
  const db = { notes: notes.map(row => ({ ...row })), notes_restore_backup: backup.map(row => ({ ...row })), restore_audit: [] };
  const calls = [];
  const fetchImpl = async (url, options) => {
    const u = new URL(url);
    const table = u.pathname.replace('/rest/v1/', '');
    calls.push({ table, method: options.method, id: u.searchParams.get('id') });
    const id = u.searchParams.get('id')?.replace(/^eq\./u, '');
    const rows = db[table];
    const json = (status, body) => new Response(JSON.stringify(body), { status });
    if (options.method === 'GET') return json(200, rows.filter(row => !id || row.id === id));
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      if (table === 'notes' && rows.some(row => row.id === body.id)) return json(409, {});
      rows.push(body);
      return json(201, [body]);
    }
    if (options.method === 'PATCH') {
      if (!id) return json(400, {});
      const matched = rows.filter(row => row.id === id);
      for (const row of matched) Object.assign(row, JSON.parse(options.body));
      return json(200, matched);
    }
    return json(405, {});
  };
  return { db, calls, fetchImpl };
}

const call = async (store, token, method = 'POST', extra = {}) => {
  const response = recorder();
  const logs = [];
  await handleRestoreRequest({ method, headers: token ? { authorization: `Bearer ${token}` } : {}, ...extra }, response,
    { env, fetchImpl: store.fetchImpl, verifyLogin, log: entry => logs.push(entry) });
  return { response, logs };
};

const otherNote = { id: OTHER_NOTE, owner_id: USER_A, title: 'A 메모', content: 'A 내용' };

test('변조된 B 메모 한 건만 사본으로 되돌리고 ID·소유자·내용 해시가 같아진다', async () => {
  const store = fakeDb({ notes: [{ ...original, title: '변조', content: '변조된 내용', owner_id: USER_A }, otherNote] });
  const { response } = await call(store, 'B');
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { restored: RESTORE_TARGET.id, beforeState: 'tampered',
    idMatches: true, ownerMatches: true, contentHashMatches: true, audited: true });
  assert.deepEqual(store.db.notes[0], original);
  assert.deepEqual(store.db.notes[1], otherNote);
  assert.ok(store.calls.filter(c => c.table === 'notes' && c.method !== 'GET').every(c => c.id === `eq.${RESTORE_TARGET.id}`));
  assert.equal(JSON.stringify(response.body).includes('가상 B 내용'), false);
});

test('삭제된 B 메모는 같은 id로 다시 넣고, 감사 기록은 덧붙이기만 한다', async () => {
  const store = fakeDb({ notes: [otherNote] });
  store.db.restore_audit.push({ note_id: RESTORE_TARGET.id, actor_kind: 'owner', before_state: 'unchanged', result: 'restored' });
  const { response } = await call(store, 'J');
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.beforeState, 'deleted');
  assert.deepEqual(store.db.notes.find(row => row.id === RESTORE_TARGET.id), original);
  assert.equal(store.db.restore_audit.length, 2);
  assert.deepEqual(store.db.restore_audit[1], { note_id: RESTORE_TARGET.id, actor_kind: 'judge', before_state: 'deleted', result: 'restored' });
  assert.equal(store.calls.some(c => c.table === 'restore_audit' && c.method !== 'POST' && c.method !== 'GET'), false);
});

test('사본의 해시나 소유자가 맞지 않거나 사본이 없으면 아무것도 바꾸지 않고 중단한다', async () => {
  for (const backup of [[{ ...backupRow, content_sha256: '0'.repeat(64) }], [{ ...backupRow, owner_id: USER_A }], []]) {
    const tampered = { ...original, content: '변조' };
    const store = fakeDb({ notes: [tampered], backup });
    const { response } = await call(store, 'B');
    assert.ok([409, 502].includes(response.statusCode));
    assert.deepEqual(store.db.notes, [tampered]);
    assert.equal(store.calls.some(c => c.table === 'notes' && c.method !== 'GET'), false);
  }
});

test('B 본인이나 심판이 아니면 거부하고, POST만 받는다', async () => {
  const store = fakeDb({ notes: [{ ...original, content: '변조' }] });
  assert.equal((await call(store, 'A')).response.statusCode, 403);
  assert.equal((await call(store, null)).response.statusCode, 401);
  assert.equal((await call(store, 'B', 'GET')).response.statusCode, 405);
  const body = await call(store, 'A', 'POST', { body: { id: OTHER_NOTE, role: 'instructor' }, query: { zone: 'restore', id: OTHER_NOTE } });
  assert.equal(body.response.statusCode, 403);
  assert.equal(store.db.notes[0].content, '변조');
});

test('이미 같으면 그대로 두고 unchanged로 알린다', async () => {
  const store = fakeDb({ notes: [original] });
  const { response } = await call(store, 'B');
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.beforeState, 'unchanged');
  assert.equal(store.calls.some(c => c.table === 'notes' && c.method !== 'GET'), false);
});
