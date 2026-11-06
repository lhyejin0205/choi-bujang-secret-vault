import assert from 'node:assert/strict';
import { test } from 'node:test';
import { handleOpsRequest } from '../src/ops-handler.mjs';
import { RESTORE_TARGET } from '../src/restore-handler.mjs';

const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const env = { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SECRET_KEY: 'test-secret-not-a-real-key' };
const verifyLogin = async auth => ({ 'Bearer A': { kind: 'student', userId: USER_A },
  'Bearer J': { kind: 'judge', userId: 'judge-subject' } })[auth] ?? null;
const approved = async () => ({ ok: true });

const tables = {
  device_approvals: [
    { key_thumbprint: 'a'.repeat(64), owner_id: USER_A, status: 'approved', requested_at: '2026-11-06T05:00:00Z', decided_at: '2026-11-06T05:01:00Z' },
    { key_thumbprint: 'b'.repeat(64), owner_id: USER_B, status: 'pending', requested_at: '2026-11-06T04:00:00Z', decided_at: null },
    { key_thumbprint: 'c'.repeat(64), owner_id: USER_A, status: 'revoked', requested_at: '2026-11-06T03:00:00Z', decided_at: '2026-11-06T03:30:00Z' },
  ],
  restore_audit: [
    { seq: 2, at: '2026-11-06T06:00:00Z', actor_kind: 'judge', before_state: 'deleted', result: 'restored' },
    { seq: 1, at: '2026-11-06T05:30:00Z', actor_kind: 'judge', before_state: 'tampered', result: 'restored' },
  ],
  notes_restore_backup: [
    { id: RESTORE_TARGET.id, content_sha256: '35f71b9389012cda3ab8f6f33c856e1bac32940de3f644e935d8a887677ad53c', captured_at: '2026-11-06T03:45:55Z',
      title: '가상 B 메모 제목', content: '가상 B 메모 본문' },
  ],
};

function fakeDb() {
  const calls = [];
  const fetchImpl = async (url, options) => {
    const u = new URL(url);
    const table = u.pathname.replace('/rest/v1/', '');
    calls.push({ table, method: options.method, select: u.searchParams.get('select') });
    const columns = u.searchParams.get('select').split(',');
    const pick = row => Object.fromEntries(columns.map(column => [column, row[column]]));
    return new Response(JSON.stringify(tables[table].map(pick)), { status: 200 });
  };
  return { calls, fetchImpl };
}

function recorder() {
  return { statusCode: 0, body: undefined, setHeader() {},
    status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
}

const call = async (request, options) => {
  const response = recorder();
  await handleOpsRequest(request, response, { env, verifyLogin, requireDevice: approved, ...options });
  return response;
};

test('작전실 요약은 출처를 붙이고, 수치는 가린 서버 기록에서 센 값과 같다', async () => {
  const db = fakeDb();
  const { statusCode, body } = await call({ method: 'GET', headers: { authorization: 'Bearer A' } }, { fetchImpl: db.fetchImpl });
  assert.equal(statusCode, 200);
  assert.match(body.requestId, /^[0-9a-f-]{36}$/u);
  assert.ok(!Number.isNaN(Date.parse(body.checkedAt)));
  assert.equal(body.decider.source, 'code');
  assert.ok(body.decider.ruleIds.includes('resource_zone'));
  assert.equal(body.detection.source, 'not_run');
  assert.equal(body.detection.events, null);
  assert.equal(body.revocation.source, 'api');
  assert.deepEqual(body.revocation.counts, { pending: 1, approved: 1, revoked: 1 });
  assert.equal(body.revocation.total, body.revocation.records.length);
  assert.deepEqual(body.revocation.records.map(r => [r.device, r.mine, r.status]),
    [['aaaaaaaaaaaa', true, 'approved'], ['bbbbbbbbbbbb', false, 'pending'], ['cccccccccccc', true, 'revoked']]);
  assert.equal(body.recovery.audit.source, 'api');
  assert.deepEqual(body.recovery.audit.counts, { restored: 2 });
  assert.equal(body.recovery.noteBackup.source, 'api');
  assert.equal(body.recovery.noteBackup.contentSha256Prefix, '35f71b938901');
  assert.equal(body.recovery.policy.version, 'safe-2026-11-06-57b2c50');
  assert.equal(body.recovery.policy.sha256, '68fa0f04884eb9d3a9c5308db46af9aa00c28969eda342ba66cdb7d1bf8865d5');
});

test('메모 본문·사용자 번호·전체 기기 지문은 응답에 없고, 본문 칸은 고르지도 않는다', async () => {
  const db = fakeDb();
  const { body } = await call({ method: 'GET', headers: { authorization: 'Bearer A' } }, { fetchImpl: db.fetchImpl });
  const text = JSON.stringify(body);
  for (const secret of ['가상 B 메모 본문', '가상 B 메모 제목', USER_A, USER_B, 'a'.repeat(64)]) {
    assert.equal(text.includes(secret), false, secret);
  }
  assert.ok(db.calls.every(c => c.method === 'GET' && !/title|content(?!_sha256)/u.test(c.select)));
});

test('로그인·승인 기기 서명이 없으면 요약을 주지 않는다', async () => {
  const db = fakeDb();
  assert.equal((await call({ method: 'GET', headers: {} }, { fetchImpl: db.fetchImpl })).statusCode, 401);
  assert.equal((await call({ method: 'GET', headers: { authorization: 'Bearer J' } }, { fetchImpl: db.fetchImpl })).statusCode, 401);
  const unsigned = await call({ method: 'GET', headers: { authorization: 'Bearer A' } }, {
    fetchImpl: db.fetchImpl, requireDevice: async () => ({ ok: false, error: 'DEVICE_SIGNATURE_REQUIRED', reason: 'unsigned' }) });
  assert.equal(unsigned.statusCode, 403);
  assert.deepEqual(unsigned.body, { error: 'DEVICE_SIGNATURE_REQUIRED' });
  assert.equal((await call({ method: 'POST', headers: { authorization: 'Bearer A' } }, { fetchImpl: db.fetchImpl })).statusCode, 405);
  assert.equal(db.calls.length, 0);
});

test('DB를 읽지 못한 항목은 실측으로 꾸미지 않고 미실행으로 남긴다', async () => {
  const failing = async () => new Response('{}', { status: 500 });
  const { statusCode, body } = await call({ method: 'GET', headers: { authorization: 'Bearer A' } }, { fetchImpl: failing });
  assert.equal(statusCode, 200);
  assert.equal(body.revocation.source, 'not_run');
  assert.equal(body.recovery.audit.source, 'not_run');
  assert.equal(body.recovery.noteBackup.source, 'not_run');
});
