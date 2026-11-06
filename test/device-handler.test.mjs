import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  handleDeviceRequest, isPublicJwk, keyThumbprint, signingString, verifyDeviceRequest,
} from '../src/device-handler.mjs';
import { handleNotesRequest } from '../src/notes-handler.mjs';

const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const NOTE_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const env = { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SECRET_KEY: 'test-secret-not-a-real-key' };
const userA = { kind: 'student', userId: USER_A };
const verifyLogin = async auth => ({ 'Bearer A': userA, 'Bearer B': { kind: 'student', userId: USER_B },
  'Bearer J': { kind: 'judge', userId: 'judge-subject' } })[auth] ?? null;
const { subtle } = globalThis.crypto;

async function newDevice() {
  const keys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await subtle.exportKey('jwk', keys.publicKey);
  const jwk = { kty, crv, x, y };
  return { keys, jwk, thumbprint: keyThumbprint(jwk) };
}

async function sign(device, { method, path, body, time = Date.now() }) {
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, device.keys.privateKey,
    new TextEncoder().encode(signingString({ method, path, time, body })));
  return { 'x-device-key': device.thumbprint, 'x-device-time': String(time),
    'x-device-signature': Buffer.from(signature).toString('base64url') };
}

// PostgREST 흉내: device_approvals 와 notes 두 테이블.
function fakeDb(devices = [], notes = []) {
  const db = { device_approvals: devices.map(row => ({ ...row })), notes: notes.map(row => ({ ...row })) };
  const fetchImpl = async (url, options) => {
    const u = new URL(url);
    const table = u.pathname.replace('/rest/v1/', '');
    const filters = [...u.searchParams].filter(([key]) => !['select', 'limit', 'order'].includes(key))
      .map(([key, value]) => [key, value.replace(/^eq\./u, '')]);
    const match = row => filters.every(([key, value]) => String(row[key]) === value);
    const json = (status, body) => new Response(JSON.stringify(body), { status });
    if (options.method === 'GET') return json(200, db[table].filter(match));
    if (options.method === 'POST') { db[table].push(JSON.parse(options.body)); return json(201, []); }
    return json(405, {});
  };
  return { db, fetchImpl };
}

function recorder() {
  return { statusCode: 0, body: undefined, headers: new Map(),
    setHeader(name, value) { this.headers.set(name.toLowerCase(), value); },
    status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
}

test('공개키만 받고 기기 지문은 정해진 네 값으로 만든다', async () => {
  const device = await newDevice();
  assert.equal(isPublicJwk(device.jwk), true);
  assert.equal(isPublicJwk({ ...device.jwk, d: 'private' }), false);
  assert.match(device.thumbprint, /^[0-9a-f]{64}$/u);
  assert.equal(keyThumbprint({ ...device.jwk, alg: 'ES256' }), device.thumbprint);
});

test('기기 등록은 "승인 대기"로만 들어가고 본문의 status는 무시한다', async () => {
  const device = await newDevice();
  const store = fakeDb();
  const response = recorder();
  await handleDeviceRequest({ method: 'POST', headers: { authorization: 'Bearer A' },
    body: { publicKey: device.jwk, status: 'approved', approved: true } }, response,
  { env, fetchImpl: store.fetchImpl, verifyLogin });
  assert.equal(response.statusCode, 201);
  assert.deepEqual(response.body, { deviceKey: device.thumbprint, status: 'pending' });
  assert.equal(store.db.device_approvals.length, 1);
  assert.equal(store.db.device_approvals[0].owner_id, USER_A);
  assert.equal(Object.hasOwn(store.db.device_approvals[0], 'status'), false);

  store.db.device_approvals[0].status = 'pending';
  const again = recorder();
  await handleDeviceRequest({ method: 'POST', headers: { authorization: 'Bearer A' }, body: { publicKey: device.jwk } },
    again, { env, fetchImpl: store.fetchImpl, verifyLogin });
  assert.deepEqual(again.body, { deviceKey: device.thumbprint, status: 'pending' });

  const other = recorder();
  await handleDeviceRequest({ method: 'POST', headers: { authorization: 'Bearer B' }, body: { publicKey: device.jwk } },
    other, { env, fetchImpl: store.fetchImpl, verifyLogin });
  assert.equal(other.statusCode, 409);
});

test('기기 등록은 로그인한 학생 계정의 POST만 받는다', async () => {
  const device = await newDevice();
  const store = fakeDb();
  for (const [request, status] of [
    [{ method: 'POST', headers: {}, body: { publicKey: device.jwk } }, 401],
    [{ method: 'POST', headers: { authorization: 'Bearer J' }, body: { publicKey: device.jwk } }, 401],
    [{ method: 'GET', headers: { authorization: 'Bearer A' } }, 405],
    [{ method: 'POST', headers: { authorization: 'Bearer A' }, body: { publicKey: { ...device.jwk, d: 'x' } } }, 400],
  ]) {
    const response = recorder();
    await handleDeviceRequest(request, response, { env, fetchImpl: store.fetchImpl, verifyLogin });
    assert.equal(response.statusCode, status);
  }
  assert.equal(store.db.device_approvals.length, 0);
});

test('승인된 기기의 서명만 통과하고, 서명 없음·경로 변경·본문 변경·승인 전·만료는 거부한다', async () => {
  const device = await newDevice();
  const pending = await newDevice();
  const store = fakeDb([
    { key_thumbprint: device.thumbprint, owner_id: USER_A, public_key_jwk: device.jwk, status: 'approved' },
    { key_thumbprint: pending.thumbprint, owner_id: USER_A, public_key_jwk: pending.jwk, status: 'pending' },
  ]);
  const check = (headers, { method = 'PUT', path = `/api/notes/${NOTE_A}`, body = { title: 't', body: 'b' }, user = userA } = {}) =>
    verifyDeviceRequest({ method, headers, body }, user, { path, env, fetchImpl: store.fetchImpl });
  const signed = await sign(device, { method: 'PUT', path: `/api/notes/${NOTE_A}`, body: { title: 't', body: 'b' } });

  assert.deepEqual(await check(signed), { ok: true });
  assert.deepEqual(await check(signed, { body: { body: 'b', title: 't' } }), { ok: true });
  assert.equal((await check({})).error, 'DEVICE_SIGNATURE_REQUIRED');
  assert.equal((await check(signed, { path: '/api/notes/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' })).error, 'DEVICE_SIGNATURE_INVALID');
  assert.equal((await check(signed, { body: { title: 't', body: '바뀐 본문' } })).error, 'DEVICE_SIGNATURE_INVALID');
  assert.equal((await check(signed, { method: 'DELETE' })).error, 'DEVICE_SIGNATURE_INVALID');
  assert.equal((await check(signed, { user: { kind: 'student', userId: USER_B } })).error, 'DEVICE_NOT_APPROVED');
  const unapproved = await sign(pending, { method: 'PUT', path: `/api/notes/${NOTE_A}`, body: { title: 't', body: 'b' } });
  assert.equal((await check(unapproved)).error, 'DEVICE_NOT_APPROVED');
  const stale = await sign(device, { method: 'PUT', path: `/api/notes/${NOTE_A}`, body: { title: 't', body: 'b' },
    time: Date.now() - 10 * 60 * 1000 });
  assert.equal((await check(stale)).error, 'DEVICE_SIGNATURE_EXPIRED');
});

test('메모 API는 승인 기기 서명이 없으면 자료 없이 403, 있으면 기존대로 응답한다', async () => {
  const device = await newDevice();
  const store = fakeDb([{ key_thumbprint: device.thumbprint, owner_id: USER_A, public_key_jwk: device.jwk, status: 'approved' }],
    [{ id: NOTE_A, owner_id: USER_A, title: 'A 메모', content: 'A 내용' }]);
  const call = async (headers) => {
    const request = { method: 'GET', query: { id: NOTE_A }, headers: { authorization: 'Bearer A', ...headers } };
    const response = recorder();
    await handleNotesRequest(request, response, { env, fetchImpl: store.fetchImpl, verifyLogin,
      requireDevice: user => verifyDeviceRequest(request, user, { path: `/api/notes/${NOTE_A}`, env, fetchImpl: store.fetchImpl }) });
    return response;
  };
  const unsigned = await call({});
  assert.equal(unsigned.statusCode, 403);
  assert.deepEqual(unsigned.body, { error: 'DEVICE_SIGNATURE_REQUIRED' });
  const signed = await call(await sign(device, { method: 'GET', path: `/api/notes/${NOTE_A}` }));
  assert.equal(signed.statusCode, 200);
  assert.deepEqual(signed.body, { id: NOTE_A, title: 'A 메모', body: 'A 내용' });
  const moved = await call(await sign(device, { method: 'GET', path: '/api/notes' }));
  assert.equal(moved.statusCode, 403);
  assert.deepEqual(moved.body, { error: 'DEVICE_SIGNATURE_INVALID' });
});
