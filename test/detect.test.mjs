import assert from 'node:assert/strict';
import { test } from 'node:test';
import { burstReadSubject, detect, readEvent, readEvents } from '../src/detect.mjs';

const at = '2026-10-01T00:00:00.000Z';
const START = Date.parse(at);
const reads = (count, { gapMs = 2000, sub = 'learner_fixture', method = 'GET', start = START } = {}) =>
  Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * gapMs).toISOString(), method, identity: { sub } }));

test('burst_read: 10분 안 121건 이상 조회만 의심이다', () => {
  assert.equal(burstReadSubject(reads(120)), null);
  assert.equal(burstReadSubject(reads(121)), 'learner_fixture');
  assert.equal(burstReadSubject(reads(200)), 'learner_fixture');
});

test('burst_read: 10분 경계와 느린 조회는 같은 구간으로 세지 않는다', () => {
  // 121건이 정확히 10분(600초)에 걸쳐 있으면 처음과 마지막은 다른 구간입니다.
  assert.equal(burstReadSubject(reads(121, { gapMs: 5000 })), null);
  // 같은 121건이 10분보다 조금 짧게 모이면 의심입니다.
  assert.equal(burstReadSubject(reads(121, { gapMs: 4999 })), 'learner_fixture');
  assert.equal(burstReadSubject(reads(200, { gapMs: 7000 })), null);
});

test('burst_read: 다른 사용자·GET이 아닌 사건은 합치지 않고, 순서가 섞여도 at으로 센다', () => {
  const mixed = [...reads(100), ...reads(100, { sub: 'other_fixture' })];
  assert.equal(burstReadSubject(mixed), null);
  assert.equal(burstReadSubject([...reads(100), ...reads(100, { method: 'PUT', start: START + 1 })]), null);
  const shuffled = reads(121).reverse();
  assert.equal(burstReadSubject(shuffled), 'learner_fixture');
  assert.equal(burstReadSubject([...reads(60, { sub: 'other_fixture' }), ...reads(121, { sub: 'burst_fixture' })]),
    'burst_fixture');
});

test('사건에서 at·method·identity.sub 세 값만 읽는다', () => {
  const event = { at, method: 'get', identity: { sub: 'learner_fixture', name: '실명', email: 'x' },
    token: 'secret-token', body: '메모 본문', network: 'first_seen', deviceId: 'a'.repeat(16), region: 'foreign' };
  const read = readEvent(event);
  assert.deepEqual(Object.keys(read).sort(), ['atMs', 'method', 'sub']);
  assert.deepEqual({ ...read }, { atMs: Date.parse(at), method: 'GET', sub: 'learner_fixture' });
  assert.equal(JSON.stringify(read).includes('secret-token'), false);
  assert.equal(JSON.stringify(read).includes('메모 본문'), false);
});

test('형식이 맞지 않는 사건은 세지 않고 건너뛴다', () => {
  const bad = [null, [], 'GET', { method: 'GET', identity: { sub: 'a' } },
    { at: 'not-a-time', method: 'GET', identity: { sub: 'a' } },
    { at, method: 1, identity: { sub: 'a' } }, { at, method: 'GET' },
    { at, method: 'GET', identity: { sub: '' } }, { at, method: 'GET', identity: [] },
    { at, method: 'GET', userId: 'a' }];
  assert.deepEqual(readEvents(bad), []);
  assert.equal(readEvents([...bad, { at, method: 'GET', identity: { sub: 'a' } }]).length, 1);
});

test('배열이 아니면 오류이고, 정상 사건은 observe 한 키만 돌려준다', () => {
  assert.throws(() => detect(null), /invalid_detection_events/u);
  assert.deepEqual(detect([{ at, method: 'GET', identity: { sub: 'a' } }]), { action: 'observe' });
  assert.deepEqual(detect([]), { action: 'observe' });
});

test('폭주면 정확히 세 키로 회수를 제안하고, 기기 번호 같은 값은 붙이지 않는다', () => {
  const events = reads(121).map(event => ({ ...event, deviceId: 'a'.repeat(16), token: 'secret-token' }));
  const result = detect(events);
  assert.deepEqual(result, { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'learner_fixture' });
  assert.deepEqual(Object.keys(result).sort(), ['action', 'reasonCode', 'subject']);
  assert.equal(JSON.stringify(result).includes('secret-token'), false);
});
