import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  POLICY_FILES, applyRestore, collectPolicy, diffLines, diffPolicies, hashSnapshot, makeSnapshot, makeTrialPolicy,
  planRestore, verifySnapshot,
} from '../src/policy-backup.mjs';
import { checkPolicy } from '../scripts/policy.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const policy = collectPolicy(root);
const safe = makeSnapshot(policy, { version: 'safe-test', createdAt: '2026-11-06T00:00:00.000Z', sourceCommit: 'a'.repeat(40) });
const hash = hashSnapshot(safe);

test('안전 정책은 판정기 규칙·allowedRoutes·DB 접근 정책을 담고 비밀값은 없다', () => {
  assert.deepEqual(Object.keys(policy.files).sort(), [...POLICY_FILES].sort());
  assert.deepEqual(policy.allowedRoutes, ['GET /api/notes/:id', 'GET /api/notices', 'GET /api/notices/:id']);
  assert.equal(/sb_secret_|eyJ[A-Za-z0-9_-]{12,}\.|BEGIN [A-Z ]*PRIVATE/u.test(JSON.stringify(safe)), false);
});

test('사본을 다시 읽어 해시를 검증하고, 없거나 다르면 중단한다', () => {
  assert.equal(verifySnapshot(JSON.parse(JSON.stringify(safe)), `${hash}\n`), hash);
  assert.throws(() => verifySnapshot(undefined, hash), /사본이 없거나/u);
  assert.throws(() => verifySnapshot(safe, ''), /해시가 없습니다/u);
  const tampered = JSON.parse(JSON.stringify(safe));
  tampered.policy.allowedRoutes.push('GET /api/notes');
  assert.throws(() => verifySnapshot(tampered, hash), /해시가 맞지 않습니다/u);
});

test('시험 정책은 판정기 규칙 한 줄만 바꾸고, 차이에는 그 한 줄만 나온다', () => {
  const trial = makeTrialPolicy(safe.policy);
  const items = diffPolicies(safe.policy, trial);
  assert.equal(items.length, 1);
  assert.equal(items[0].item, 'src/decider.mjs');
  assert.deepEqual(items[0].changes.map(change => change.type), ['removed', 'added']);
  assert.match(items[0].changes[0].text, /route: 'GET \/notes\/:id'/u);
  assert.match(items[0].changes[1].text, /route: 'GET \/notes',/u);
  assert.equal(items[0].changes[0].line, items[0].changes[1].line);
  assert.deepEqual(diffPolicies(safe.policy, safe.policy), []);
});

test('시험 정책을 만들어도 운영 정책 파일은 바뀌지 않는다', () => {
  makeTrialPolicy(safe.policy);
  const decider = readFileSync(new URL('../src/decider.mjs', import.meta.url), 'utf8');
  assert.match(decider, /route: 'GET \/notes\/:id'/u);
  assert.doesNotMatch(decider, /route: 'GET \/notes', path/u);
});

test('allowedRoutes 차이와 줄 차이를 항목별로 보여 준다', () => {
  const changed = { ...safe.policy, allowedRoutes: [...safe.policy.allowedRoutes.slice(1), 'GET /api/notes'] };
  const [routes] = diffPolicies(safe.policy, changed);
  assert.equal(routes.item, 'aleph.config.json#allowedRoutes');
  assert.deepEqual(routes.changes, [{ type: 'removed', text: 'GET /api/notes/:id' }, { type: 'added', text: 'GET /api/notes' }]);
  assert.deepEqual(diffLines('a\nb\nc', 'a\nc\nd'), [
    { type: 'removed', line: 2, text: 'b' }, { type: 'added', line: 3, text: 'd' }]);
});

test('복원은 검증한 사본의 항목만 되돌리고, 사본에 없는 다른 서비스 규칙은 보존한다', () => {
  const attacked = makeTrialPolicy(safe.policy);
  attacked.allowedRoutes = [...attacked.allowedRoutes, 'GET /api/notes'];
  attacked.files = { ...attacked.files, 'xdr/deny-rules.json': '{"other":"service"}' };
  const plan = planRestore(safe.policy, attacked);
  assert.deepEqual(plan.map(({ item }) => item), ['aleph.config.json#allowedRoutes', 'src/decider.mjs']);
  const { policy: restored, restored: items } = applyRestore(safe.policy, attacked);
  assert.deepEqual(items, ['aleph.config.json#allowedRoutes', 'src/decider.mjs']);
  assert.deepEqual(restored.allowedRoutes, safe.policy.allowedRoutes);
  assert.equal(restored.files['src/decider.mjs'], safe.policy.files['src/decider.mjs']);
  assert.equal(restored.files['xdr/deny-rules.json'], '{"other":"service"}');
  assert.deepEqual(planRestore(safe.policy, restored), []);
});

test('복원 뒤 B의 A 자료 요청은 거부되고 A 정상 요청은 유지된다', async () => {
  const before = await checkPolicy(makeTrialPolicy(safe.policy));
  assert.deepEqual(before.filter(item => !item.passed).map(item => item.name),
    ['A 메모 한 건 읽기(판정기)', '메모 전체 목록(판정기)']);
  const after = await checkPolicy(applyRestore(safe.policy, makeTrialPolicy(safe.policy)).policy);
  assert.deepEqual(after.map(({ name, actual, passed }) => [name, actual, passed]), [
    ['A 메모 한 건 읽기(판정기)', 'allow', true],
    ['메모 전체 목록(판정기)', 'deny', true],
    ['B가 A 메모 id 읽기(자료 API)', 404, true],
    ['A가 자기 메모 읽기(자료 API)', 200, true],
  ]);
});
