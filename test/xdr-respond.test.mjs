// 오늘 고친 세 가지 회귀를 파일을 쓰지 않고 확인합니다: 차단 회피, 모듈 간 규칙 덮어쓰기, 만료 연장.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as bf from '../xdr/brute-force/respond.mjs';
import * as wi from '../xdr/web-injection/respond.mjs';

const load = (m) => JSON.parse(readFileSync(new URL(`../xdr/fixtures/${m}.json`, import.meta.url), 'utf8')).alerts;
const BF = load('brute-force');
const WI = load('web-injection');
const at = (alerts, id) => new Date(Date.parse(alerts.find((a) => a.id === id).timestamp));
const upTo = (alerts, t) => alerts.filter((a) => Date.parse(a.timestamp) <= t.getTime());
const HOUR = 60 * 60 * 1000; // respond.mjs 의 TTL_MS 와 같아야 합니다

test('brute-force: 로그인 성공 경보가 와도 무차별 대입 주소의 차단이 풀리지 않는다', () => {
  const t = at(BF, 'bf-91');
  const { rules } = bf.buildRules(upTo(BF, t), [], t);
  assert.ok(rules.some((r) => r.id === 'xdr-bf-198.51.100.91'), '규칙이 만들어져야 합니다');
  assert.equal(bf.isDenied(rules, '198.51.100.91', t), true);
});

test('web-injection: 무해한 경보를 섞어도 공격 주소가 막힌다', () => {
  const t = at(WI, 'wi-91');
  const { rules } = wi.buildRules(upTo(WI, t), [], t);
  assert.equal(wi.isDenied(rules, '198.51.100.90', t), true);
});

test('두 모듈의 규칙이 같은 주소에서도 서로를 지우거나 섞지 않는다', () => {
  const t = new Date(Math.max(at(BF, 'bf-01').getTime(), at(WI, 'wi-01').getTime()));
  const w1 = wi.buildRules(upTo(WI, t), [], t).rules;
  const b1 = bf.buildRules(upTo(BF, t), w1, t).rules;
  assert.ok(b1.some((r) => r.id === 'xdr-wi-203.0.113.10'), 'bf 실행 직후에도 wi 규칙이 남아야 합니다');
  const w2 = wi.buildRules(upTo(WI, t), b1, t).rules;
  for (const id of ['xdr-wi-203.0.113.10', 'xdr-bf-203.0.113.10']) {
    assert.equal(w2.filter((r) => r.id === id).length, 1, `${id} 가 정확히 하나여야 합니다`);
  }
  const bfRule = w2.find((r) => r.id === 'xdr-bf-203.0.113.10');
  assert.deepEqual(bfRule.alertIds.filter((x) => x.startsWith('wi-')), [], 'bf 규칙에 wi 경보가 섞이면 안 됩니다');
});

test('만료: TTL 이 지난 뒤 같은 경보를 다시 읽어도 차단이 연장되지 않는다', () => {
  const t0 = at(BF, 'bf-90');
  const later = new Date(t0.getTime() + 2 * HOUR);
  const { rules } = bf.buildRules(upTo(BF, t0), [], later);
  assert.equal(bf.isDenied(rules, '198.51.100.91', later), false);
});
