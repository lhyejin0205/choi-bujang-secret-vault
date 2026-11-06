import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { readAlerts } from '../xdr/persistence/read-alerts.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));

test('persistence reader returns one summary row per source alert with only five fields', () => {
  const result = readAlerts();
  assert.equal(result.alertCount, fixture.alerts.length);
  assert.equal(result.rows.length, fixture.alerts.length);
  assert.ok(result.rows.every((row) =>
    Object.keys(row).sort().join(',') === 'account,description,level,srcip,time'));
  // 경로 같은 다른 칸은 뽑지 않습니다.
  assert.equal(JSON.stringify(result.rows).includes('AppData'), false);
});

test('persistence reader hides secret-looking values and does not change the source', () => {
  const dir = mkdtempSync(join(tmpdir(), 'persistence-reader-'));
  try {
    const path = join(dir, 'persistence.json');
    const source = JSON.stringify({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'persistence', alerts: [{
      id: 'x', timestamp: '2026-09-27T09:00:00+09:00', rule: { level: 9,
        description: 'token Bearer abcdefghijklmnopqrstuvwxyz0123456789 in task' },
      data: { srcip: '192.0.2.1', srcuser: 'user01', password: 'not-shown' } }] });
    writeFileSync(path, source);
    const result = readAlerts(pathToFileURL(path));
    assert.equal(result.rows.length, 1);
    assert.equal(JSON.stringify(result.rows).includes('abcdefghijklmnopqrstuvwxyz0123456789'), false);
    assert.equal(JSON.stringify(result.rows).includes('not-shown'), false);
    assert.equal(result.hiddenCount, 2);
    assert.equal(readFileSync(path, 'utf8'), source);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('persistence patterns are grounded: each has a name, condition, one-line evidence, and a T1543/T1053 technique', () => {
  const patterns = JSON.parse(readFileSync(new URL('../xdr/persistence/patterns.json', import.meta.url), 'utf8'));
  assert.equal(patterns.moduleKey, 'persistence');
  assert.deepEqual(patterns.thresholds, { block: 0.85, alert: 0.5 });
  const names = new Set();
  for (const pattern of patterns.patterns) {
    assert.ok(!names.has(pattern.name), pattern.name);
    names.add(pattern.name);
    assert.ok(typeof pattern.condition === 'string' && pattern.condition.length > 10, pattern.name);
    assert.ok(typeof pattern.evidence === 'string' && pattern.evidence.length > 10, pattern.name);
    assert.equal(/\r|\n/u.test(pattern.evidence), false, pattern.name);
    assert.match(pattern.evidence, /MITRE ATT&CK T1\d{3}|T1543|T1053/u, pattern.name);
    assert.ok(pattern.techniques.length > 0 && pattern.techniques.every((t) => ['T1543', 'T1053'].includes(t)), pattern.name);
    assert.ok(pattern.confidence >= 0 && pattern.confidence <= 1, pattern.name);
  }
});

test('persistence decision module is standalone and splits attack, ambiguous, and normal alerts', async () => {
  const { decide } = await import('../xdr/persistence/decide.mjs');
  const source = readFileSync(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /^\s*import\s/mu);
  assert.doesNotMatch(source, /\b(?:readFileSync|writeFileSync|readFile|writeFile|fetch)\s*\(/u);

  const decisions = fixture.alerts.map((alert) => decide(alert));
  assert.ok(decisions.slice(0, 8).every((d) => d.action === 'block' && d.confidence >= 0.85));
  assert.ok(decisions.slice(8, 16).every((d) => d.action === 'alert' && d.confidence >= 0.5 && d.confidence < 0.85));
  assert.ok(decisions.slice(16).every((d) => d.action === 'record' && d.confidence < 0.5));
  assert.ok(decisions.every((d) => typeof d.reason === 'string' && d.reason.length > 0 && !/\r|\n/u.test(d.reason)));

  const base = fixture.alerts[0];
  // 정상 이벤트는 기법 표시가 있어도 막거나 알리지 않습니다(평소 업데이트·서명된 서비스).
  assert.equal(decide({ ...base, rule: { ...base.rule, level: 3 } }).action, 'record');
  // 임시 폴더 실행 파일이어도 수준이 낮으면 차단하지 않고 알림입니다.
  assert.equal(decide({ ...base, rule: { ...base.rule, level: 8 } }).action, 'alert');
  // 수준이 높아도 뚜렷한 신호가 없으면 알림으로 남깁니다(기록으로 흘리지 않음).
  assert.equal(decide({ ...base, data: { ...base.data, path: 'C:\lab\tool.exe' } }).action, 'alert');
  // 기법 표시가 없으면 경로만으로 막지 않습니다.
  assert.equal(decide({ ...base, rule: { ...base.rule, mitre: [] } }).action, 'record');
  // 하위 기법 표시와 / 경로 구분자도 같은 신호로 봅니다.
  assert.equal(decide({ ...base, rule: { ...base.rule, mitre: ['T1543.003'] },
    data: { ...base.data, path: 'C:/Users/u/AppData/Local/Temp/x.exe' } }).action, 'block');
  assert.equal(decide({}).action, 'record');
  assert.equal(decide(null).action, 'record');
});

test('persistence responder blocks only clear attacks, keeps other rules, and logs block and alert once', async () => {
  const { decide } = await import('../xdr/persistence/decide.mjs');
  const { respondAlerts } = await import('../xdr/persistence/respond.mjs');
  const { mkdirSync } = await import('node:fs');
  const root = mkdtempSync(join(tmpdir(), 'persistence-respond-'));
  try {
    const xdrDir = join(root, 'xdr');
    mkdirSync(xdrDir);
    const rulesPath = join(xdrDir, 'deny-rules.json');
    const logPath = join(xdrDir, 'alerts.log');
    writeFileSync(join(xdrDir, 'allowlist.json'), JSON.stringify({ ips: [] }));
    writeFileSync(rulesPath, JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1',
      rules: [{ id: 'xdr-kc-203.0.113.9', action: 'deny', srcip: '203.0.113.9', expiresAt: '2026-09-27T07:00:00.000Z' }] }));
    writeFileSync(logPath, '');

    const decisions = fixture.alerts.map((alert) => decide(alert));
    const result = respondAlerts({ alerts: fixture.alerts, decisions, root });
    const saved = JSON.parse(readFileSync(rulesPath, 'utf8')).rules;
    assert.ok(saved.some((rule) => rule.id === 'xdr-kc-203.0.113.9'), '다른 모듈 규칙 보존');
    const own = saved.filter((rule) => rule.id.startsWith('xdr-ps-'));
    const attackIps = new Set(fixture.alerts.slice(0, 8).map((alert) => alert.data.srcip));
    assert.ok(own.every((rule) => attackIps.has(rule.srcip) && rule.action === 'deny'
      && rule.alertIds.length > 0 && !Number.isNaN(Date.parse(rule.expiresAt))));
    const otherIps = new Set(fixture.alerts.slice(8).map((alert) => alert.data.srcip));
    assert.ok(own.every((rule) => !otherIps.has(rule.srcip)), '정상·애매한 경보 주소는 규칙에 없음');
    assert.equal(result.replay.normalBlocked, 0);
    assert.equal(result.replay.mismatches, 0);
    assert.equal(result.replay.blocked, 8);
    const lines = readFileSync(logPath, 'utf8').trim().split(/\r?\n/u);
    assert.equal(lines.length, 16);
    assert.ok(lines.every((line) => / \| (block|alert) \| ps-\d\d \| /u.test(line)));

    // 다시 흘려도 같은 알림을 두 번 쓰지 않습니다.
    respondAlerts({ alerts: fixture.alerts, decisions, root });
    assert.equal(readFileSync(logPath, 'utf8').trim().split(/\r?\n/u).length, 16);

    // 허용 목록 주소는 차단 후보라도 규칙에 넣지 않습니다.
    writeFileSync(join(xdrDir, 'allowlist.json'), JSON.stringify({ ips: [fixture.alerts[0].data.srcip] }));
    writeFileSync(rulesPath, JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules: [] }));
    const allowed = respondAlerts({ alerts: fixture.alerts, decisions, root });
    assert.ok(!allowed.rules.some((rule) => rule.srcip === fixture.alerts[0].data.srcip));
    assert.ok(allowed.skipped.includes('ps-01'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
