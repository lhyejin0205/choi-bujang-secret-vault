import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { readAlerts } from '../xdr/privilege/read-alerts.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));

test('privilege reader returns one summary row per source alert with only five fields', () => {
  const result = readAlerts();
  assert.equal(result.alertCount, fixture.alerts.length);
  assert.equal(result.rows.length, fixture.alerts.length);
  assert.ok(result.rows.every((row) =>
    Object.keys(row).sort().join(',') === 'account,description,level,srcip,time'));
  // 그룹 이름 같은 다른 칸은 뽑지 않습니다.
  assert.equal(JSON.stringify(result.rows).includes('"administrators"'), false);
});

test('privilege reader hides secret-looking values and does not change the source', () => {
  const dir = mkdtempSync(join(tmpdir(), 'privilege-reader-'));
  try {
    const path = join(dir, 'privilege.json');
    const source = JSON.stringify({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'privilege', alerts: [{
      id: 'x', timestamp: '2026-09-27T09:00:00+09:00', rule: { level: 9,
        description: 'admin token eyJabcdefghijklmn.eyJabcdefghijklmn.signaturepart used' },
      data: { srcip: '192.0.2.1', srcuser: 'user01', secret: 'not-shown' } }] });
    writeFileSync(path, source);
    const result = readAlerts(pathToFileURL(path));
    assert.equal(result.rows.length, 1);
    assert.equal(JSON.stringify(result.rows).includes('eyJabcdefghijklmn'), false);
    assert.equal(JSON.stringify(result.rows).includes('not-shown'), false);
    assert.equal(result.hiddenCount, 2);
    assert.equal(readFileSync(path, 'utf8'), source);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('privilege patterns are grounded: each has a name, condition, one-line evidence, and a T1068/T1078 technique', () => {
  const patterns = JSON.parse(readFileSync(new URL('../xdr/privilege/patterns.json', import.meta.url), 'utf8'));
  assert.equal(patterns.moduleKey, 'privilege');
  assert.deepEqual(patterns.thresholds, { block: 0.85, alert: 0.5 });
  const names = new Set();
  for (const pattern of patterns.patterns) {
    assert.ok(!names.has(pattern.name), pattern.name);
    names.add(pattern.name);
    assert.ok(typeof pattern.condition === 'string' && pattern.condition.length > 10, pattern.name);
    assert.ok(typeof pattern.evidence === 'string' && pattern.evidence.length > 10, pattern.name);
    assert.equal(/\r|\n/u.test(pattern.evidence), false, pattern.name);
    assert.match(pattern.evidence, /T1068|T1078/u, pattern.name);
    assert.ok(pattern.techniques.length > 0 && pattern.techniques.every((t) => ['T1068', 'T1078'].includes(t)), pattern.name);
    assert.ok(pattern.confidence >= 0 && pattern.confidence <= 1, pattern.name);
  }
  // 과제가 말한 세 신호(관리자 그룹 추가, 처음 보는 관리자 명령, 업무 시간 밖 권한 사용)가 모두 패턴으로 있습니다.
  for (const name of ['account-added-to-admin-group', 'privileged-command-after-escalation', 'off-hours-privileged-use']) {
    assert.ok(names.has(name), name);
  }
});

test('privilege decision module is standalone, copies patterns.json, and splits attack, ambiguous, and normal alerts', async () => {
  const { decide } = await import('../xdr/privilege/decide.mjs');
  const source = readFileSync(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /^\s*import\s/mu);
  assert.doesNotMatch(source, /\b(?:require|readFileSync|writeFileSync|readFile|writeFile|fetch)\s*\(/u);

  const patterns = JSON.parse(readFileSync(new URL('../xdr/privilege/patterns.json', import.meta.url), 'utf8'));
  for (const pattern of patterns.patterns) {
    assert.ok(source.includes(`name: '${pattern.name}'`), pattern.name);
    assert.ok(source.includes(pattern.evidence), pattern.name);
    assert.ok(source.includes(`confidence: ${pattern.confidence},`), pattern.name);
  }

  const decisions = fixture.alerts.map((alert) => decide(alert));
  assert.ok(decisions.slice(0, 9).every((d) => d.action === 'block' && d.confidence >= 0.85));
  assert.ok(decisions.slice(9, 17).every((d) => d.action === 'alert' && d.confidence >= 0.5 && d.confidence < 0.85));
  assert.ok(decisions.slice(17).every((d) => d.action === 'record' && d.confidence < 0.5));
  assert.ok(decisions.every((d) => typeof d.reason === 'string' && d.reason.length > 0 && !/\r|\n/u.test(d.reason)));
  assert.ok(decisions.every((d) => Object.keys(d).sort().join(',') === 'action,confidence,reason'));

  const base = fixture.alerts[0];
  assert.equal(decide({ ...base, rule: { ...base.rule, level: 8 } }).action, 'alert');
  assert.equal(decide({ ...base, rule: { ...base.rule, mitre: [] } }).action, 'record');
  assert.equal(decide({ ...base, data: { ...base.data, group: 'project-week3' } }).action, 'alert');
  assert.equal(decide({ ...base, rule: { ...base.rule, mitre: ['T1078.003'] } }).action, 'block');
  const noGroup = { ...base, data: { srcip: base.data.srcip, srcuser: base.data.srcuser } };
  assert.equal(decide({ ...noGroup, timestamp: '2026-09-27T23:10:00+09:00' }).action, 'block');
  assert.equal(decide({ ...noGroup, timestamp: '2026-09-27T14:10:00+09:00' }).action, 'alert');
  assert.equal(decide({}).action, 'record');
  assert.equal(decide(null).action, 'record');
});

test('privilege responder blocks only clear attacks, keeps other rules, and logs block and alert once', async () => {
  const { decide } = await import('../xdr/privilege/decide.mjs');
  const { respondAlerts } = await import('../xdr/privilege/respond.mjs');
  const { mkdirSync } = await import('node:fs');
  const root = mkdtempSync(join(tmpdir(), 'privilege-respond-'));
  try {
    const xdrDir = join(root, 'xdr');
    mkdirSync(xdrDir);
    const rulesPath = join(xdrDir, 'deny-rules.json');
    const logPath = join(xdrDir, 'alerts.log');
    const otherRule = { id: 'xdr-ps-203.0.113.9', action: 'deny', srcip: '203.0.113.9', expiresAt: '2026-09-27T07:00:00.000Z' };
    writeFileSync(join(xdrDir, 'allowlist.json'), JSON.stringify({ ips: [] }));
    writeFileSync(rulesPath, JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules: [otherRule] }));
    writeFileSync(logPath, '');

    const decisions = fixture.alerts.map((alert) => decide(alert));
    const now = new Date('2026-09-27T00:10:00.000Z');
    const result = respondAlerts({ alerts: fixture.alerts, decisions, root, now });
    const saved = JSON.parse(readFileSync(rulesPath, 'utf8')).rules;
    assert.ok(saved.some((rule) => rule.id === otherRule.id), '다른 모듈 규칙 보존');
    const own = saved.filter((rule) => rule.id.startsWith('xdr-pv-'));
    const attackIps = new Set(fixture.alerts.slice(0, 9).map((alert) => alert.data.srcip));
    const otherIps = new Set(fixture.alerts.slice(9).map((alert) => alert.data.srcip));
    assert.equal(own.length, attackIps.size);
    assert.ok(own.every((rule) => attackIps.has(rule.srcip) && rule.action === 'deny'
      && rule.alertIds.length > 0 && !Number.isNaN(Date.parse(rule.expiresAt))));
    assert.ok(own.every((rule) => !otherIps.has(rule.srcip)), '정상·애매한 경보 주소는 규칙에 없음');
    assert.deepEqual(own.find((rule) => rule.srcip === fixture.alerts[0].data.srcip).alertIds, ['pv-01', 'pv-02']);
    assert.equal(result.replay.normalBlocked, 0);
    assert.equal(result.replay.mismatches, 0);
    assert.equal(result.replay.blocked, 9);
    const lines = readFileSync(logPath, 'utf8').trim().split(/\r?\n/u);
    assert.equal(lines.length, 17);
    assert.ok(lines.every((line) => / \| (block|alert) \| pv-\d\d \| /u.test(line)));

    respondAlerts({ alerts: fixture.alerts, decisions, root, now });
    assert.equal(readFileSync(logPath, 'utf8').trim().split(/\r?\n/u).length, 17);

    writeFileSync(join(xdrDir, 'allowlist.json'), JSON.stringify({ ips: [fixture.alerts[0].data.srcip] }));
    writeFileSync(rulesPath, JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules: [] }));
    const allowed = respondAlerts({ alerts: fixture.alerts, decisions, root, now });
    assert.ok(!allowed.rules.some((rule) => rule.srcip === fixture.alerts[0].data.srcip));
    assert.ok(allowed.skipped.includes('pv-01'));

    writeFileSync(join(xdrDir, 'allowlist.json'), JSON.stringify({ ips: [] }));
    writeFileSync(rulesPath, JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules: [] }));
    const weak = { ...fixture.alerts[0], rule: { ...fixture.alerts[0].rule, level: 6 } };
    const forced = respondAlerts({ alerts: [weak], decisions: [{ action: 'block', confidence: 0.92,
      reason: 'account-added-to-admin-group: 시험' }], root, now });
    assert.equal(forced.rules.length, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
