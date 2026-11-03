import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readAlerts } from '../xdr/known-cve/read-alerts.mjs';
import { decide } from '../xdr/known-cve/decide.mjs';
import { respondAlerts } from '../xdr/known-cve/respond.mjs';

const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));

test('known-cve reader returns one safe summary row per source alert', () => {
  const result = readAlerts(new URL('../xdr/fixtures/known-cve.json', import.meta.url));
  assert.equal(result.alertCount, fixture.alerts.length);
  assert.equal(result.rows.length, fixture.alerts.length);
  assert.ok(result.rows.every((row) =>
    Object.keys(row).sort().join(',') === 'account,description,level,srcip,time'));
  assert.equal(JSON.stringify(result.rows).includes('${jndi:'), false);
});

test('known-cve decision module is standalone and distinguishes attack, ambiguous, and normal alerts', async () => {
  const source = await import('node:fs/promises').then(({ readFile }) =>
    readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8'));
  assert.doesNotMatch(source, /^\s*import\s/mu);
  assert.doesNotMatch(source, /\b(?:readFileSync|writeFileSync|fetch)\s*\(/u);
  const decisions = fixture.alerts.map((alert) => decide(alert));
  assert.equal(decisions.filter((decision) => decision.action === 'block').length, 8);
  assert.equal(decisions.filter((decision) => decision.action === 'alert').length, 1);
  assert.equal(decisions.filter((decision) => decision.action === 'record').length, 15);
  assert.equal(decisions[0].action, 'block');
  assert.equal(decisions[12].action, 'alert');
  assert.ok(decisions.slice(16).every((decision) => decision.action === 'record'));
  const untaggedScanner = {
    ...fixture.alerts[12],
    rule: { ...fixture.alerts[12].rule, mitre: [] },
  };
  assert.equal(decide(untaggedScanner).action, 'alert');
  const urlOnlyScanner = {
    ...untaggedScanner,
    rule: { ...untaggedScanner.rule, description: '요청 요약' },
  };
  assert.equal(decide(urlOnlyScanner).action, 'alert');
  const ordinary = {
    ...urlOnlyScanner,
    data: { ...urlOnlyScanner.data, url: '/notes', useragent: 'browser' },
  };
  assert.equal(decide(ordinary).action, 'record');
  assert.ok(decisions.every((decision) => decision.confidence >= 0 && decision.confidence <= 1
    && typeof decision.reason === 'string'));
});

test('known-cve responder preserves other rules and blocks only clear attack events', () => {
  const root = mkdtempSync(join(tmpdir(), 'known-cve-test-'));
  try {
    const xdrDir = join(root, 'xdr');
    const rulesPath = join(xdrDir, 'deny-rules.json');
    const logPath = join(xdrDir, 'alerts.log');
    mkdirSync(xdrDir);
    writeFileSync(join(xdrDir, 'allowlist.json'), JSON.stringify({ ips: [] }));
    writeFileSync(rulesPath, JSON.stringify({
      schema: 'aleph.xdr.deny-rules.v1',
      rules: [{ id: 'xdr-bf-203.0.113.1', action: 'deny', srcip: '203.0.113.1' }],
    }));
    writeFileSync(logPath, '');

    const decisions = fixture.alerts.map((alert) => decide(alert));
    const result = respondAlerts({
      alerts: fixture.alerts,
      decisions,
      root,
      now: new Date(Math.max(...fixture.alerts.map((alert) => Date.parse(alert.timestamp)))),
    });
    const saved = JSON.parse(readFileSync(rulesPath, 'utf8'));
    assert.ok(saved.rules.some((rule) => rule.id === 'xdr-bf-203.0.113.1'));
    assert.equal(result.replay.normalBlocked, 0);
    assert.equal(result.replay.mismatches, 0);
    const notices = readFileSync(logPath, 'utf8').trim().split(/\r?\n/u);
    assert.equal(notices.length, 9);
    assert.equal(notices.some((line) => line.includes('${jndi:')), false);

    const firstAttacks = fixture.alerts.slice(0, 2);
    const attackTime = new Date(Date.parse(firstAttacks[1].timestamp) + 60_000);
    respondAlerts({
      alerts: firstAttacks,
      decisions: decisions.slice(0, 2),
      root,
      now: attackTime,
    });
    const activeRules = JSON.parse(readFileSync(rulesPath, 'utf8')).rules;
    assert.ok(activeRules.some((rule) => rule.id === 'xdr-kc-203.0.113.10'
      && rule.alertIds.includes('kc-01') && rule.alertIds.includes('kc-02')
      && Date.parse(rule.expiresAt) > attackTime.getTime()));
    assert.ok(activeRules.every((rule) => !rule.id.startsWith('xdr-kc-') || rule.alertIds.every((id) =>
      decisions[fixture.alerts.findIndex((alert) => alert.id === id)]?.action === 'block')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
