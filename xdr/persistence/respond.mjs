// 보너스 XDR-04(몰래 심은 프로그램): decide 결과 가운데 차단 후보(block)만 XDR 거부 규칙으로 연결하고,
// block·alert 만 xdr/alerts.log 에 한 줄씩 남깁니다.
// - 규칙은 출발 주소 단위(id: xdr-ps-<주소>)이며 만료 시각과 근거 경보 번호를 붙입니다.
// - 다른 모듈의 규칙은 보존하고, ZTNA 판정기 src/decider.mjs 의 기존 규칙은 고치지 않습니다.
// - decide.mjs 는 판단만 하며, 파일 쓰기와 판정기 연결은 이 파일만 맡습니다.
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decide } from './decide.mjs';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_ROOT = resolve(MODULE_DIR, '../..');
const RULE_PREFIX = 'xdr-ps-';
const TTL_MS = 60 * 60 * 1000;
const TECHNIQUES = ['T1543', 'T1053'];
// 차단 근거로 인정하는 패턴(확신도 0.85 이상인 decide.mjs 패턴 이름)
const BLOCK_PATTERNS = [
  'unsigned-service-from-temp-path',
  'unfamiliar-scheduled-task-temp-path',
  'startup-folder-unlisted-program',
  'repeated-unsigned-service-registration',
];

function isOwnRule(rule) {
  return typeof rule?.id === 'string' && rule.id.startsWith(RULE_PREFIX);
}

function validIpv4(value) {
  if (typeof value !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(value)) return false;
  return value.split('.').every((part) => Number(part) <= 255);
}

function hasPersistenceTechnique(alert) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((value) => typeof value === 'string'
    && TECHNIQUES.includes(value.split('.')[0].toUpperCase()));
}

function blockReason(decision) {
  return typeof decision?.reason === 'string'
    && BLOCK_PATTERNS.some((name) => decision.reason.startsWith(`${name}:`));
}

function readJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  return JSON.parse(readFileSync(path, 'utf8'));
}

function readRules(path) {
  const saved = readJson(path, { rules: [] });
  if (!Array.isArray(saved.rules)) throw new Error('xdr/deny-rules.json 의 rules 형식이 아닙니다.');
  return saved.rules;
}

function lastAlertTime(alerts, fallback) {
  const times = alerts.map((alert) => Date.parse(alert?.timestamp)).filter(Number.isFinite);
  return times.length ? new Date(Math.max(...times)) : fallback;
}

function isDenied(rules, srcip, at) {
  return rules.some((rule) => isOwnRule(rule) && rule.srcip === srcip
    && Date.parse(rule.expiresAt) > at.getTime());
}

function applyDecisions(alerts, decisions, existingRules, allowlist, now) {
  const others = existingRules.filter((rule) => !isOwnRule(rule));
  const own = new Map(existingRules
    .filter((rule) => isOwnRule(rule) && Date.parse(rule.expiresAt) > now.getTime())
    .map((rule) => [rule.id, rule]));
  const skipped = [];
  const paired = alerts.map((alert, index) => ({ alert, decision: decisions[index] }));

  for (const { alert, decision } of paired) {
    if (decision?.action !== 'block') continue;
    const srcip = alert?.data?.srcip;
    // 정상 사용자를 막지 않도록: 허용 목록 주소, 지속성 기법 표시가 없는 경보, 차단 패턴 근거가 없는 결과는 규칙으로 넣지 않습니다.
    if (!validIpv4(srcip) || allowlist.has(srcip) || !hasPersistenceTechnique(alert) || !blockReason(decision)
        || typeof alert?.id !== 'string' || !alert.id) {
      skipped.push(alert?.id ?? '');
      continue;
    }
    const atValue = Date.parse(alert.timestamp);
    const expiresAt = (Number.isFinite(atValue) ? atValue : now.getTime()) + TTL_MS;
    if (expiresAt <= now.getTime()) {
      skipped.push(alert.id);
      continue;
    }
    const id = `${RULE_PREFIX}${srcip}`;
    const previous = own.get(id);
    const maxExpiry = Math.max(expiresAt, Date.parse(previous?.expiresAt ?? '') || 0);
    own.set(id, {
      id,
      action: 'deny',
      srcip,
      alertIds: [...new Set([...(previous?.alertIds ?? []), alert.id])],
      reason: decision.reason,
      confidence: Math.max(previous?.confidence ?? 0, decision.confidence),
      createdAt: previous?.createdAt ?? now.toISOString(),
      expiresAt: new Date(maxExpiry).toISOString(),
    });
  }
  return { paired, rules: [...others, ...own.values()], skipped };
}

function appendNotices(logPath, paired, now) {
  const prior = existsSync(logPath) ? readFileSync(logPath, 'utf8') : '';
  const lines = [];
  for (const { alert, decision } of paired) {
    if (!['block', 'alert'].includes(decision?.action)) continue;
    if (prior.includes(`| ${decision.action} | ${alert.id} |`)) continue;
    lines.push(`${now.toISOString()} | ${decision.action} | ${alert.id} | `
      + `${alert?.data?.srcip ?? '-'} | ${decision.confidence} | ${decision.reason}`);
  }
  if (lines.length) appendFileSync(logPath, `${lines.join('\n')}\n`, 'utf8');
  return lines.length;
}

// 경보를 시간순으로 다시 흘려, 그 시각까지의 판단으로 만든 규칙이 각 경보를 막는지 봅니다.
function replay(alerts, decisions, allowlist) {
  let blocked = 0;
  let normalBlocked = 0;
  let mismatches = 0;
  const samples = alerts.map((alert, index) => ({ alert, decision: decisions[index] }));
  for (const { alert, decision } of samples) {
    const timestamp = Date.parse(alert?.timestamp);
    const at = new Date(Number.isFinite(timestamp) ? timestamp : 0);
    const prior = samples.filter((item) => {
      const eventTime = Date.parse(item.alert?.timestamp);
      return Number.isFinite(eventTime) && eventTime <= at.getTime();
    });
    const temporaryRules = applyDecisions(prior.map((item) => item.alert), prior.map((item) => item.decision),
      [], allowlist, at).rules;
    const denied = isDenied(temporaryRules, alert?.data?.srcip, at);
    const expectedDenied = decision?.action === 'block' && validIpv4(alert?.data?.srcip)
      && !allowlist.has(alert.data.srcip) && hasPersistenceTechnique(alert) && blockReason(decision);
    if (denied) blocked += 1;
    if (denied !== expectedDenied) mismatches += 1;
    if (denied && !(hasPersistenceTechnique(alert) && blockReason(decision))) normalBlocked += 1;
  }
  return { blocked, normalBlocked, mismatches };
}

export function respondAlerts({
  alerts,
  decisions = alerts.map((alert) => decide(alert)),
  root = DEFAULT_ROOT,
  now = lastAlertTime(alerts, new Date()),
}) {
  if (!Array.isArray(alerts) || !Array.isArray(decisions) || alerts.length !== decisions.length) {
    throw new TypeError('alerts 와 decisions 는 같은 길이의 배열이어야 합니다.');
  }
  const xdrDir = join(root, 'xdr');
  const rulesPath = join(xdrDir, 'deny-rules.json');
  const logPath = join(xdrDir, 'alerts.log');
  const allowlistData = readJson(join(xdrDir, 'allowlist.json'), { ips: [] });
  if (!Array.isArray(allowlistData.ips)) throw new Error('xdr/allowlist.json 의 ips 형식이 아닙니다.');
  const allowlist = new Set(allowlistData.ips);
  const existing = readRules(rulesPath);
  const { paired, rules, skipped } = applyDecisions(alerts, decisions, existing, allowlist, now);
  writeFileSync(rulesPath, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules }, null, 2)}\n`, 'utf8');
  const noticeCount = appendNotices(logPath, paired, now);
  const replayResult = replay(alerts, decisions, allowlist);
  return { rules, noticeCount, skipped, replay: replayResult };
}

function main() {
  const fixture = readJson(join(MODULE_DIR, '../fixtures/persistence.json'), null);
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'persistence'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('persistence 경보 묶음 형식이 아닙니다.');
  }
  const decisions = fixture.alerts.map((alert) => decide(alert));
  const result = respondAlerts({ alerts: fixture.alerts, decisions });
  console.log(`거부 규칙 ${result.rules.filter(isOwnRule).length}개, 새 알림 ${result.noticeCount}줄, 규칙 제외 ${result.skipped.length}건`);
  console.log(`다시 흘린 경보 ${fixture.alerts.length}건 중 막힘 ${result.replay.blocked}건, 정상 이벤트 막힘 ${result.replay.normalBlocked}건, 불일치 ${result.replay.mismatches}건`);
  if (result.replay.normalBlocked || result.replay.mismatches) process.exitCode = 1;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
