// decide 결과 가운데 차단 후보만 xdr/deny-rules.json 의 거부 규칙으로 쌓고,
// 알림은 xdr/alerts.log 에 한 줄씩 남깁니다. 판정기(src/decider.mjs)와 기존 규칙은 건드리지 않습니다.
// 이 파일은 심판 격리 환경에서 불리지 않는 연결용입니다. decide.mjs 는 판단만 하고 파일을 쓰지 않습니다.
import { readFileSync, writeFileSync, appendFileSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decide } from './decide.mjs';

// 운영자가 지정한 주소만 차단에서 제외합니다. 판정 결과에서 추론하지 않습니다.
const ALLOWLIST_FILE = fileURLToPath(new URL('../allowlist.json', import.meta.url));
function loadAllowlist() {
  if (!existsSync(ALLOWLIST_FILE)) return new Set();
  return new Set(JSON.parse(readFileSync(ALLOWLIST_FILE, 'utf8')).ips ?? []);
}

const FIXTURE_FILE = fileURLToPath(new URL('../fixtures/brute-force.json', import.meta.url));
const RULES_FILE = fileURLToPath(new URL('../deny-rules.json', import.meta.url));
const LOG_FILE = fileURLToPath(new URL('../alerts.log', import.meta.url));
const TTL_MS = 60 * 60 * 1000; // 거부 규칙은 만든 뒤 1시간이 지나면 만료됩니다.
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

const isT1110 = (alert) =>
  Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((t) => String(t).startsWith('T1110'));

function loadRules() {
  if (!existsSync(RULES_FILE)) return [];
  try {
    const saved = JSON.parse(readFileSync(RULES_FILE, 'utf8'));
    return Array.isArray(saved.rules) ? saved.rules : [];
  } catch {
    return [];
  }
}

export function isDenied(rules, srcip, now = new Date()) {
  return rules.some((r) => r.srcip === srcip && Date.parse(r.expiresAt) > now.getTime());
}

// 차단 후보만 규칙으로 만듭니다. 허용 목록(xdr/allowlist.json)에 있는 주소와 T1110 표시가 없는 경보는 규칙에 넣지 않습니다.
export function buildRules(alerts, existingRules = [], now = new Date()) {
  const results = alerts.map((alert) => ({ alert, d: decide(alert) }));
  const normalIps = loadAllowlist();
  // 이 모듈이 만든 규칙(xdr-bf-)만 다루고, 다른 모듈·운영자 규칙은 그대로 돌려줍니다.
  const isOwnBf = (r) => typeof r?.id === 'string' && r.id.startsWith('xdr-bf-');
  const others = existingRules.filter((r) => !isOwnBf(r));
  const own = new Map(
    existingRules.filter((r) => isOwnBf(r) && Date.parse(r.expiresAt) > now.getTime()).map((r) => [r.id, r]),
  );
  const skipped = [];
  for (const { alert, d } of results) {
    if (d.action !== 'block') continue;
    const ip = alert.data?.srcip;
    if (!IPV4.test(ip ?? '') || normalIps.has(ip) || !isT1110(alert)) {
      skipped.push(alert.id);
      continue;
    }
    const id = `xdr-bf-${ip}`;
    const prev = own.get(id);
    own.set(id, {
      id,
      action: 'deny',
      srcip: ip,
      alertIds: [...new Set([...(prev?.alertIds ?? []), alert.id])],
      reason: d.reason,
      confidence: Math.max(prev?.confidence ?? 0, d.confidence),
      createdAt: prev?.createdAt ?? now.toISOString(),
      expiresAt: new Date(now.getTime() + TTL_MS).toISOString(),
    });
  }
  return { results, rules: [...others, ...own.values()], skipped };
}

// block·alert 만 알림으로 남기고, 이미 쓴 (경보 번호, 행동) 은 다시 쓰지 않습니다.
export function writeNotices(results, now = new Date()) {
  const seen = existsSync(LOG_FILE) ? readFileSync(LOG_FILE, 'utf8') : '';
  const lines = [];
  for (const { alert, d } of results) {
    if (d.action === 'record') continue;
    if (seen.includes(`| ${d.action} | ${alert.id} |`)) continue;
    lines.push(`${now.toISOString()} | ${d.action} | ${alert.id} | ${alert.data?.srcip ?? '-'} | ${d.confidence} | ${d.reason}`);
  }
  if (lines.length) appendFileSync(LOG_FILE, lines.join('\n') + '\n', 'utf8');
  return lines.length;
}

function main() {
  const now = new Date();
  const { alerts } = JSON.parse(readFileSync(FIXTURE_FILE, 'utf8'));
  const { results, rules, skipped } = buildRules(alerts, loadRules(), now);
  writeFileSync(RULES_FILE, JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules }, null, 2) + '\n', 'utf8');
  const noticeCount = writeNotices(results, now);

  // 시험 경보를 다시 흘려, 명확한 공격만 막히고 정상 요청은 통과하는지 확인합니다.
  let wrong = 0;
  let blocked = 0;
  for (const { alert, d } of results) {
    const denied = isDenied(rules, alert.data?.srcip, now);
    if (denied) blocked += 1;
    if (denied !== (d.action === 'block') || (denied && d.action === 'record')) wrong += 1;
  }
  console.log(`거부 규칙 ${rules.length}개, 새 알림 ${noticeCount}줄, 규칙 제외 ${skipped.length}건`);
  console.log(`다시 흘린 경보 ${results.length}건 중 막힘 ${blocked}건, 기대와 다른 경우 ${wrong}건`);
  if (wrong) process.exitCode = 1;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
