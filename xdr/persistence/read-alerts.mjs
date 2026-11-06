// 보너스 XDR-04(몰래 심은 프로그램) 확인용 추출기입니다. decide.mjs 는 이 파일을 불러오지 않습니다.
// 원본 Wazuh 모양 경보(xdr/fixtures/persistence.json)는 읽기만 하고 고치지 않습니다.
// 시각·출발 주소·계정·규칙 수준·설명만 뽑고, 비밀값처럼 보이는 값은 가립니다.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const FIXTURE_URL = new URL('../fixtures/persistence.json', import.meta.url);
const SECRET_KEY = /pass(word|wd)?|secret|token|api[-_]?key|private[-_]?key|authorization|credential/i;
const SECRET_VALUE_SOURCES = [
  /sb_(secret|publishable)_[\w-]+/g,
  /eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]*/g,
  /Bearer\s+[\w.~+/-]{10,}/gi,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b[A-Fa-f0-9]{32,}\b/g,
  /\b[A-Za-z0-9_-]{40,}\b/g,
];
const HIDDEN = '[숨김]';

function maskValue(value) {
  let output = String(value ?? '');
  for (const source of SECRET_VALUE_SOURCES) {
    output = output.replace(new RegExp(source.source, source.flags), HIDDEN);
  }
  return output;
}

function countSecretLike(value, key = '') {
  if (value && typeof value === 'object') {
    return Object.entries(value).reduce(
      (count, [name, child]) => count + countSecretLike(child, name), 0,
    );
  }
  if (typeof value !== 'string' || value.length === 0) return 0;
  if (SECRET_KEY.test(key)) return 1;
  return SECRET_VALUE_SOURCES.some((source) =>
    new RegExp(source.source, source.flags.replace('g', '')).test(value)) ? 1 : 0;
}

export function readAlerts(fixtureUrl = FIXTURE_URL) {
  const fixture = JSON.parse(readFileSync(fixtureUrl, 'utf8'));
  const alerts = Array.isArray(fixture.alerts) ? fixture.alerts : [];
  let hiddenCount = 0;
  const rows = alerts.map((alert) => {
    hiddenCount += countSecretLike(alert);
    return {
      time: maskValue(alert?.timestamp),
      srcip: maskValue(alert?.data?.srcip),
      account: maskValue(alert?.data?.srcuser ?? '-'),
      level: Number(alert?.rule?.level ?? 0),
      description: maskValue(alert?.rule?.description),
    };
  });
  return { alertCount: alerts.length, rows, hiddenCount };
}

function main() {
  const { alertCount, rows, hiddenCount } = readAlerts();
  for (const row of rows) {
    console.log(`${row.time} | ${row.srcip} | ${row.account} | 수준 ${row.level} | ${row.description}`);
  }
  console.error(`경보 ${alertCount}건, 뽑은 줄 ${rows.length}줄` +
    (hiddenCount ? `, 비밀값처럼 보이는 값 ${hiddenCount}건은 출력하지 않음` : ''));
  if (alertCount !== rows.length) {
    console.error('경보 건수와 뽑은 줄 수가 다릅니다.');
    process.exitCode = 1;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
