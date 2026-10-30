// 확인용 읽기 모듈입니다. decide.mjs 는 이 파일을 불러오지 않습니다.
// xdr/fixtures/brute-force.json 의 Wazuh 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑습니다.
// 원본 경보는 읽기만 하고 고치지 않으며, 비밀값처럼 보이는 값은 출력하지 않습니다.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const FIXTURE_URL = new URL('../fixtures/brute-force.json', import.meta.url);

// 이름이 비밀값을 뜻하는 칸
const SECRET_KEY = /pass(word|wd)?|secret|token|api[-_]?key|private[-_]?key|authorization|credential/i;
// 값 모양이 비밀값처럼 보이는 것
const SECRET_VALUES = [
  /sb_(secret|publishable)_[\w-]+/g,
  /eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]*/g,
  /Bearer\s+[\w.~+/-]{10,}/gi,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b[A-Fa-f0-9]{32,}\b/g,
  /\b[A-Za-z0-9_-]{40,}\b/g,
];
const HIDDEN = '[숨김]';

function maskValue(text) {
  let out = String(text ?? '');
  for (const re of SECRET_VALUES) out = out.replace(re, HIDDEN);
  return out;
}

// 경보 전체에서 비밀값처럼 보이는 칸·값이 몇 개인지만 셉니다(내용은 쓰지 않습니다).
function countSecretLike(node, key = '') {
  if (node && typeof node === 'object') {
    return Object.entries(node).reduce((sum, [k, v]) => sum + countSecretLike(v, k), 0);
  }
  if (typeof node !== 'string' || node === '') return 0;
  if (SECRET_KEY.test(key)) return 1;
  return SECRET_VALUES.some((re) => new RegExp(re.source, re.flags.replace('g', '')).test(node)) ? 1 : 0;
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
      user: maskValue(alert?.data?.srcuser),
      level: Number(alert?.rule?.level ?? 0),
      description: maskValue(alert?.rule?.description),
    };
  });
  return { alertCount: alerts.length, rows, hiddenCount };
}

function main() {
  const { alertCount, rows, hiddenCount } = readAlerts();
  for (const r of rows) {
    console.log(`${r.time} | ${r.srcip} | ${r.user} | 수준 ${r.level} | ${r.description}`);
  }
  console.error(`경보 ${alertCount}건, 뽑은 줄 ${rows.length}줄` +
    (hiddenCount ? `, 비밀값처럼 보이는 값 ${hiddenCount}건은 출력하지 않음` : ''));
  if (alertCount !== rows.length) {
    console.error('경보 건수와 뽑은 줄 수가 다릅니다.');
    process.exitCode = 1;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
