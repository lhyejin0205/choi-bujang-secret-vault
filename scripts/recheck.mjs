import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RECHECK_CASES, judgeResult, notRunRow } from '../public/recheck-cases.js';

// 12단계: 1~11단계 정상·금지 요청 재확인 표 (npm run ops:recheck).
// 계정 없이 보낼 수 있는 줄(auth: none·forged)만 배포 앱에 실제로 보내고 응답 코드를 그대로 적습니다.
// 로그인·승인 기기가 필요한 줄은 작전실 화면의 「재확인 표 만들기」에서 실행하고, 여기서는 "미실행"으로 둡니다.
// 운영 엔진·계정 비밀값이 필요한 줄도 "미실행"입니다. 어떤 줄도 실행하지 않고 통과로 적지 않습니다.
// 결과는 artifacts/recheck.json(Git 제외)에 저장합니다. 토큰·키·메모 본문은 기록하지 않습니다.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FORGED_TOKEN = ['aaaaaaaaaa', 'bbbbbbbbbb', 'cccccccccc'].join('.');

export function appOrigin(config) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.pathname !== '/' || app.search || app.hash) {
    throw new Error('aleph.config.json의 publicAppUrl을 확인해 주세요.');
  }
  return app;
}

export async function runAnonymousRecheck(app, { fetchImpl = globalThis.fetch, now = () => new Date() } = {}) {
  const rows = [];
  for (const testCase of RECHECK_CASES) {
    if (testCase.engine) { rows.push(notRunRow(testCase, testCase.engine)); continue; }
    if (testCase.auth === 'session') { rows.push(notRunRow(testCase, '로그인과 승인된 기기가 필요해 작전실 화면에서 실행')); continue; }
    const clientRequestId = randomUUID();
    const headers = { 'x-request-id': clientRequestId };
    if (testCase.body !== undefined) headers['content-type'] = 'application/json';
    if (testCase.auth === 'forged') headers.authorization = `Bearer ${FORGED_TOKEN}`;
    if (testCase.sign === 'forged') {
      Object.assign(headers, { 'x-device-key': '0'.repeat(64), 'x-device-time': String(Date.now()), 'x-device-signature': 'A'.repeat(86) });
    }
    const checkedAt = now().toISOString();
    let status = null;
    let serverRequestId = null;
    try {
      const response = await fetchImpl(new URL(testCase.path, app), {
        method: testCase.method, headers, redirect: 'manual', signal: AbortSignal.timeout(10000),
        body: testCase.body === undefined ? undefined : JSON.stringify(testCase.body),
      });
      status = response.status;
      serverRequestId = response.headers.get('x-vercel-id');
    } catch {
      status = null;
    }
    rows.push({ id: testCase.id, stage: testCase.stage, kind: testCase.kind, request: `${testCase.method} ${testCase.path}`,
      name: testCase.name, expected: testCase.expect.join('/'), actual: status === null ? '요청 실패' : String(status),
      verdict: status === null ? '불일치' : judgeResult(testCase, status), clientRequestId, serverRequestId, checkedAt, note: '명령에서 실제 요청' });
  }
  return rows;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
    const rows = await runAnonymousRecheck(appOrigin(config));
    mkdirSync(join(root, 'artifacts'), { recursive: true });
    const out = { schema: 'aleph.recheck.v1', app: config.publicAppUrl, generatedAt: new Date().toISOString(), rows };
    writeFileSync(join(root, 'artifacts', 'recheck.json'), `${JSON.stringify(out, null, 2)}\n`, 'utf8');
    for (const row of rows) {
      process.stdout.write(`${row.verdict.padEnd(4)} · ${row.stage.padEnd(5)} ${row.kind} · ${row.request} · 기대 ${row.expected} · 실제 ${row.actual}`
        + `${row.serverRequestId ? ` · ${row.serverRequestId}` : ''}${row.checkedAt ? ` · ${row.checkedAt}` : ''}${row.verdict === '미실행' ? ` (${row.note})` : ''}\n`);
    }
    const count = verdict => rows.filter(row => row.verdict === verdict).length;
    process.stdout.write(`일치 ${count('일치')} · 불일치 ${count('불일치')} · 미실행 ${count('미실행')} — artifacts/recheck.json\n`
      + '학생 자기 점검이며 심판의 41종 판정이 아닙니다.\n');
    if (count('불일치')) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`재확인 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
