import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  applyRestore, canonicalJson, collectPolicy, diffPolicies, hashSnapshot, makeSnapshot, makeTrialPolicy,
  planRestore, verifySnapshot,
} from '../src/policy-backup.mjs';
import { handleNotesRequest } from '../src/notes-handler.mjs';
import { fixtureRequests } from './fixture-7.mjs';

// 10단계 안전 정책 사본 도구. 운영 정책 파일(src/decider.mjs, aleph.config.json, supabase/*.sql)은 읽기만 합니다.
//   npm run policy:snapshot  지금 정책으로 검증용 사본과 해시를 만듭니다(이미 있으면 덮어쓰지 않음).
//   npm run policy:trial     검증한 사본에서 규칙 한 줄을 바꾼 시험 정책 사본을 만듭니다.
//   npm run policy:diff      사본을 다시 읽어 해시를 검증하고, 시험 정책과의 차이만 보여 줍니다.
//   npm run policy:restore   시험 정책을 검증한 버전으로 되돌릴 항목을 보여 줍니다(바꾸지 않음).
//   npm run policy:restore -- --confirm=<해시 앞 12자>  확인한 뒤 실제로 되돌리고 감사 기록에 덧붙입니다.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const BACKUP_DIR = 'policy-backup';
const SAFE = join(BACKUP_DIR, 'safe-policy.json');
const SAFE_HASH = join(BACKUP_DIR, 'safe-policy.sha256');
const TRIAL = join(BACKUP_DIR, 'trial-policy.json');
// 감사 기록: 한 줄에 한 건씩 덧붙이기만 하고, 지우거나 다시 쓰지 않습니다.
const AUDIT = join(BACKUP_DIR, 'audit-log.jsonl');

const read = (path, what) => {
  if (!existsSync(join(root, path))) throw new Error(`${what}(${path})이 없습니다. 중단합니다.`);
  return readFileSync(join(root, path), 'utf8');
};
const writeJson = (path, value) => writeFileSync(join(root, path), `${JSON.stringify(value, null, 2)}\n`, 'utf8');

export function loadVerifiedSafe() {
  let snapshot;
  try {
    snapshot = JSON.parse(read(SAFE, '검증한 정책 사본'));
  } catch (error) {
    throw error instanceof SyntaxError ? new Error('검증한 정책 사본을 읽을 수 없습니다. 중단합니다.') : error;
  }
  const hash = verifySnapshot(snapshot, read(SAFE_HASH, '정책 사본의 확인용 해시'));
  return { snapshot, hash };
}

function snapshot() {
  if (existsSync(join(root, SAFE)) || existsSync(join(root, SAFE_HASH))) {
    throw new Error('검증한 정책 사본이 이미 있습니다. 덮어쓰지 않고 중단합니다.');
  }
  const sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  const createdAt = new Date().toISOString();
  const safe = makeSnapshot(collectPolicy(root), {
    version: `safe-${createdAt.slice(0, 10)}-${sourceCommit.slice(0, 7)}`, createdAt, sourceCommit,
  });
  mkdirSync(join(root, BACKUP_DIR), { recursive: true });
  writeJson(SAFE, safe);
  const hash = hashSnapshot(safe);
  writeFileSync(join(root, SAFE_HASH), `${hash}\n`, 'utf8');
  return [`검증용 정책 사본을 만들었습니다: ${safe.version}`, `확인용 해시(SHA-256): ${hash}`];
}

function trial() {
  const { snapshot: safe, hash } = loadVerifiedSafe();
  const trialPolicy = {
    schema: 'aleph.trial-policy.v1', basedOn: safe.version, basedOnHash: hash,
    note: '침공 흉내: 판정기의 메모 한 건 읽기 규칙을 메모 전체 목록 허용으로 바꾼 시험 정책입니다. 운영 정책이 아닙니다.',
    policy: makeTrialPolicy(safe.policy),
  };
  writeJson(TRIAL, trialPolicy);
  return [`시험 정책 사본을 만들었습니다: ${TRIAL} (기준 ${safe.version})`];
}

function loadTrial() {
  const trialSnapshot = JSON.parse(read(TRIAL, '시험 정책 사본'));
  if (trialSnapshot?.schema !== 'aleph.trial-policy.v1' || !trialSnapshot.policy
      || !Array.isArray(trialSnapshot.policy.allowedRoutes) || !trialSnapshot.policy.files) {
    throw new Error('시험 정책 사본의 형식이 맞지 않습니다. 중단합니다.');
  }
  return trialSnapshot;
}

const policyHash = policy => hashSnapshot(policy);

// 정책을 다시 시험합니다. 시험 정책의 판정기 코드와 운영 자료 API(소유자 검사)를 메모리에서만 부릅니다.
//  - A의 메모 한 건 읽기(GET /notes/:id)는 판정기에서 허용되어야 합니다.
//  - 메모 전체 목록(GET /notes)은 판정기에서 거부되어야 합니다.
//  - B가 A 메모 id를 읽으면 자료 API가 404, A가 읽으면 200이어야 합니다.
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const NOTE_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

async function apiStatus(token) {
  const row = { id: NOTE_A, owner_id: USER_A, title: '가상 A 메모', content: '가상 내용' };
  const fetchImpl = async (url) => {
    const owner = new URL(url).searchParams.get('owner_id')?.replace(/^eq\./u, '');
    return new Response(JSON.stringify(owner === row.owner_id ? [row] : []), { status: 200 });
  };
  const verifyLogin = async auth => ({ 'Bearer A': { kind: 'student', userId: USER_A },
    'Bearer B': { kind: 'student', userId: USER_B } })[auth] ?? null;
  const response = { statusCode: 0, setHeader() {}, status(code) { this.statusCode = code; return this; }, json() { return this; } };
  await handleNotesRequest({ method: 'GET', query: { id: NOTE_A }, headers: { authorization: `Bearer ${token}` } },
    response, { env: { SUPABASE_URL: 'https://project.supabase.co', SUPABASE_SECRET_KEY: 'test-only' }, fetchImpl, verifyLogin });
  return response.statusCode;
}

export async function checkPolicy(policy) {
  const source = policy.files['src/decider.mjs'];
  const { decide } = await import(`data:text/javascript;charset=utf-8,${encodeURIComponent(source)}`);
  const { normal } = fixtureRequests();
  const single = await decide(normal);
  const list = await decide({ ...normal, requestId: crypto.randomUUID(), route: 'GET /notes', path: '/notes' });
  const checks = [
    { name: 'A 메모 한 건 읽기(판정기)', expected: 'allow', actual: single.decision },
    { name: '메모 전체 목록(판정기)', expected: 'deny', actual: list.decision },
    { name: 'B가 A 메모 id 읽기(자료 API)', expected: 404, actual: await apiStatus('B') },
    { name: 'A가 자기 메모 읽기(자료 API)', expected: 200, actual: await apiStatus('A') },
  ];
  return checks.map(item => ({ ...item, passed: item.actual === item.expected }));
}

const checkLines = checks => checks.map(item => `  ${item.passed ? '통과' : '실패'} · ${item.name}: ${item.actual}`
  + (item.passed ? '' : ` (기대 ${item.expected})`));

async function restore() {
  const { snapshot: safe, hash } = loadVerifiedSafe();
  const trialSnapshot = loadTrial();
  const plan = planRestore(safe.policy, trialSnapshot.policy);
  const confirmArg = process.argv.slice(3).find(arg => arg.startsWith('--confirm='));
  const token = hash.slice(0, 12);
  const lines = [`복원할 버전: ${safe.version} (사본 해시 검증 통과 ${token}…)`, `대상: ${TRIAL} (운영 정책 파일은 바꾸지 않음)`];
  if (!plan.length) return [...lines, '되돌릴 항목이 없습니다. 시험 정책이 이미 검증한 버전과 같습니다.'];
  lines.push(`바뀔 항목 ${plan.length}개:`);
  for (const { item, changes } of plan) {
    lines.push(`- ${item}`);
    // diff(검증본→시험본): removed = 검증본에만 있는 줄(되살림), added = 시험본에만 있는 줄(없앰)
    for (const change of changes) {
      lines.push(`  ${change.type === 'removed' ? '되살릴 줄' : '없앨 줄'}${change.line ? ` ${change.line}행` : ''}: ${change.text.trim()}`);
    }
  }
  const kept = Object.keys(trialSnapshot.policy.files).filter(path => !Object.hasOwn(safe.policy.files, path));
  lines.push(`보존할 다른 서비스 규칙: ${kept.length ? kept.join(', ') : '없음'}`);
  lines.push('지금 시험 정책 확인:', ...checkLines(await checkPolicy(trialSnapshot.policy)));
  if (!confirmArg) {
    return [...lines, `아직 아무것도 바꾸지 않았습니다. 위 항목을 확인했으면 다음을 실행하세요:`,
      `  npm run policy:restore -- --confirm=${token}`];
  }
  if (confirmArg !== `--confirm=${token}`) throw new Error('확인 값이 검증한 사본 해시와 맞지 않습니다. 중단합니다.');

  const before = policyHash(trialSnapshot.policy);
  const { policy, restored } = applyRestore(safe.policy, trialSnapshot.policy);
  const checks = await checkPolicy(policy);
  const entry = {
    at: new Date().toISOString(), action: 'restore_trial_policy', target: TRIAL.replaceAll('\\', '/'),
    restoredTo: safe.version, safeHash: hash, beforeHash: before, afterHash: policyHash(policy),
    restoredItems: restored, keptItems: kept, recheck: checks.map(({ name, passed }) => ({ name, passed })),
  };
  writeJson(TRIAL, { ...trialSnapshot, policy, restoredFrom: safe.version, restoredAt: entry.at });
  appendFileSync(join(root, AUDIT), `${canonicalJson(entry)}\n`, 'utf8');
  lines.push(`되돌렸습니다: ${restored.join(', ')}`, `감사 기록에 한 줄 덧붙였습니다: ${AUDIT}`,
    '복원 뒤 다시 확인:', ...checkLines(checks));
  if (checks.some(item => !item.passed)) throw new Error(`${lines.join('\n')}\n복원 뒤 확인에 실패한 항목이 있습니다.`);
  return lines;
}

export function describeDiff() {
  const { snapshot: safe, hash } = loadVerifiedSafe();
  const trialSnapshot = loadTrial();
  const items = diffPolicies(safe.policy, trialSnapshot.policy);
  const lines = [
    `복원할 버전: ${safe.version} (원본 커밋 ${safe.sourceCommit.slice(0, 7)}, 만든 시각 ${safe.createdAt})`,
    `사본 해시 검증: 통과 ${hash.slice(0, 12)}…`,
    `시험 정책의 기준 버전: ${trialSnapshot.basedOn ?? '(없음)'}`,
  ];
  if (!items.length) return [...lines, '변경 범위: 없음 (시험 정책이 검증한 사본과 같습니다)'];
  lines.push(`변경 범위: ${items.length}개 항목`);
  for (const { item, changes } of items) {
    lines.push(`- ${item}`);
    for (const change of changes) {
      lines.push(`  ${change.type === 'added' ? '+' : '-'}${change.line ? ` ${change.line}행` : ''} ${change.text.trim()}`);
    }
  }
  return lines;
}

const COMMANDS = { snapshot, trial, diff: describeDiff, restore };

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const command = COMMANDS[process.argv[2]];
  try {
    if (!command) throw new Error('사용법: node scripts/policy.mjs snapshot|trial|diff|restore');
    process.stdout.write(`${(await command()).join('\n')}\n`);
  } catch (error) {
    process.stderr.write(`정책 사본 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
