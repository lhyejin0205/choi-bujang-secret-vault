import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// 10단계: 1~9단계에서 만든 접근 규칙을 "안전 정책"으로 정하고 사본·해시·차이를 다룹니다.
// - 판정기 규칙:      src/decider.mjs
// - 허용 경로:        aleph.config.json 의 allowedRoutes
// - DB 접근 정책:     supabase/stage4-rls.sql, supabase/stage5-revoke.sql
// 사본에는 메모 본문·키·토큰이 들어가지 않습니다. 이 모듈은 운영 정책 파일을 고치지 않습니다.
export const POLICY_SCHEMA = 'aleph.safe-policy.v1';
export const POLICY_FILES = Object.freeze([
  'src/decider.mjs',
  'supabase/stage4-rls.sql',
  'supabase/stage5-revoke.sql',
]);

const normalize = text => text.replace(/\r\n?/gu, '\n');

// 지금 저장소의 정책 항목을 읽습니다. 줄바꿈은 LF로 맞춰 운영체제에 따라 해시가 달라지지 않게 합니다.
export function collectPolicy(root) {
  const files = {};
  for (const path of POLICY_FILES) files[path] = normalize(readFileSync(join(root, path), 'utf8'));
  const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
  if (!Array.isArray(config.allowedRoutes)) throw new Error('aleph.config.json의 allowedRoutes가 없습니다.');
  return { allowedRoutes: [...config.allowedRoutes], files };
}

// 키 순서와 상관없이 같은 내용이면 같은 문자열이 되도록 정렬해 직렬화합니다.
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function hashSnapshot(snapshot) {
  return createHash('sha256').update(canonicalJson(snapshot)).digest('hex');
}

export function makeSnapshot(policy, { version, createdAt, sourceCommit }) {
  return { schema: POLICY_SCHEMA, version, createdAt, sourceCommit, policy };
}

function isSnapshot(value) {
  return value !== null && typeof value === 'object' && value.schema === POLICY_SCHEMA
    && typeof value.version === 'string' && value.policy !== null && typeof value.policy === 'object'
    && Array.isArray(value.policy.allowedRoutes) && value.policy.files !== null
    && typeof value.policy.files === 'object';
}

// 사본과 해시를 다시 읽어 검증합니다. 없거나 맞지 않으면 오류로 중단합니다.
export function verifySnapshot(snapshot, expectedHash) {
  if (!isSnapshot(snapshot)) throw new Error('검증한 정책 사본이 없거나 형식이 맞지 않습니다. 중단합니다.');
  if (typeof expectedHash !== 'string' || !/^[0-9a-f]{64}$/u.test(expectedHash.trim())) {
    throw new Error('정책 사본의 확인용 해시가 없습니다. 중단합니다.');
  }
  const actual = hashSnapshot(snapshot);
  if (actual !== expectedHash.trim()) {
    throw new Error(`정책 사본의 해시가 맞지 않습니다(기대 ${expectedHash.trim().slice(0, 12)}, 실제 ${actual.slice(0, 12)}). 중단합니다.`);
  }
  return actual;
}

// 두 줄 목록의 바뀐 부분만 찾습니다(최장 공통 부분열). 정책 파일은 몇백 줄이라 충분히 빠릅니다.
export function diffLines(before, after) {
  const a = normalize(before).split('\n');
  const b = normalize(after).split('\n');
  const table = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      table[i][j] = a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }
  const changes = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) { i += 1; j += 1; continue; }
    if (j < b.length && (i === a.length || table[i][j + 1] > table[i + 1][j])) {
      changes.push({ type: 'added', line: j + 1, text: b[j] });
      j += 1;
    } else {
      changes.push({ type: 'removed', line: i + 1, text: a[i] });
      i += 1;
    }
  }
  return changes;
}

// 검증한 사본과 시험 정책의 차이만 항목별로 돌려줍니다. 같은 항목은 넣지 않습니다.
export function diffPolicies(safePolicy, trialPolicy) {
  const items = [];
  const safeRoutes = new Set(safePolicy.allowedRoutes);
  const trialRoutes = new Set(trialPolicy.allowedRoutes);
  const routeChanges = [
    ...[...safeRoutes].filter(route => !trialRoutes.has(route)).map(text => ({ type: 'removed', text })),
    ...[...trialRoutes].filter(route => !safeRoutes.has(route)).map(text => ({ type: 'added', text })),
  ];
  if (routeChanges.length) items.push({ item: 'aleph.config.json#allowedRoutes', changes: routeChanges });
  const paths = new Set([...Object.keys(safePolicy.files), ...Object.keys(trialPolicy.files)]);
  for (const path of [...paths].sort()) {
    const before = safePolicy.files[path];
    const after = trialPolicy.files[path];
    if (before === after) continue;
    if (before === undefined || after === undefined) {
      items.push({ item: path, changes: [{ type: before === undefined ? 'added' : 'removed', text: '(파일 전체)' }] });
      continue;
    }
    items.push({ item: path, changes: diffLines(before, after) });
  }
  return items;
}

// 만들기 2: 시험 정책을 검증한 안전 정책 버전으로 되돌립니다.
// 되돌리는 대상은 "검증한 사본에 있는 항목 가운데 시험 정책과 다른 것"뿐입니다.
// 검증한 사본에 없는 다른 서비스 규칙(시험 정책에만 있는 파일)은 손대지 않고 보존합니다.
export function planRestore(safePolicy, trialPolicy) {
  return diffPolicies(safePolicy, trialPolicy).filter(({ item }) => item === 'aleph.config.json#allowedRoutes'
    || Object.hasOwn(safePolicy.files, item));
}

export function applyRestore(safePolicy, trialPolicy) {
  const plan = planRestore(safePolicy, trialPolicy);
  const files = { ...trialPolicy.files };
  let allowedRoutes = [...trialPolicy.allowedRoutes];
  for (const { item } of plan) {
    if (item === 'aleph.config.json#allowedRoutes') allowedRoutes = [...safePolicy.allowedRoutes];
    else files[item] = safePolicy.files[item];
  }
  return { policy: { allowedRoutes, files }, restored: plan.map(({ item }) => item) };
}

// 침공 흉내: 판정기에서 메모 한 건 읽기 규칙 한 줄을 "메모 전체 목록 허용"으로 바꾼 시험 정책을 만듭니다.
export const TRIAL_TARGET = "Object.freeze({ service: 'notes', route: 'GET /notes/:id', path: /^\\/notes\\/[^/?#]+$/u }),";
export const TRIAL_REPLACEMENT = "Object.freeze({ service: 'notes', route: 'GET /notes', path: /^\\/notes$/u }),";

export function makeTrialPolicy(safePolicy) {
  const decider = safePolicy.files['src/decider.mjs'];
  const lines = decider.split('\n');
  const index = lines.findIndex(line => line.trim() === TRIAL_TARGET);
  if (index === -1) throw new Error('시험용으로 바꿀 판정기 규칙 줄을 찾지 못했습니다. 중단합니다.');
  const indent = lines[index].slice(0, lines[index].indexOf(TRIAL_TARGET));
  lines[index] = `${indent}${TRIAL_REPLACEMENT}`;
  return { allowedRoutes: [...safePolicy.allowedRoutes], files: { ...safePolicy.files, 'src/decider.mjs': lines.join('\n') } };
}
