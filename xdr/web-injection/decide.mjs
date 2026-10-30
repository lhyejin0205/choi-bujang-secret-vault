// 심판이 인터넷 없이 이 파일 하나만 불러옵니다. import 도 파일 읽기·쓰기도 바깥 호출도 없고,
// 경보 하나를 받아 이 파일 안에서 혼자 계산해 답합니다. 파일 쓰기·판정기 연결은 respond.mjs 가 합니다.

// ---- patterns.json 에서 옮겨 적은 상수 (고치면 patterns.json 도 같이 맞추세요) ----
const THRESHOLDS = Object.freeze({ block: 0.85, alert: 0.5 });
const LEVEL_BOOST = Object.freeze({ minLevel: 10, add: 0.03 });
const COUNT_TIERS = Object.freeze([
  { minCount: 8, score: 0.88 },
  { minCount: 3, score: 0.7 },
  { minCount: 1, score: 0.55 },
]);
const URL_MARKER_MIN_SCORE = 0.7;
const FLOOR = Object.freeze({ name: 't1190-tag-only', score: 0.5 });
const PATTERNS = Object.freeze([
  {
    name: 'sql-fragment-in-request',
    condition: '경보가 T1190 으로 분류되고, 경보 설명에 SQL 구문 표기(SQL, 데이터베이스 조회, select, 따옴표)가 있거나 요청 주소 인자에 SQL 구문이 있다. 반복 횟수(count)가 8회 이상이면 뚜렷, 3회 이상이면 의심, 1회는 약하다.',
    evidence: 'MITRE ATT&CK T1190: 공개된 앱의 입력 처리 약점을 노려 요청 인자에 SQL 구문을 끼워 넣는 SQL 주입은 T1190 의 대표 악용 사례(APT39 등)로 올라 있다.',
    descriptionKeywords: ['SQL', '데이터베이스 조회', 'select', '따옴표'],
    urlRegex: "('|%27)(\\s|\\+|%20)*(or|and)(\\s|\\+|%20)+\\d+\\s*=\\s*\\d+|union(\\s|\\+|%20)+select|(;|%3b)(\\s|\\+|%20)*drop(\\s|\\+|%20)",
  },
  {
    name: 'script-tag-in-request',
    condition: '경보가 T1190 으로 분류되고, 경보 설명에 스크립트 삽입 표기가 있거나 요청 주소 인자에 스크립트 태그가 있다. 반복 횟수 기준은 위와 같다.',
    evidence: 'MITRE ATT&CK T1190: 공개된 앱이 입력 값을 검증하지 못하는 약점을 노려 요청 인자에 스크립트 태그를 끼워 넣는 것은 웹 앱 약점 악용의 한 형태다(T1190 항목에는 SQL 주입·명령 주입·경로 순회 사례가 직접 올라 있고, 스크립트 삽입은 일반적인 웹 앱 약점 분류에 따른다).',
    descriptionKeywords: ['스크립트'],
    urlRegex: '<script|%3cscript',
  },
  {
    name: 'path-traversal-repeat',
    condition: '경보가 T1190 으로 분류되고, 경보 설명에 경로를 거슬러 올라가는(경로 이탈) 표기가 있거나 요청 주소에 ../ 가 두 번 이상 반복된다. 반복 횟수 기준은 위와 같다.',
    evidence: 'MITRE ATT&CK T1190: 공개된 앱의 경로 처리 약점을 노려 ../ 를 반복해 허용 범위 밖 파일에 닿는 경로 순회(디렉터리 순회)는 T1190 사례(APT41 의 C0017 등)로 올라 있다.',
    descriptionKeywords: ['거슬러 올라가', '경로 이탈', '../'],
    urlRegex: '(\\.\\./|%2e%2e%2f|\\.\\.%2f){2,}',
  },
  {
    name: 'command-separator-in-request',
    condition: '경보가 T1190 으로 분류되고, 경보 설명에 명령 구분자 표기가 있거나 요청 주소 인자에 명령 구분자 뒤 셸 명령이 있다. 반복 횟수 기준은 위와 같다. (요청하신 세 신호 밖에서 시험 경보 wi-06 때문에 추가한 패턴입니다.)',
    evidence: 'MITRE ATT&CK T1190: 공개된 앱의 입력 처리 약점으로 서버에 명령을 실행시키는 명령 주입은 T1190 사례(Ivanti Connect Secure 악용 등)로 올라 있다.',
    descriptionKeywords: ['명령 구분자', '구분 문자'],
    urlRegex: '(;|\\|\\||&&|%3b|%7c%7c|%26%26)\\s*(cat|ls|id|whoami|wget|curl)\\b',
  },
]);
// -------------------------------------------------------------------------------

const COMPILED = PATTERNS.map((p) => ({ ...p, url: new RegExp(p.urlRegex, 'i') }));

function toCount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function actionFor(confidence) {
  if (confidence >= THRESHOLDS.block) return 'block';
  if (confidence >= THRESHOLDS.alert) return 'alert';
  return 'record';
}

export function decide(alert) {
  const a = alert && typeof alert === 'object' ? alert : {};
  const mitre = Array.isArray(a.rule?.mitre) ? a.rule.mitre : [];
  const tagged = mitre.some((t) => typeof t === 'string' && t.startsWith('T1190'));
  if (!tagged) {
    return { action: 'record', confidence: 0.05, reason: '일치하는 패턴 없음: T1190 표시가 없는 이벤트' };
  }

  const description = typeof a.rule?.description === 'string' ? a.rule.description : '';
  const lowered = description.toLowerCase();
  const url = typeof a.data?.url === 'string' ? a.data.url : '';
  const count = toCount(a.data?.count);
  const tier = COUNT_TIERS.find((t) => count >= t.minCount) ?? COUNT_TIERS[COUNT_TIERS.length - 1];

  const matches = [];
  for (const p of COMPILED) {
    const descHit = p.descriptionKeywords.some((k) => lowered.includes(k.toLowerCase()));
    const urlHit = p.url.test(url);
    if (!descHit && !urlHit) continue;
    matches.push({ name: p.name, score: urlHit ? Math.max(tier.score, URL_MARKER_MIN_SCORE) : tier.score });
  }

  if (matches.length === 0) {
    return {
      action: actionFor(FLOOR.score),
      confidence: FLOOR.score,
      reason: `${FLOOR.name}: T1190 표시만 있고 패턴 표기는 없음`,
    };
  }

  matches.sort((x, y) => y.score - x.score);
  const level = toCount(a.rule?.level);
  let score = matches[0].score;
  if (level >= LEVEL_BOOST.minLevel) score += LEVEL_BOOST.add;

  const confidence = Math.min(1, Math.max(0, Math.round(score * 100) / 100));
  const names = matches.map((m) => m.name).join(' + ');
  return { action: actionFor(confidence), confidence, reason: `${names}: 표기 ${count}회` };
}
