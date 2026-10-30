// 심판이 인터넷 없이 이 파일 하나만 불러옵니다. import 도 파일 읽기·쓰기도 바깥 호출도 없고,
// 경보 하나를 받아 이 파일 안에서 혼자 계산해 답합니다. 파일 쓰기·판정기 연결은 respond.mjs 가 합니다.

// ---- patterns.json 에서 옮겨 적은 상수 (고치면 patterns.json 도 같이 맞추세요) ----
const THRESHOLDS = Object.freeze({ block: 0.85, alert: 0.5 });
const LEVEL_BOOST = Object.freeze({ minLevel: 10, add: 0.03 });
const PATTERNS = Object.freeze({
  'repeated-login-failure': {
    condition: '경보가 T1110 으로 분류되고, 같은 주소에서 짧은 시간에 로그인 실패가 연속으로 쌓였다. 실패 건수(count)가 3건 이상이면 의심, 10건 이상이면 뚜렷, 30건 이상이면 매우 뚜렷하다.',
    evidence: 'MITRE ATT&CK T1110.001 Password Guessing: 공격자가 비밀번호를 반복해 추측하므로 같은 주소·계정에서 로그인 실패가 짧은 시간에 몰린다.',
    params: {
      failureTiers: [
        { minCount: 30, score: 0.95 },
        { minCount: 10, score: 0.88 },
        { minCount: 5, score: 0.65 },
        { minCount: 3, score: 0.55 },
      ],
      successAfterFailurePenalty: 0.05,
    },
  },
  'password-spraying': {
    condition: '경보가 T1110 으로 분류되고, 같은 비밀번호를 여러 계정에 연속으로 넣었다. 계정이 5개 이상이면 뚜렷, 2개 이상이면 의심이고, 계정 수를 알 수 없으면 약하게 본다.',
    evidence: 'MITRE ATT&CK T1110.003 Password Spraying: 계정 잠금을 피하려고 흔한 비밀번호 하나를 여러 계정에 돌려 가며 대입한다.',
    params: {
      accountTiers: [
        { minAccounts: 5, score: 0.9 },
        { minAccounts: 2, score: 0.7 },
      ],
      unknownAccountsScore: 0.6,
      successAfterFailurePenalty: 0.05,
    },
  },
});
// -------------------------------------------------------------------------------

function toCount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function countAccounts(alert, description) {
  const list = alert.data?.accounts;
  const items = Array.isArray(list) ? list : typeof list === 'string' ? list.split(',') : [];
  const names = new Set(items.map((s) => String(s).trim()).filter(Boolean));
  if (names.size > 0) return names.size;
  const m = /계정\s*(\d+)\s*개/.exec(description);
  return m ? Number(m[1]) : null;
}

function matchRepeatedFailure(alert, description) {
  if (!/실패/.test(description)) return null;
  const count = toCount(alert.data?.count);
  const tier = PATTERNS['repeated-login-failure'].params.failureTiers.find((t) => count >= t.minCount);
  if (!tier) return null;
  return { name: 'repeated-login-failure', score: tier.score, detail: `로그인 실패 ${count}건` };
}

function matchPasswordSpraying(alert, description) {
  if (!/같은 비밀번호/.test(description)) return null;
  const { accountTiers, unknownAccountsScore } = PATTERNS['password-spraying'].params;
  const accounts = countAccounts(alert, description);
  if (accounts === null) {
    return { name: 'password-spraying', score: unknownAccountsScore, detail: '여러 계정에 같은 비밀번호(계정 수 미상)' };
  }
  const tier = accountTiers.find((t) => accounts >= t.minAccounts);
  if (!tier) return null;
  return { name: 'password-spraying', score: tier.score, detail: `계정 ${accounts}개에 같은 비밀번호` };
}

function actionFor(confidence) {
  if (confidence >= THRESHOLDS.block) return 'block';
  if (confidence >= THRESHOLDS.alert) return 'alert';
  return 'record';
}

export function decide(alert) {
  const a = alert && typeof alert === 'object' ? alert : {};
  const mitre = Array.isArray(a.rule?.mitre) ? a.rule.mitre : [];
  const tagged = mitre.some((t) => typeof t === 'string' && t.startsWith('T1110'));
  if (!tagged) {
    return { action: 'record', confidence: 0.05, reason: '일치하는 패턴 없음: T1110 표시가 없는 이벤트' };
  }

  const description = typeof a.rule?.description === 'string' ? a.rule.description : '';
  const matches = [matchRepeatedFailure(a, description), matchPasswordSpraying(a, description)].filter(Boolean);
  if (matches.length === 0) {
    return { action: 'record', confidence: 0.2, reason: '일치하는 패턴 없음: T1110 이지만 실패 건수·계정 수가 기준에 못 미침' };
  }

  const best = matches.reduce((x, y) => (y.score > x.score ? y : x));
  const level = toCount(a.rule?.level);
  const successAfter = /성공/.test(description) && !/성공(은|이)\s*없/.test(description);
  let score = best.score;
  if (level >= LEVEL_BOOST.minLevel) score += LEVEL_BOOST.add;
  if (successAfter) score -= PATTERNS[best.name].params.successAfterFailurePenalty;

  const confidence = Math.min(1, Math.max(0, Math.round(score * 100) / 100));
  return { action: actionFor(confidence), confidence, reason: `${best.name}: ${best.detail}` };
}
