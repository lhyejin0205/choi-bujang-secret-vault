// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
function appUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

const timeout = () => AbortSignal.timeout(10000);

// 3단계: 로그인 없이, 또는 가짜 토큰으로 자료 API를 불러 실제 응답을 기록합니다.
// 정상 A 로그인 요청은 계정 비밀번호가 필요하므로 여기서 보내지 않습니다.
async function checkLoginRequired(app) {
  const probe = async (init) => {
    const response = await fetch(new URL('/api/notes', app), { redirect: 'error', signal: timeout(), ...init });
    let leaked = false;
    try {
      const data = await response.json();
      leaked = response.ok && (Array.isArray(data) ? data.length > 0 : typeof data?.id === 'string');
    } catch {
      leaked = false;
    }
    return { status: response.status, leaked };
  };
  const describe = ({ status, leaked }, what) => leaked
    ? `${what}에서 자료가 반환됨 (HTTP ${status})`
    : `${what}에서 자료가 반환되지 않음 (HTTP ${status})`;
  const anonymousRead = await probe({ method: 'GET' });
  const anonymousCreate = await probe({
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'attack-check', body: 'attack-check' }),
  });
  // 서명이 없는 가짜 토큰입니다. 세 조각 모양만 갖추고 검사를 통과할 수 없습니다.
  const forgedToken = ['aaaaaaaaaa', 'bbbbbbbbbb', 'cccccccccc'].join('.');
  const forgedRead = await probe({
    method: 'GET', headers: { authorization: `Bearer ${forgedToken}` },
  });
  return [
    { attackId: 'anonymous_notes_read', expected: '로그인 없이 /api/notes에서 메모를 확인',
      observed: describe(anonymousRead, '로그인 없는 목록 요청') },
    { attackId: 'anonymous_notes_create', expected: '로그인 없이 /api/notes에 메모를 추가',
      observed: anonymousCreate.leaked || (anonymousCreate.status >= 200 && anonymousCreate.status < 300)
        ? `로그인 없는 추가 요청이 받아들여짐 (HTTP ${anonymousCreate.status})`
        : `로그인 없는 추가 요청이 거부됨 (HTTP ${anonymousCreate.status})` },
    { attackId: 'forged_token_notes_read', expected: '검사를 통과하지 못하는 가짜 토큰으로 메모를 확인',
      observed: describe(forgedRead, '가짜 토큰 목록 요청') },
    { attackId: 'login_a_notes_read', expected: '정상 A 로그인 뒤에는 메모가 보임',
      observed: '미실행. 계정 비밀번호가 필요해 이 점검에서는 보내지 않음. 심판이 확인함' },
  ];
}

// 4단계: B가 A의 메모를 읽기·수정·삭제·주인 바꾸기 하는 시도입니다.
// 두 계정의 로그인 토큰이 필요해 이 자기 점검에서는 보내지 않고 미실행으로 남깁니다.
const OWNER_ATTACKS = [
  ['b_reads_a_note', 'B 로그인으로 A 메모 id를 GET /api/notes/:id'],
  ['b_updates_a_note', 'B 로그인으로 A 메모 id를 PUT /api/notes/:id'],
  ['b_deletes_a_note', 'B 로그인으로 A 메모 id를 DELETE /api/notes/:id'],
  ['a_changes_owner', 'A 로그인으로 자기 메모의 owner_id를 B로 바꾸는 PUT'],
];
const notSent = '미실행. A·B 계정 토큰이 필요해 이 점검에서는 보내지 않음';

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  const app = appUrl(config);
  if (config.step === 3) return checkLoginRequired(app);
  if (config.step === 4) {
    return [...await checkLoginRequired(app),
      ...OWNER_ATTACKS.map(([attackId, expected]) => ({ attackId, expected, observed: notSent }))];
  }
  if (config.step === 1 && (typeof config.sampleMarker !== 'string' || !config.sampleMarker)) {
    throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  }
  const route = config.step === 1 ? '/data.json' : '/api/notes';
  const response = await fetch(new URL(route, app), {
    redirect: 'error', signal: timeout(),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = config.step === 1
        ? data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes) && data.notes.length > 0
        : Array.isArray(data) && data.length > 0
          && data.every(note => typeof note?.title === 'string' && typeof note?.content === 'string');
    } catch {
      visible = false;
    }
  }
  const expected = config.step === 1 ? '비로그인 화면에서 가상 메모를 확인' : '비로그인 API 요청은 메모를 반환하지 않아야 함';
  const observed = config.step === 1
    ? visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})`
    : visible ? '비로그인 API 요청에서 메모가 반환됨' : `비로그인 API 요청에서 메모가 반환되지 않음 (HTTP ${response.status})`;
  return [{ attackId: 'anonymous_note_read', expected, observed }];
}
