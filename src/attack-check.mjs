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

// 12단계: 심판은 제출 묶음을 격리 환경에서 다시 실행하고 실제로 나간 요청을 따로 기록합니다.
// 그 기록과 맞지 않는 결과를 적지 않도록, 배포 앱에 보내던 점검(로그인 없는·가짜 토큰·지어낸 서명 요청과
// 쓰기 요청)은 이제 보내지 않고 observed 를 not_run 으로 둡니다. 결과를 지어내지 않습니다.
// 같은 정상·금지 요청의 실제 결과는 npm run ops:recheck 와 탈환 작전실의 재확인 표에 남깁니다.
export const NOT_RUN = 'not_run';
export const WRITE_NOT_RUN = NOT_RUN;

// 3단계: 로그인 없이, 또는 가짜 토큰으로 자료 API를 부르는 점검입니다(12단계부터 보내지 않음).
// 정상 A 로그인 요청은 계정 비밀번호가 필요하므로 여기서 보내지 않습니다.
function checkLoginRequired() {
  return [
    { attackId: 'anonymous_notes_read', expected: '로그인 없이 /api/notes에서 메모를 확인',
      observed: NOT_RUN },
    { attackId: 'anonymous_notes_create', expected: '로그인 없이 /api/notes에 메모를 추가',
      observed: NOT_RUN },
    { attackId: 'forged_token_notes_read', expected: '검사를 통과하지 못하는 가짜 토큰으로 메모를 확인',
      observed: NOT_RUN },
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

// 5단계: 공개용 publishable(anon) 키로 원본 자료 API를 직접 불러 실제 응답을 기록합니다.
// 화면 코드에는 이제 키가 없으므로, bundle을 실행할 때 환경변수 SUPABASE_PUBLISHABLE_KEY로 받습니다.
// 키가 없으면 요청을 보내지 않고 미실행으로 남깁니다. 키와 메모 본문은 결과에 싣지 않습니다.
function originalUrl(config) {
  let url;
  try {
    url = new URL(config.originalApiUrl);
  } catch {
    throw new Error('aleph.config.json의 originalApiUrl을 확인해 주세요.');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
      || !url.hostname.endsWith('.supabase.co') || url.pathname !== '/rest/v1/notes') {
    throw new Error('originalApiUrl은 쿼리 없는 https://….supabase.co/rest/v1/notes 이어야 합니다.');
  }
  return url;
}

function publishableKey(env) {
  const key = env.SUPABASE_PUBLISHABLE_KEY?.trim();
  if (!key) return null;
  if (!/^sb_publishable_[A-Za-z0-9_-]{10,}$/u.test(key)) {
    throw new Error('SUPABASE_PUBLISHABLE_KEY에는 sb_publishable_로 시작하는 공개용 키만 넣어 주세요.');
  }
  return key;
}

const ORIGINAL_EXPECTED = 'anon 키로 원본 자료 API(/rest/v1/notes)에서 메모를 직접 확인';
const STEP_UP_NOT_SENT = {
  attackId: 'same_login_step_up_material_block',
  expected: '복합 이상 접속에서 재로그인 전 자료 차단과 새 요청 재판정',
  observed: '미실행. 계약에 같은 로그인 재로그인 시각이 없어 실제 자료 요청을 보내지 않음',
};

// 8단계: 강사 공지 구역을 로그인 없이 읽거나 고치는 점검입니다(12단계부터 보내지 않음).
// 학생 계정 토큰으로 공지를 고치는 시도는 계정 토큰이 필요해 보내지 않고 미실행으로 남깁니다.
function checkNoticeZone() {
  return [
    { attackId: 'anonymous_notices_read', expected: '로그인 없이 /api/notices에서 강사 공지를 확인',
      observed: NOT_RUN },
    { attackId: 'anonymous_notice_update', expected: '로그인 없이 본문에 role을 넣어 강사 공지를 PUT',
      observed: WRITE_NOT_RUN },
    { attackId: 'student_updates_notice', expected: '학생 시험 계정으로 강사 공지를 PUT /api/notices/:id',
      observed: '미실행. 학생 계정 토큰이 필요해 이 점검에서는 보내지 않음' },
  ];
}

// 9단계: 탐지 규칙(src/detect.mjs)은 npm run detect:test의 가상 사건으로만 연습합니다.
// 운영 반 엔진의 사건 전달과 접속 회수 집행은 연결되지 않아 배포 앱에 요청을 보내지 않습니다.
const DETECTION_NOT_SENT = {
  attackId: 'burst_read_revocation',
  expected: '같은 가명 사용자가 10분 안에 121건 이상 조회하면 회수 제안 뒤 다음 요청이 막힘',
  observed: '미실행. 운영 반 엔진의 사건 전달·회수 집행이 연결되지 않아 실제 요청을 보내지 않음',
};

// 10단계: 복원 경로 POST /api/restore 는 쓰기 요청이라 이 점검에서는 보내지 않습니다(not_run).
// B 본인이 메모를 변조·삭제한 뒤 복원하는 시험도 B 계정 토큰이 필요해 보내지 않습니다.
function checkRestoreRoute() {
  return [
    { attackId: 'anonymous_restore_call', expected: '로그인 없이 POST /api/restore 로 B 메모 복원을 실행',
      observed: WRITE_NOT_RUN },
    { attackId: 'b_note_restore_after_tamper', expected: 'B 메모를 변조·삭제한 뒤 B가 POST /api/restore 로 한 건만 복원',
      observed: '미실행. B 계정 토큰이 필요하고 실제 메모를 바꿔야 해 이 점검에서는 보내지 않음' },
  ];
}

// 11단계: 로그인 없이 기기를 "승인됨"으로 등록하려는 요청과, 서명 머리글을 지어낸 보호 요청 점검입니다(12단계부터 보내지 않음).
// 로그인한 계정에서 서명 없이·서명 뒤 경로나 본문을 바꿔 보내는 시험은 계정 토큰이 필요해 보내지 않습니다.
function checkDeviceApproval() {
  return [
    { attackId: 'anonymous_device_approval', expected: '로그인 없이 본문에 status:approved를 넣어 기기를 등록',
      observed: NOT_RUN },
    { attackId: 'forged_device_signature_read', expected: '지어낸 기기 서명 머리글만으로 /api/notes에서 메모를 확인',
      observed: NOT_RUN },
    { attackId: 'signed_request_tampered', expected: '로그인한 계정으로 서명 없이, 또는 서명 뒤 경로·본문을 바꿔 보호 요청',
      observed: '미실행. 계정 토큰과 승인된 기기가 필요해 이 점검에서는 보내지 않음' },
  ];
}

// 12단계: 탈환 작전실 요약 GET /api/ops 를 로그인 없이 부르는 점검입니다(보내지 않음).
function checkOpsClosed() {
  return { attackId: 'anonymous_ops_summary', expected: '로그인 없이 /api/ops에서 작전실 요약(기기·복원 기록)을 확인',
    observed: NOT_RUN };
}

async function checkOriginalApiClosed(config, env) {
  const url = originalUrl(config);
  const key = publishableKey(env);
  if (!key) {
    return { attackId: 'anon_original_api_read', expected: ORIGINAL_EXPECTED,
      observed: '미실행. SUPABASE_PUBLISHABLE_KEY 없이 실행해 이 점검에서는 보내지 않음' };
  }
  const probe = new URL(url);
  probe.searchParams.set('select', 'id');
  probe.searchParams.set('limit', '1');
  const response = await fetch(probe, {
    headers: { apikey: key, authorization: `Bearer ${key}`, accept: 'application/json' },
    redirect: 'error', signal: timeout(),
  });
  let leaked = false;
  try {
    const data = await response.json();
    leaked = response.ok && Array.isArray(data) && data.length > 0;
  } catch {
    leaked = false;
  }
  return {
    attackId: 'anon_original_api_read', expected: ORIGINAL_EXPECTED,
    observed: leaked ? `anon 키 직접 요청에서 자료가 반환됨 (HTTP ${response.status})`
      : `anon 키 직접 요청에서 자료가 반환되지 않음 (HTTP ${response.status})`,
  };
}

export async function runAttackChecks(config, env = process.env) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  const app = appUrl(config);
  if (config.step === 3) return checkLoginRequired(app);
  if (config.step >= 5) {
    const results = [...await checkLoginRequired(app), await checkOriginalApiClosed(config, env),
      ...OWNER_ATTACKS.map(([attackId, expected]) => ({ attackId, expected, observed: notSent }))];
    if (config.step >= 7) results.push(STEP_UP_NOT_SENT);
    if (config.step >= 8) results.push(...await checkNoticeZone(app));
    if (config.step >= 9) results.push(DETECTION_NOT_SENT);
    if (config.step >= 10) results.push(...checkRestoreRoute());
    if (config.step >= 11) results.push(...await checkDeviceApproval(app));
    if (config.step >= 12) results.push(await checkOpsClosed(app));
    return results;
  }
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
