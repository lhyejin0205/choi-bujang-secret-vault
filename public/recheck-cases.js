// 12단계: 1~11단계 정상·금지 요청 재확인 목록. 명령(scripts/recheck.mjs)과 작전실 화면이 같은 목록을 씁니다.
// 각 줄은 실제로 보낼 요청과 기대 결과만 정합니다. 결과는 실제 응답으로만 채우고, 보내지 않은 줄은 "미실행"입니다.
//   auth: none(로그인 없음) | forged(가짜 토큰) | session(로그인 + 승인 기기, 화면에서만 실행)
//   sign: signed(승인 기기 서명) | none | wrong-path(다른 경로에 서명한 머리글로 보냄) | forged(지어낸 서명 머리글)
//   engine: 운영 엔진이나 계정 비밀값이 필요해 이 절차로는 보내지 않는 줄
// 이 목록은 심판의 41종 시험이 아닙니다. 심판 결과는 상황실 판정으로만 확인합니다.
export const OTHER_NOTE_ID = '7cd005ec-cbad-47d4-9100-3a48e0f04269';

export const RECHECK_CASES = Object.freeze([
  { id: 's1-page', stage: '1·2', kind: '정상', name: '첫 화면 열기', method: 'GET', path: '/', auth: 'none', expect: [200] },
  { id: 's1-datajson', stage: '1·2', kind: '금지', name: '공개 data.json', method: 'GET', path: '/data.json', auth: 'none', expect: [404] },
  { id: 's2-anon-list', stage: '2·3', kind: '금지', name: '로그인 없이 메모 목록', method: 'GET', path: '/api/notes', auth: 'none', expect: [401] },
  { id: 's3-anon-create', stage: '3', kind: '금지', name: '로그인 없이 메모 추가', method: 'POST', path: '/api/notes', auth: 'none',
    body: { title: 'recheck', body: 'recheck' }, expect: [401] },
  { id: 's3-forged-token', stage: '3', kind: '금지', name: '가짜 토큰으로 메모 목록', method: 'GET', path: '/api/notes', auth: 'forged', expect: [401] },
  { id: 's3-own-list', stage: '3·4', kind: '정상', name: '내 메모 목록', method: 'GET', path: '/api/notes', auth: 'session', sign: 'signed', expect: [200] },
  { id: 's4-other-note', stage: '4', kind: '금지', name: '다른 계정(B) 메모 한 건 읽기', method: 'GET', path: `/api/notes/${OTHER_NOTE_ID}`,
    auth: 'session', sign: 'signed', expect: [404], skipIfOwn: OTHER_NOTE_ID },
  { id: 's4-b-attacks', stage: '4', kind: '금지', name: 'B 토큰으로 A 메모 수정·삭제·주인 바꾸기', engine: 'B 계정 토큰이 필요' },
  { id: 's5-anon-key', stage: '5', kind: '금지', name: 'publishable 키로 원본 API 직접 읽기', engine: '공개용 키를 실행할 때 넘겨야 함(npm run bundle)' },
  { id: 's6-decider', stage: '6·7', kind: '정상·금지', name: '등록 기기·이상 접속 판정', engine: '운영 SDP 엔진의 판정 기록이 이 서버에 오지 않음(가상 연습 npm run decider:test 만 실행)' },
  { id: 's8-anon-notices', stage: '8', kind: '금지', name: '로그인 없이 공지 목록', method: 'GET', path: '/api/notices', auth: 'none', expect: [401] },
  { id: 's8-anon-notice-put', stage: '8', kind: '금지', name: '로그인 없이 공지 수정', method: 'PUT', path: '/api/notices/n-001', auth: 'none',
    body: { title: 'recheck', body: 'recheck', role: 'instructor' }, expect: [401] },
  { id: 's8-notices', stage: '8', kind: '정상', name: '공지 목록 읽기', method: 'GET', path: '/api/notices', auth: 'session', sign: 'signed', expect: [200] },
  { id: 's8-student-notice-put', stage: '8', kind: '금지', name: '학생 계정으로 공지 수정(본문 role 포함)', method: 'PUT', path: '/api/notices/n-001',
    auth: 'session', sign: 'signed', body: { title: 'recheck', body: 'recheck', role: 'instructor' }, expect: [403] },
  { id: 's9-detect', stage: '9', kind: '금지', name: '조회 폭주 회수', engine: '운영 반 엔진의 사건 전달·회수 집행이 연결되지 않음(가상 연습 npm run detect:test 만 실행)' },
  { id: 's10-anon-restore', stage: '10', kind: '금지', name: '로그인 없이 복원 경로 호출', method: 'POST', path: '/api/restore', auth: 'none', body: {}, expect: [401] },
  { id: 's10-owner-restore', stage: '10', kind: '정상', name: 'B 본인 복원', engine: 'B 계정 토큰이 필요하고 실제 메모를 바꿔야 함' },
  { id: 's11-anon-device', stage: '11', kind: '금지', name: '로그인 없이 기기를 approved로 등록', method: 'POST', path: '/api/devices', auth: 'none',
    body: { publicKey: { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) }, status: 'approved' }, expect: [401] },
  { id: 's11-forged-signature', stage: '11', kind: '금지', name: '지어낸 서명 머리글만으로 메모 목록', method: 'GET', path: '/api/notes', auth: 'none', sign: 'forged', expect: [401] },
  { id: 's11-unsigned', stage: '11', kind: '금지', name: '로그인했지만 서명 없이 메모 목록', method: 'GET', path: '/api/notes', auth: 'session', sign: 'none', expect: [403] },
  { id: 's11-wrong-path', stage: '11', kind: '금지', name: '목록 경로에 서명하고 공지 경로로 보냄', method: 'GET', path: '/api/notices', signPath: '/api/notes',
    auth: 'session', sign: 'wrong-path', expect: [403] },
  { id: 's12-ops', stage: '12', kind: '정상', name: '탈환 작전실 요약', method: 'GET', path: '/api/ops', auth: 'session', sign: 'signed', expect: [200] },
]);

export function judgeResult(testCase, status) {
  return testCase.expect.includes(status) ? '일치' : '불일치';
}

export function notRunRow(testCase, reason) {
  return { id: testCase.id, stage: testCase.stage, kind: testCase.kind, request: testCase.method ? `${testCase.method} ${testCase.path}` : testCase.name,
    name: testCase.name, expected: testCase.expect ? testCase.expect.join('/') : '-', actual: '미실행', verdict: '미실행',
    clientRequestId: null, serverRequestId: null, checkedAt: null, note: reason };
}
