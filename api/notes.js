import config from '../aleph.config.json' with { type: 'json' };
import { handleNotesRequest } from '../src/notes-handler.mjs';
import { handleNoticesRequest } from '../src/notices-handler.mjs';
import { handleRestoreRequest } from '../src/restore-handler.mjs';
import { handleDeviceRequest, verifyDeviceRequest } from '../src/device-handler.mjs';
import { handleLogin, handleLogout } from '../src/session-handler.mjs';

// 로그인 검사는 틀이 준 src/verify-login.mjs를 그대로 씁니다.
// 서버 런타임에서 한 번만 만들고, 만들지 못하면 다음 요청에서 다시 시도합니다.
let verifierPromise;
function getVerifier() {
  verifierPromise ??= import('../src/verify-login.mjs')
    .then(({ createLoginVerifier }) => createLoginVerifier({
      config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    }))
    .catch((error) => { verifierPromise = undefined; throw error; });
  return verifierPromise;
}

async function verifyLogin(authorization) {
  const verify = await getVerifier();
  return verify(authorization);
}

// 8단계: 자료 API가 거부한 요청의 짧은 사유를 Vercel 함수 기록에 남깁니다(사용자 번호·토큰·본문 없음).
const logDenial = (entry) => console.warn(JSON.stringify(entry));

// 11단계: 보호 요청(메모·공지)의 서명 검증에 쓸 "실제 경로"를 서버가 라우팅으로 다시 만듭니다.
// 요청이 주장하는 경로가 아니라 이 값으로 검증하므로, 서명한 뒤 경로를 바꾸면 거부됩니다.
function protectedPath(query = {}) {
  const base = query.zone === 'notices' ? '/api/notices' : '/api/notes';
  return Object.hasOwn(query, 'id') ? `${base}/${typeof query.id === 'string' ? query.id : ''}` : base;
}
const deviceCheck = request => user => verifyDeviceRequest(request, user, { path: protectedPath(request.query) });

// 시작 틀은 서버 함수 파일을 늘리지 않으므로, 로그인·로그아웃도 이 함수 하나가 받습니다.
// vercel.json이 /api/login → /api/notes?session=login, /api/logout → /api/notes?session=logout 으로 넘겨 줍니다.
export default function handler(request, response) {
  const session = request.query?.session;
  if (session === 'login') return handleLogin(request, response);
  if (session === 'logout') return handleLogout(request, response);
  // 8단계: /api/notices, /api/notices/:id → /api/notes?zone=notices(&id=) 로 넘어온 강사 공지 구역
  // 10단계: /api/restore → /api/notes?zone=restore 로 넘어온 B 메모 한 건 복원 경로
  if (request.query?.zone === 'restore') {
    return handleRestoreRequest(request, response, { verifyLogin, log: logDenial });
  }
  // 11단계: /api/devices → /api/notes?zone=devices 로 넘어온 기기 승인 대기 등록·상태 확인
  if (request.query?.zone === 'devices') {
    return handleDeviceRequest(request, response, { verifyLogin, log: logDenial });
  }
  if (request.query?.zone === 'notices') {
    return handleNoticesRequest(request, response, { verifyLogin, requireDevice: deviceCheck(request), log: logDenial });
  }
  return handleNotesRequest(request, response, { verifyLogin, requireDevice: deviceCheck(request), log: logDenial });
}
