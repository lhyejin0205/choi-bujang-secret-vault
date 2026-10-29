import config from '../aleph.config.json' with { type: 'json' };
import { handleNotesRequest } from '../src/notes-handler.mjs';
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

// 시작 틀은 서버 함수 파일을 늘리지 않으므로, 로그인·로그아웃도 이 함수 하나가 받습니다.
// vercel.json이 /api/login → /api/notes?session=login, /api/logout → /api/notes?session=logout 으로 넘겨 줍니다.
export default function handler(request, response) {
  const session = request.query?.session;
  if (session === 'login') return handleLogin(request, response);
  if (session === 'logout') return handleLogout(request, response);
  return handleNotesRequest(request, response, { verifyLogin });
}
