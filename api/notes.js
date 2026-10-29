import config from '../aleph.config.json' with { type: 'json' };
import { handleNotesRequest } from '../src/notes-handler.mjs';

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

export default function handler(request, response) {
  return handleNotesRequest(request, response, { verifyLogin });
}
