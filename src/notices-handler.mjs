import { NOTICE_ID, markResource, markResourceKind } from './resources.mjs';

// 8단계: 강사 공지 구역. 메모(note:*)와 다른 자원 ID(notice:*)를 씁니다.
// 공지는 실습용 가상 문구이며, 로그인한 사용자가 읽기만 할 수 있습니다.
// 공지 쓰기는 검증된 로그인 사용자를 서버에 저장된 강사 목록(환경변수 INSTRUCTOR_USER_IDS)과 대조합니다.
// 화면 메뉴나 요청 본문의 role·isInstructor 같은 값은 보지 않습니다.
// 강사라도 공지 저장소가 아직 없어 수정은 받지 않습니다(501).
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

// 서버 설정에 저장된 강사 사용자 번호 목록. 쉼표로 구분된 UUID만 받습니다.
export function instructorIds(env) {
  const raw = typeof env?.INSTRUCTOR_USER_IDS === 'string' ? env.INSTRUCTOR_USER_IDS : '';
  return new Set(raw.split(',').map(value => value.trim().toLowerCase()).filter(value => UUID.test(value)));
}

export const NOTICES = Object.freeze([
  Object.freeze({ id: 'n-001', title: '[가상 공지] 3차 방어전 일정', body: '실습용 가상 공지입니다. 단계마다 저장점을 남겨 주세요.' }),
  Object.freeze({ id: 'n-002', title: '[가상 공지] 자료실 이용 안내', body: '실습용 가상 공지입니다. 메모는 본인만 볼 수 있습니다.' }),
]);

function sendJson(response, status, body) {
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('cache-control', 'no-store');
  return response.status(status).json(body);
}

function routeId(request) {
  const query = request.query;
  if (!query || typeof query !== 'object' || !Object.hasOwn(query, 'id')) return undefined;
  return typeof query.id === 'string' ? query.id : '';
}

export async function handleNoticesRequest(request, response, options = {}) {
  const { verifyLogin, env = process.env, log = () => {} } = options;
  const id = routeId(request);
  markResourceKind(response, 'notice');
  const deny = (status, error, reason) => {
    log({ event: 'api_denied', zone: 'notice', method: request.method, reason });
    return sendJson(response, status, { error });
  };
  if (request.method !== 'GET' && !WRITE_METHODS.includes(request.method)) {
    response.setHeader('allow', 'GET');
    return deny(405, 'METHOD_NOT_ALLOWED', 'method');
  }

  let user;
  try {
    if (typeof verifyLogin !== 'function') throw new TypeError('missing_verifier');
    user = await verifyLogin(request.headers?.authorization);
  } catch {
    return sendJson(response, 503, { error: 'AUTH_NOT_CONFIGURED' });
  }
  if (!user || typeof user.userId !== 'string' || !UUID.test(user.userId)) {
    response.setHeader('www-authenticate', 'Bearer');
    return deny(401, 'UNAUTHORIZED', 'no_valid_login');
  }

  if (WRITE_METHODS.includes(request.method)) {
    // 검증된 Supabase 로그인 사용자이면서 저장된 강사 목록에 있어야 합니다. 본문의 role은 쓰지 않습니다.
    const instructor = user.kind === 'student' && instructorIds(env).has(user.userId.toLowerCase());
    if (!instructor) return deny(403, 'NOT_INSTRUCTOR', 'not_instructor');
    response.setHeader('allow', 'GET');
    return deny(501, 'NOTICE_EDIT_NOT_AVAILABLE', 'notice_store_missing');
  }

  if (id === undefined) {
    markResource(response, 'notice');
    return sendJson(response, 200, NOTICES.map(({ id: noticeId, title }) => ({ id: noticeId, title })));
  }
  const notice = NOTICE_ID.test(id) ? NOTICES.find(item => item.id === id) : undefined;
  if (!notice) return deny(404, 'NOT_FOUND', 'missing');
  markResource(response, 'notice', id);
  return sendJson(response, 200, { id: notice.id, title: notice.title, body: notice.body });
}
