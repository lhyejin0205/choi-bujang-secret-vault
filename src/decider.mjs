// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  const registeredDevice = request.deviceRegistered === true
    && typeof request.subjectId === 'string' && request.subjectId.length > 0
    && typeof request.deviceId === 'string' && /^[0-9a-f]{16}$/u.test(request.deviceId);
  const readRoute = request.service === 'notes' && request.method === 'GET'
    && ((request.route === 'GET /notes' && request.path === '/notes')
      || (request.route === 'GET /notes/:id' && /^\/notes\/[^/]+$/u.test(request.path)));
  const allowed = registeredDevice && readRoute;
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: allowed ? 'allow' : 'deny',
    reasonCode: allowed ? 'approved' : 'device_not_registered',
    ruleIds: [RULE_IDS[0]],
  };
}
