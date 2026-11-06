// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'connection_context_verified',
  'unusual_access_pattern',
  'step_up_required',
  'resource_zone',
]);

// 8단계: 자원 구역별로 허용하는 서비스·동작·정확한 경로 모양입니다. 여기 없는 요청은 모두 거부합니다.
// - 메모(notes): 자료 ID 하나를 고르는 읽기만. ID 없는 전체 목록(/notes)은 거부합니다.
// - 반 공지(notices): 읽기(GET)만. 쓰기는 누구에게나 거부하고, 강사 수정은 서버의 관리 경로가 맡습니다.
// - 강사 자료 등 그 밖의 서비스·경로: 판정기에서 모두 거부합니다.
// ID 형식은 좁히지 않고(심판 요청은 UUID가 아닐 수 있음) 경로 한 칸만 봅니다.
// 메모 주인 비교는 자료 API가 맡으며, 쿼리로 기능을 고르는 요청은 받지 않습니다.
const ZONE_ROUTES = Object.freeze([
  Object.freeze({ service: 'notes', route: 'GET /notes/:id', path: /^\/notes\/[^/?#]+$/u }),
  Object.freeze({ service: 'notices', route: 'GET /notices', path: /^\/notices$/u }),
  Object.freeze({ service: 'notices', route: 'GET /notices/:id', path: /^\/notices\/[^/?#]+$/u }),
]);

function allowedZoneRoute(request) {
  return request?.method === 'GET' && request.queryLength === 0
    && typeof request.path === 'string'
    && ZONE_ROUTES.some(zone => zone.service === request.service
      && zone.route === request.route && zone.path.test(request.path));
}

function denyResponse(request, ruleId) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: 'deny',
    reasonCode: 'device_not_registered',
    ruleIds: [ruleId],
  };
}

const SIGNAL_KEYS = ['hour', 'network', 'region', 'source'];
const EVENT_KEYS = ['ageSeconds', 'count', 'kind'];
const REQUEST_KEYS = [
  'at', 'classId', 'deviceId', 'deviceRegistered', 'method', 'path', 'policyRevision',
  'projectId', 'queryLength', 'querySha256', 'recentEvents', 'requestId', 'route',
  'schema', 'service', 'signals', 'stepUp', 'subjectId',
];

function hasExactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function hasCompleteFixtureContext(request) {
  const signals = request?.signals;
  const events = request?.recentEvents;
  if (!hasExactKeys(request, REQUEST_KEYS)
      || !hasExactKeys(signals, SIGNAL_KEYS) || signals.source !== 'judge_fixture'
      || typeof signals.region !== 'string' || !signals.region.trim()
      || signals.region === 'unknown'
      || typeof signals.network !== 'string' || !signals.network.trim()
      || signals.network === 'unknown'
      || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23
      || !Array.isArray(events) || events.length > 12) {
    return false;
  }
  return events.every(event => hasExactKeys(event, EVENT_KEYS)
    && typeof event.kind === 'string' && event.kind.trim().length > 0
    && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0
    && Number.isSafeInteger(event.count) && event.count > 0);
}

function unusualAccessPattern(request) {
  const { hour, network } = request.signals;
  const unusualHour = hour < 6 || hour >= 22;
  // 시작 틀 가상 사건의 'unusual'·'risk_signal'도 같은 뜻으로 받습니다.
  const unfamiliarNetwork = network === 'first_seen' || network === 'unusual';
  const suddenBulkRead = request.recentEvents.some(event =>
    (event.kind === 'bulk_read' || event.kind === 'risk_signal')
    && event.ageSeconds <= 300 && event.count >= 20);
  return unusualHour && unfamiliarNetwork && suddenBulkRead;
}

// 계약: stepUp은 {verified, authAgeSeconds}. 확인 완료이고 0~900초 안일 때만 재확인으로 인정합니다.
function verifiedStepUp(request) {
  const stepUp = request.stepUp;
  return hasExactKeys(stepUp, ['authAgeSeconds', 'verified']) && stepUp.verified === true
    && Number.isFinite(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= 900;
}

function stepUpResponse(request, ruleId) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'step_up',
    reasonCode: 'step_up_required',
    ruleIds: [RULE_IDS[3], ruleId],
  };
}

export async function decide(request) {
  const registeredDevice = request?.deviceRegistered === true
    && typeof request.subjectId === 'string' && request.subjectId.length > 0
    && typeof request.deviceId === 'string' && /^[0-9a-f]{16}$/u.test(request.deviceId);
  if (!registeredDevice) return denyResponse(request, RULE_IDS[0]);
  if (!allowedZoneRoute(request)) return denyResponse(request, RULE_IDS[4]);

  if (!hasCompleteFixtureContext(request)) {
    return stepUpResponse(request, RULE_IDS[1]);
  }

  if (unusualAccessPattern(request) && !verifiedStepUp(request)) {
    return stepUpResponse(request, RULE_IDS[2]);
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [RULE_IDS[0], RULE_IDS[1]],
  };
}
