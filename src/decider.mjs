// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'connection_context_verified',
  'unusual_access_pattern',
  'step_up_required',
]);

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
  const unusualHour = hour >= 3 && hour <= 5;
  const suddenBulkRead = request.recentEvents.some(event => event.kind === 'bulk_read'
    && event.ageSeconds <= 300 && event.count >= 20);
  return unusualHour && network === 'first_seen' && suddenBulkRead;
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
  const readRoute = request?.service === 'notes' && request.method === 'GET'
    && ((request.route === 'GET /notes' && request.path === '/notes')
      || (request.route === 'GET /notes/:id' && /^\/notes\/[^/]+$/u.test(request.path)));
  if (!registeredDevice || !readRoute) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  if (!hasCompleteFixtureContext(request)) {
    return stepUpResponse(request, RULE_IDS[1]);
  }

  if (unusualAccessPattern(request)) {
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
