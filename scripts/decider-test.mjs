import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(request, response, ruleIds) {
  return response && typeof response === 'object' && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === RESPONSE_KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && typeof response.reasonCode === 'string'
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(id => ruleIds.includes(id));
}

// Local practice only. The class engine and the server judge validate live requests separately.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !Array.isArray(ruleIds)
      || !ruleIds.includes('device_registered')) {
    throw new Error('6단계 device_registered 규칙을 먼저 구현하고 RULE_IDS에 적어 주세요.');
  }
  const { normal, regionOnly, suspicious, unverifiedSource, forgedHeader } = fixtureRequests();
  const missingRegistration = { ...normal, requestId: randomUUID() };
  delete missingRegistration.deviceRegistered;
  const missingSignals = { ...normal, requestId: randomUUID() };
  delete missingSignals.signals;
  const checks = [
    { name: '등록 기기의 정상 요청', request: normal, decision: 'allow', reasonCode: 'approved' },
    { name: '지역만 다른 가상 요청', request: regionOnly, decision: 'allow', reasonCode: 'approved' },
    { name: '미등록 기기의 가상 요청', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: false }, decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '등록 여부가 없는 가상 요청', request: missingRegistration,
      decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '접속 정보가 없는 가상 요청', request: missingSignals,
      decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '위조 출처 신호가 있는 가상 요청', request: forgedHeader,
      decision: 'step_up', reasonCode: 'step_up_required' },
    { name: '출처가 불명확한 가상 요청', request: unverifiedSource,
      decision: 'step_up', reasonCode: 'step_up_required' },
  ];
  if (ruleIds.includes('unusual_access_pattern')) {
    checks.push(
      { name: '복합 이상 접속', request: suspicious, decision: 'step_up',
        reasonCode: 'step_up_required' },
      { name: '다시 확인한 복합 이상 접속', request: { ...suspicious,
        requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'step_up', reasonCode: 'step_up_required' },
    );
  }
  const results = [];
  for (const item of checks) {
    const response = await decide(item.request);
    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && (!item.reasonCode || response.reasonCode === item.reasonCode);
    results.push({ name: item.name, passed: valid,
      decision: response?.decision, reasonCode: response?.reasonCode });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) {
      process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}`
        + ` · ${item.decision ?? '응답 없음'} · ${item.reasonCode ?? '이유 없음'}\n`);
    }
    process.stdout.write('이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
