import { createHash, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Local practice requests use the engine's public input shape. The judge sends and times its own events.
const request = (signals, recentEvents) => ({
  schema: 'aleph.decision.v1', requestId: randomUUID(), classId: 'class_fixture',
  projectId: 'project_fixture', subjectId: 'learner_fixture', deviceId: 'a'.repeat(16),
  service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
  queryLength: 0, querySha256: createHash('sha256').update('').digest('hex'),
  at: new Date().toISOString(), policyRevision: 1, deviceRegistered: true,
  stepUp: { verified: false, authAgeSeconds: null }, recentEvents, signals,
});
export function fixtureRequests() {
  return {
    normal: request({ source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 }, []),
    regionOnly: request({ source: 'judge_fixture', region: 'foreign', network: 'usual', hour: 14 }, []),
    suspicious: request({ source: 'judge_fixture', region: 'foreign',
      network: 'first_seen', hour: 3 },
    [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }]),
    boundaryHour: request({ source: 'judge_fixture', region: 'foreign',
      network: 'first_seen', hour: 6 },
    [{ kind: 'bulk_read', ageSeconds: 60, count: 20 }]),
    unverifiedSource: request({ source: 'client_header', region: 'local',
      network: 'usual', hour: 14 }, []),
    forgedHeader: { ...request({ source: 'judge_fixture', region: 'local',
      network: 'usual', hour: 14 }, []), headers: { 'x-forwarded-for': 'client-supplied' } },
  };
}
const check = (input, output) => output && typeof output === 'object'
  && Object.keys(output).sort().join(',') === 'decision,reasonCode,requestId,ruleIds,schema'
  && output.schema === 'aleph.decision.v1' && output.requestId === input.requestId
  && ['allow', 'deny', 'step_up'].includes(output.decision)
  && typeof output.reasonCode === 'string' && Array.isArray(output.ruleIds);

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { normal, regionOnly, suspicious, boundaryHour, unverifiedSource, forgedHeader } = fixtureRequests();
    const { decide } = await import('../src/decider.mjs');
    if (typeof decide !== 'function') throw new Error('src/decider.mjs에서 decide 함수를 내보내야 합니다.');
    const ordinary = await decide(normal);
    const regional = await decide(regionOnly);
    const unusual = await decide(suspicious);
    const boundary = await decide(boundaryHour);
    const unverified = await decide(unverifiedSource);
    const spoofed = await decide(forgedHeader);
    if (![ [normal, ordinary], [regionOnly, regional], [suspicious, unusual],
      [boundaryHour, boundary],
      [unverifiedSource, unverified], [forgedHeader, spoofed] ]
      .every(([input, output]) => check(input, output))) {
      throw new Error('판정기 응답 형식이 맞지 않습니다.');
    }
    process.stdout.write(`정상 사건: ${ordinary.decision}\n지역만 다른 사건: ${regional.decision}`
      + `\n복합 이상 사건: ${unusual.decision}\n6시 복합 신호: ${boundary.decision}`
      + `\n불명확한 출처: ${unverified.decision}`
      + `\n위조 헤더: ${spoofed.decision}\n`);
    if (ordinary.decision === unusual.decision) {
      throw new Error('정상 사건과 복합 이상 사건의 판정은 서로 달라야 합니다.');
    }
    if (ordinary.decision !== 'allow' || regional.decision !== 'allow'
        || boundary.decision !== 'allow'
        || unusual.decision !== 'step_up' || unverified.decision !== 'step_up'
        || spoofed.decision !== 'step_up') {
      throw new Error('정상·지역 단독·6시 사건은 allow, 복합 이상·불명확 출처·위조 헤더는 step_up이어야 합니다.');
    }
  } catch (error) {
    process.stderr.write(`가상 사건 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
