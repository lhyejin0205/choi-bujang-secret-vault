// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 1 && config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (config.step === 1 && (typeof config.sampleMarker !== 'string' || !config.sampleMarker)) {
    throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  }
  const route = config.step === 1 ? '/data.json' : '/api/notes';
  const response = await fetch(new URL(route, app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = config.step === 1
        ? data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes) && data.notes.length > 0
        : Array.isArray(data) && data.length > 0
          && data.every(note => typeof note?.title === 'string' && typeof note?.content === 'string');
    } catch {
      visible = false;
    }
  }
  const expected = config.step === 1 ? '비로그인 화면에서 가상 메모를 확인' : '비로그인 API 요청은 메모를 반환하지 않아야 함';
  const observed = config.step === 1
    ? visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})`
    : visible ? '비로그인 API 요청에서 메모가 반환됨' : `비로그인 API 요청에서 메모가 반환되지 않음 (HTTP ${response.status})`;
  return [{ attackId: 'anonymous_note_read', expected, observed }];
}
