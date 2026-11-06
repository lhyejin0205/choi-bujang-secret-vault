// 9단계에서 학생이 채우는 탐지 함수입니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
// 사건 계약은 docs/DETECT_EVENTS.md: { at, method, identity: { sub } } 세 값입니다.

// 만들기 1: 사건마다 at(시각)·method(요청 종류)·identity.sub(가명 사용자) 세 값만 읽습니다.
// 네트워크·기기·지역 같은 값은 사건에 없으므로 지어내거나 조건으로 쓰지 않습니다.
// 메모 내용·토큰·실명 등 다른 항목은 복사하지도 출력하지도 않습니다.
// 세 값 중 하나라도 형식이 맞지 않는 사건은 세지 않고 건너뜁니다.
export function readEvent(event) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) return null;
  const { at, method, identity } = event;
  if (typeof at !== 'string' || typeof method !== 'string') return null;
  const atMs = Date.parse(at);
  if (!Number.isFinite(atMs)) return null;
  if (identity === null || typeof identity !== 'object' || Array.isArray(identity)) return null;
  const { sub } = identity;
  if (typeof sub !== 'string' || sub.length === 0) return null;
  return Object.freeze({ atMs, method: method.toUpperCase(), sub });
}

export function readEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  return events.map(readEvent).filter(Boolean);
}

// 만들기 2: 규칙 burst_read.
// 같은 identity.sub의 GET 사건이 어느 10분 구간에서든 120건을 넘으면(121건 이상) 의심으로 봅니다.
// 정확히 120건은 의심이 아닙니다. 다른 사용자의 사건은 합치지 않고, 창 계산은 at 시각만 씁니다.
// 10분 구간은 [첫 사건 시각, 첫 사건 시각 + 10분) 입니다. 정확히 10분 떨어진 사건은 같은 구간이 아닙니다.
export const BURST_WINDOW_MS = 10 * 60 * 1000;
export const BURST_LIMIT = 120;

export function burstReadSubject(events) {
  const timesBySub = new Map();
  for (const { atMs, method, sub } of readEvents(events)) {
    if (method !== 'GET') continue;
    if (!timesBySub.has(sub)) timesBySub.set(sub, []);
    timesBySub.get(sub).push(atMs);
  }
  for (const [sub, times] of timesBySub) {
    times.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] >= BURST_WINDOW_MS) start += 1;
      if (end - start + 1 > BURST_LIMIT) return sub;
    }
  }
  return null;
}

// 만들기 3: 의심이면 정확히 세 키 {action, reasonCode, subject}만, 아니면 {action:'observe'}만 돌려줍니다.
// 기기 번호 같은 다른 키는 덧붙이지 않습니다. 이 함수는 회수를 "제안"만 하며,
// 회수 API를 부르거나 기기 권한을 바꾸지 않습니다. 집행은 운영 반 엔진의 몫입니다.
export function detect(events) {
  const subject = burstReadSubject(events);
  if (subject === null) return { action: 'observe' };
  return { action: 'propose_revocation', reasonCode: 'burst_read', subject };
}
