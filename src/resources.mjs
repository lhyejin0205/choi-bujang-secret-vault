// 8단계: 자료실의 자원을 구역별로 나눠 요청마다 서버가 구별할 수 있는 자원 ID를 붙입니다.
// - 메모:      note:<메모 UUID>,   목록은 note:list
// - 강사 공지: notice:<공지 ID>,   목록은 notice:list
// 자원 ID는 응답 머리글 x-resource-kind, x-resource-id로 남기며 응답 본문 모양은 바꾸지 않습니다.
// 형식 검사를 통과한 ID만 머리글에 넣어, 요청에 들어온 임의 문자열을 그대로 되돌려 쓰지 않습니다.
export const RESOURCE_KINDS = Object.freeze(['note', 'notice']);
export const NOTICE_ID = /^n-[0-9]{3}$/u;

export function resourceId(kind, id) {
  if (!RESOURCE_KINDS.includes(kind)) throw new TypeError(`unknown resource kind: ${kind}`);
  return id === undefined ? `${kind}:list` : `${kind}:${id}`;
}

export function markResourceKind(response, kind) {
  if (!RESOURCE_KINDS.includes(kind)) throw new TypeError(`unknown resource kind: ${kind}`);
  response.setHeader('x-resource-kind', kind);
}

export function markResource(response, kind, id) {
  markResourceKind(response, kind);
  response.setHeader('x-resource-id', resourceId(kind, id));
}
