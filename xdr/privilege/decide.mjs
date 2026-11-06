// 심판은 이 파일 하나만 불러옵니다. import, 파일 I/O, 외부 호출을 하지 않습니다.
// xdr/privilege/patterns.json 의 패턴을 아래 상수로 옮겨 적었습니다.
const THRESHOLDS = Object.freeze({ block: 0.85, alert: 0.5 });
const ADMIN_GROUPS = Object.freeze(['administrators', 'domain admins', 'admins']);
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'repeated-admin-group-addition',
    techniques: Object.freeze(['T1078']),
    condition: 'T1078 경보이고 규칙 수준 10 이상이며, 관리자 그룹(administrators) 추가가 같은 출발 주소에서 2건 이상(data.count) 반복되면 차단 후보로 봅니다.',
    evidence: 'MITRE ATT&CK T1078은 정상 계정을 도용해 권한을 얻는 기법이며, 한 주소가 여러 계정을 관리자 그룹에 넣거나 빠진 계정을 곧바로 다시 넣는 것은 권한 확보를 반복한 흔적입니다.',
    minLevel: 10,
    adminGroups: ADMIN_GROUPS,
    minCount: 2,
    confidence: 0.95,
  }),
  Object.freeze({
    name: 'account-added-to-admin-group',
    techniques: Object.freeze(['T1078']),
    condition: 'T1078 경보이고 규칙 수준 10 이상이며, 평범한 계정이 관리자 그룹(administrators)에 추가되면 차단 후보로 봅니다.',
    evidence: 'MITRE ATT&CK T1078(정상 계정 도용)에서 공격자는 탈취한 평범한 계정을 관리자 그룹에 넣어 권한을 얻으며, 관리자 그룹 추가는 권한 상승의 대표 신호입니다.',
    minLevel: 10,
    adminGroups: ADMIN_GROUPS,
    confidence: 0.92,
  }),
  Object.freeze({
    name: 'privileged-command-after-escalation',
    techniques: Object.freeze(['T1068']),
    condition: 'T1068 경보이고 규칙 수준 10 이상이면(권한이 바뀐 직후, 처음 보는 주소나 다른 계정 권한으로 관리자 명령 실행) 차단 후보로 봅니다.',
    evidence: 'MITRE ATT&CK T1068은 취약점이나 설정 약점을 악용해 권한을 올리는 기법이며, 높은 수준으로 잡힌 권한 변경 직후의 처음 보는 관리자 명령은 악용 뒤 실행 흔적입니다.',
    minLevel: 10,
    confidence: 0.9,
  }),
  Object.freeze({
    name: 'off-hours-privileged-use',
    techniques: Object.freeze(['T1068', 'T1078']),
    condition: 'T1068 또는 T1078 경보이고 규칙 수준 10 이상이며, 경보 시각(한국 시간)이 업무 시간 밖(22시~06시)이면 차단 후보로 봅니다.',
    evidence: 'MITRE ATT&CK T1078의 도용 계정은 정상 사용자가 없는 시간대에 쓰이는 경우가 많아, 업무 시간 밖의 높은 수준 권한 사용은 도용 신호로 봅니다.',
    minLevel: 10,
    offHours: Object.freeze({ timezoneOffsetHours: 9, startHour: 22, endHour: 6 }),
    confidence: 0.88,
  }),
  Object.freeze({
    name: 'privilege-change-needs-review',
    techniques: Object.freeze(['T1068', 'T1078']),
    condition: 'T1068 또는 T1078로 분류되고 규칙 수준이 4 이상인데 위의 관리자 그룹·높은 수준 권한 명령·업무 시간 밖 신호가 없으면, 막지 않고 알림으로 추가 확인합니다.',
    evidence: 'T1068·T1078은 권한 상승 기법이지만 취소된 권한 상승 창, 관리자 그룹이 아닌 과제 그룹 추가, 평소 주소의 관리자 명령 1건처럼 정상 수업 활동도 같은 분류로 잡히므로 사람이 확인해야 합니다.',
    minLevel: 4,
    confidence: 0.6,
  }),
]);

// 경보의 MITRE 기법 목록. 'T1078.003' 같은 하위 기법도 상위 기법으로 셉니다.
function techniquesOf(alert) {
  const list = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  return new Set(list.filter((item) => typeof item === 'string').map((item) => item.split('.')[0].toUpperCase()));
}

function levelOf(alert) {
  const level = Number(alert?.rule?.level);
  return Number.isFinite(level) ? level : 0;
}

function groupOf(alert) {
  const group = alert?.data?.group;
  return typeof group === 'string' ? group.trim().toLowerCase() : '';
}

function countOf(alert) {
  const count = Number(alert?.data?.count);
  return Number.isFinite(count) ? count : 0;
}

// 경보 시각을 정해진 시간대의 시(0~23)로 바꿉니다. 시각을 읽을 수 없으면 null 입니다.
function localHour(alert, offsetHours) {
  const time = Date.parse(alert?.timestamp);
  if (!Number.isFinite(time)) return null;
  return new Date(time + offsetHours * 60 * 60 * 1000).getUTCHours();
}

function isOffHours(alert, window) {
  const hour = localHour(alert, window.timezoneOffsetHours);
  if (hour === null) return false;
  return hour >= window.startHour || hour < window.endHour;
}

function matches(pattern, alert, techniques) {
  if (!pattern.techniques.some((technique) => techniques.has(technique))) return false;
  if (levelOf(alert) < pattern.minLevel) return false;
  if (pattern.adminGroups && !pattern.adminGroups.includes(groupOf(alert))) return false;
  if (pattern.minCount !== undefined && countOf(alert) < pattern.minCount) return false;
  if (pattern.offHours && !isOffHours(alert, pattern.offHours)) return false;
  return true;
}

function actionFor(confidence) {
  if (confidence >= THRESHOLDS.block) return 'block';
  if (confidence >= THRESHOLDS.alert) return 'alert';
  return 'record';
}

export function decide(alert) {
  const techniques = techniquesOf(alert);
  // 맞는 패턴 가운데 확신도가 가장 높은 패턴을 근거로 씁니다.
  const matched = PATTERNS.filter((pattern) => matches(pattern, alert, techniques))
    .sort((a, b) => b.confidence - a.confidence);
  if (matched.length) {
    const [pattern] = matched;
    return {
      action: actionFor(pattern.confidence),
      confidence: pattern.confidence,
      reason: `${pattern.name}: ${pattern.evidence}`,
    };
  }
  return {
    action: 'record',
    confidence: 0.1,
    reason: 'no-privilege-pattern: T1068·T1078 권한 상승 신호가 없거나 규칙 수준이 낮은 정상 이벤트',
  };
}
