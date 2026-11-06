// 심판은 이 파일 하나만 불러옵니다. import, 파일 I/O, 외부 호출을 하지 않습니다.
// xdr/persistence/patterns.json 의 패턴을 아래 상수로 옮겨 적었습니다.
const THRESHOLDS = Object.freeze({ block: 0.85, alert: 0.5 });
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'unsigned-service-from-temp-path',
    techniques: Object.freeze(['T1543']),
    condition: 'T1543 경보이고 규칙 수준 10 이상이며, 새로 만들거나 바꾼 서비스의 실행 파일이 사용자 임시 폴더(AppData\\Local\\Temp)에 있으면 차단 후보로 봅니다.',
    evidence: 'MITRE ATT&CK T1543.003은 윈도우 서비스를 만들거나 바꿔 재부팅 뒤에도 프로그램을 실행시키는 지속성 기법이며, 사용자 임시 폴더의 서명 없는 실행 파일은 정상 설치 경로가 아닙니다.',
    minLevel: 10,
    pathIndicators: Object.freeze(['\\appdata\\local\\temp\\']),
    confidence: 0.92,
  }),
  Object.freeze({
    name: 'unfamiliar-scheduled-task-temp-path',
    techniques: Object.freeze(['T1053']),
    condition: 'T1053 경보이고 규칙 수준 10 이상이며, 처음 보는 예약 작업이 사용자 임시 폴더의 실행 파일을 부르면 차단 후보로 봅니다.',
    evidence: 'MITRE ATT&CK T1053.005 예약 작업은 정해진 시각이나 부팅 때 프로그램을 다시 실행하게 하는 지속성 기법이며, 임시 폴더 실행 파일을 부르는 낯선 작업은 수업용 작업과 다릅니다.',
    minLevel: 10,
    pathIndicators: Object.freeze(['\\appdata\\local\\temp\\']),
    confidence: 0.9,
  }),
  Object.freeze({
    name: 'startup-folder-unlisted-program',
    techniques: Object.freeze(['T1543']),
    condition: 'T1543으로 분류된 규칙 수준 10 이상 경보에서 사용자 시작 폴더(Start Menu\\Programs\\Startup)에 평소 목록에 없는 실행 파일이 생기면 차단 후보로 봅니다.',
    evidence: '시작 폴더 자동 실행은 MITRE ATT&CK T1547.001(로그온 자동 실행)에 해당하는 지속성 기법이며, 이 경보는 T1543으로 분류돼 같은 재부팅 뒤 생존 시도로 다룹니다.',
    minLevel: 10,
    pathIndicators: Object.freeze(['\\start menu\\programs\\startup\\']),
    confidence: 0.9,
  }),
  Object.freeze({
    name: 'repeated-unsigned-service-registration',
    techniques: Object.freeze(['T1543']),
    condition: 'T1543 경보이고 규칙 수준 10 이상이며, 같은 출발 주소에서 서명 없는 서비스 등록이 2건 이상(data.count) 반복되면 차단 후보로 봅니다.',
    evidence: 'MITRE ATT&CK T1543.003 서비스 생성을 한 출발 주소가 반복하는 것은 지속성 확보를 여러 번 시도한 흔적이며, 수업 중 정상 설치는 같은 서비스를 연달아 등록하지 않습니다.',
    minLevel: 10,
    minCount: 2,
    confidence: 0.9,
  }),
  Object.freeze({
    name: 'persistence-change-needs-review',
    techniques: Object.freeze(['T1543', 'T1053']),
    condition: 'T1543 또는 T1053으로 분류되고 규칙 수준이 4 이상인데 위의 임시 폴더·시작 폴더·반복 신호가 없으면, 막지 않고 알림으로 추가 확인합니다.',
    evidence: 'T1543·T1053은 지속성 기법이지만 수업용 예약 작업과 도구 서비스도 같은 분류로 잡히므로, 뚜렷한 악성 신호가 없으면 사람이 확인해야 합니다.',
    minLevel: 4,
    confidence: 0.6,
  }),
]);

// 경보의 MITRE 기법 목록. 'T1543.003' 같은 하위 기법도 상위 기법으로 셉니다.
function techniquesOf(alert) {
  const list = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  return new Set(list.filter((item) => typeof item === 'string').map((item) => item.split('.')[0].toUpperCase()));
}

function levelOf(alert) {
  const level = Number(alert?.rule?.level);
  return Number.isFinite(level) ? level : 0;
}

// 경로는 대소문자와 / \ 를 맞춰 비교합니다.
function pathOf(alert) {
  const path = alert?.data?.path;
  return typeof path === 'string' ? `${path.toLowerCase().replaceAll('/', '\\')}` : '';
}

function countOf(alert) {
  const count = Number(alert?.data?.count);
  return Number.isFinite(count) ? count : 0;
}

function matches(pattern, alert, techniques) {
  if (!pattern.techniques.some((technique) => techniques.has(technique))) return false;
  const level = levelOf(alert);
  if (level < pattern.minLevel) return false;
  if (pattern.maxLevel !== undefined && level > pattern.maxLevel) return false;
  if (pattern.pathIndicators) {
    const path = pathOf(alert);
    if (!pattern.pathIndicators.some((indicator) => path.includes(indicator))) return false;
  }
  if (pattern.minCount !== undefined && countOf(alert) < pattern.minCount) return false;
  return true;
}

function actionFor(confidence) {
  if (confidence >= THRESHOLDS.block) return 'block';
  if (confidence >= THRESHOLDS.alert) return 'alert';
  return 'record';
}

export function decide(alert) {
  const techniques = techniquesOf(alert);
  // 뚜렷한 패턴부터 맞춰 보고, 가장 확신도가 높은 패턴을 근거로 씁니다.
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
    reason: 'no-persistence-pattern: T1543·T1053 지속성 신호가 없거나 규칙 수준이 낮은 정상 이벤트',
  };
}
