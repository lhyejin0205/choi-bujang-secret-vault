// 심판은 이 파일 하나만 불러옵니다. import, 파일 I/O, 외부 호출을 하지 않습니다.
// patterns.json 의 패턴을 아래 상수로 옮겨 적었습니다.
const THRESHOLDS = Object.freeze({ block: 0.85, alert: 0.5 });
const PATTERNS = Object.freeze([
  Object.freeze({
    name: 'jndi-remote-lookup-in-request',
    condition: 'MITRE ATT&CK T1190 경보의 요청 머리글(useragent) 또는 URL 인자에 완전한 JNDI 원격 조회 구문이 있으면 차단 후보로 봅니다.',
    evidence: 'CVE-2021-44228 악용 형태는 요청이 처리하는 값에 JNDI 원격 조회 구문을 넣는 것이며, MITRE ATT&CK T1190은 공개 애플리케이션 악용을 분류합니다.',
    fields: Object.freeze(['data.useragent', 'data.url']),
    expression: '\\$\\{\\s*jndi\\s*:\\s*[a-z][a-z0-9+.-]*\\s*:',
    confidence: Object.freeze({ t1190: 0.96, untagged: 0.7 }),
  }),
  Object.freeze({
    name: 'known-vulnerability-scanner-trace',
    condition: '완전한 JNDI 구문이 없더라도 요청 머리글 또는 URL 경로에 알려진 점검 도구의 구체적인 표식이 있으면 T1190 유무와 관계없이 추가 확인 대상으로 봅니다.',
    evidence: '요청에서 확인된 특정 점검 도구 표식은 조사할 근거지만, 설명 문구만으로는 도구 사용을 입증할 수 없습니다.',
    fields: Object.freeze(['data.useragent', 'data.url']),
    requestIndicators: Object.freeze(['/tools/class-check']),
    confidence: 0.6,
  }),
]);

function hasT1190(alert) {
  return Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.some((technique) =>
      typeof technique === 'string' && (technique === 'T1190' || technique.startsWith('T1190.')));
}

function hasJndiRequest(alert) {
  const pattern = PATTERNS.find((item) => item.name === 'jndi-remote-lookup-in-request');
  const expression = new RegExp(pattern.expression, 'iu');
  return pattern.fields.some((field) => {
    const [parent, key] = field.split('.');
    const value = alert?.[parent]?.[key];
    return typeof value === 'string' && expression.test(value);
  });
}

function hasScannerTrace(alert) {
  const pattern = PATTERNS.find((item) => item.name === 'known-vulnerability-scanner-trace');
  return pattern.fields.some((field) => {
    const [parent, key] = field.split('.');
    const value = alert?.[parent]?.[key];
    return typeof value === 'string'
      && pattern.requestIndicators.some((indicator) => value.toLowerCase().includes(indicator));
  });
}

function actionFor(confidence) {
  if (confidence >= THRESHOLDS.block) return 'block';
  if (confidence >= THRESHOLDS.alert) return 'alert';
  return 'record';
}

export function decide(alert) {
  const t1190 = hasT1190(alert);
  const jndi = hasJndiRequest(alert);
  if (jndi) {
    const pattern = PATTERNS.find((item) => item.name === 'jndi-remote-lookup-in-request');
    const confidence = t1190 ? pattern.confidence.t1190 : pattern.confidence.untagged;
    return {
      action: actionFor(confidence),
      confidence,
      reason: `${pattern.name}: ${pattern.evidence}${t1190 ? ' (T1190)' : ' (T1190 미표시)'}`,
    };
  }

  if (hasScannerTrace(alert)) {
    const pattern = PATTERNS.find((item) => item.name === 'known-vulnerability-scanner-trace');
    return {
      action: actionFor(pattern.confidence),
      confidence: pattern.confidence,
      reason: `${pattern.name}: ${pattern.evidence}`,
    };
  }

  return {
    action: 'record',
    confidence: 0.1,
    reason: 'no-known-cve-pattern: 완전한 JNDI 원격 조회 또는 점검 도구 흔적이 없음',
  };
}
