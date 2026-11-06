import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RECHECK_CASES } from '../public/recheck-cases.js';
import { runAnonymousRecheck } from '../scripts/recheck.mjs';

const app = new URL('https://example-vault.vercel.app/');

test('재확인 목록의 줄은 보낼 요청과 기대 결과가 있거나, 보내지 않는 까닭이 있다', () => {
  const ids = new Set();
  for (const testCase of RECHECK_CASES) {
    assert.equal(ids.has(testCase.id), false, testCase.id);
    ids.add(testCase.id);
    if (testCase.engine) continue;
    assert.ok(['GET', 'POST', 'PUT'].includes(testCase.method), testCase.id);
    assert.ok(testCase.path.startsWith('/'), testCase.id);
    assert.ok(Array.isArray(testCase.expect) && testCase.expect.length, testCase.id);
    assert.ok(['none', 'forged', 'session'].includes(testCase.auth), testCase.id);
  }
  const kinds = RECHECK_CASES.filter(c => !c.engine).map(c => c.kind);
  assert.ok(kinds.includes('정상') && kinds.includes('금지'));
});

test('명령은 계정 없는 줄만 보내고, 응답 코드를 그대로 적으며, 나머지는 미실행으로 둔다', async () => {
  const sent = [];
  const fetchImpl = async (url, options) => {
    sent.push({ path: new URL(url).pathname, method: options.method, headers: options.headers });
    const status = new URL(url).pathname === '/api/notices' ? 200 : (new URL(url).pathname === '/' ? 200 : 401);
    return new Response('{}', { status, headers: { 'x-vercel-id': 'icn1::test' } });
  };
  const rows = await runAnonymousRecheck(app, { fetchImpl, now: () => new Date('2026-11-06T00:00:00Z') });
  assert.equal(rows.length, RECHECK_CASES.length);
  for (const row of rows) {
    const testCase = RECHECK_CASES.find(c => c.id === row.id);
    if (testCase.engine || testCase.auth === 'session') {
      assert.equal(row.verdict, '미실행', row.id);
      assert.equal(row.actual, '미실행', row.id);
      assert.equal(row.checkedAt, null, row.id);
    } else {
      assert.notEqual(row.verdict, '미실행', row.id);
      assert.equal(row.serverRequestId, 'icn1::test');
      assert.match(row.clientRequestId, /^[0-9a-f-]{36}$/u);
      assert.equal(row.checkedAt, '2026-11-06T00:00:00.000Z');
    }
  }
  assert.equal(sent.some(s => s.headers.authorization && !s.headers.authorization.startsWith('Bearer aaaaaaaaaa')), false);
  // 기대와 다른 응답(공지 목록이 로그인 없이 200)은 불일치로 남는다.
  assert.equal(rows.find(r => r.id === 's8-anon-notices').verdict, '불일치');
  assert.equal(rows.find(r => r.id === 's2-anon-list').verdict, '일치');
});

test('요청이 실패하면 통과로 적지 않는다', async () => {
  const rows = await runAnonymousRecheck(app, { fetchImpl: async () => { throw new Error('network'); } });
  for (const row of rows.filter(r => r.verdict !== '미실행')) {
    assert.equal(row.verdict, '불일치');
    assert.equal(row.actual, '요청 실패');
  }
});
