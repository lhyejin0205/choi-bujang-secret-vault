import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('build identity supports step 2 without carrying the step 1 note marker', () => {
  const identity = deploymentIdentity(env, { ...config, step: 2 });
  assert.equal(identity.step, 2);
  assert.equal(identity.publicAppUrl, 'https://student-defense-123.vercel.app');
  assert.equal('sampleMarker' in identity, false);
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 2 attack check records the result of an anonymous notes API request', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  try {
    globalThis.fetch = async (url) => {
      requestUrl = String(url);
      return new Response(JSON.stringify([{ title: '가상 제목', content: '가상 내용' }]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks({ ...config, step: 2 });
    assert.equal(requestUrl, 'https://student-defense.vercel.app/api/notes');
    assert.match(result.expected, /반환하지 않아야/u);
    assert.match(result.observed, /메모가 반환됨/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 3 attack check sends only anonymous and forged-token requests and records real results', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  try {
    globalThis.fetch = async (url, init) => {
      sent.push({ url: String(url), method: init.method, hasAuth: Boolean(init.headers?.authorization) });
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401 });
    };
    const results = await runAttackChecks({ ...config, step: 3 });
    assert.deepEqual(sent.map(({ method, hasAuth }) => [method, hasAuth]), [['GET', false], ['POST', false], ['GET', true]]);
    assert.ok(sent.every(entry => entry.url === 'https://student-defense.vercel.app/api/notes'));
    assert.deepEqual(results.map(item => item.attackId),
      ['anonymous_notes_read', 'anonymous_notes_create', 'forged_token_notes_read', 'login_a_notes_read']);
    assert.match(results[0].observed, /반환되지 않음 \(HTTP 401\)/u);
    assert.match(results[1].observed, /거부됨 \(HTTP 401\)/u);
    assert.match(results[3].observed, /^미실행/u);
    assert.equal(JSON.stringify(results).includes('aaaaaaaaaa'), false);

    globalThis.fetch = async () => new Response(JSON.stringify([{ id: 'x' }]), { status: 200 });
    const leaked = await runAttackChecks({ ...config, step: 3 });
    assert.match(leaked[0].observed, /자료가 반환됨/u);
    assert.match(leaked[1].observed, /받아들여짐/u);
    await assert.rejects(() => runAttackChecks({ ...config, step: 4 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
