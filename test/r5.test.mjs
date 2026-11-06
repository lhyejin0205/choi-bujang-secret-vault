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
    // 12단계: 심판이 격리 환경에서 실제 요청을 따로 기록하므로, 자기 점검은 요청을 보내지 않고 not_run 으로 적습니다.
    assert.deepEqual(sent, []);
    assert.deepEqual(results.map(item => item.attackId),
      ['anonymous_notes_read', 'anonymous_notes_create', 'forged_token_notes_read', 'login_a_notes_read']);
    assert.deepEqual(results.slice(0, 3).map(item => item.observed), ['not_run', 'not_run', 'not_run']);
    assert.match(results[3].observed, /^미실행/u);
    assert.equal(JSON.stringify(results).includes('aaaaaaaaaa'), false);
    await assert.rejects(() => runAttackChecks({ ...config, step: 13 }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 4 attack check keeps the anonymous checks and leaves owner attacks as not sent', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  try {
    globalThis.fetch = async (url, init) => {
      sent.push({ method: init.method, hasAuth: Boolean(init.headers?.authorization) });
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401 });
    };
    const results = await runAttackChecks({ ...config, step: 4 });
    assert.deepEqual(sent, []);
    assert.deepEqual(results.map(item => item.attackId), ['anonymous_notes_read', 'anonymous_notes_create',
      'forged_token_notes_read', 'login_a_notes_read', 'b_reads_a_note', 'b_updates_a_note', 'b_deletes_a_note', 'a_changes_owner']);
    for (const item of results.slice(4)) assert.match(item.observed, /^미실행/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 5 attack check also sends one anon-key request to the original API and records the real result', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  const step5 = { ...config, step: 5, originalApiUrl: 'https://project.supabase.co/rest/v1/notes' };
  try {
    globalThis.fetch = async (url, init) => {
      const u = new URL(url);
      sent.push({ host: u.host, path: u.pathname, apikey: init.headers?.apikey });
      return u.host === 'project.supabase.co'
        ? new Response(JSON.stringify({ code: '42501' }), { status: 401 })
        : new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401 });
    };
    const key = { SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_testtesttest' };
    const results = await runAttackChecks(step5, key);
    const direct = sent.filter(item => item.host === 'project.supabase.co');
    assert.equal(direct.length, 1);
    assert.equal(direct[0].path, '/rest/v1/notes');
    assert.match(direct[0].apikey, /^sb_publishable_/u);
    const item = results.find(entry => entry.attackId === 'anon_original_api_read');
    assert.match(item.observed, /반환되지 않음 \(HTTP 401\)/u);
    assert.equal(JSON.stringify(results).includes('sb_publishable_'), false);

    globalThis.fetch = async (url) => new URL(url).host === 'project.supabase.co'
      ? new Response(JSON.stringify([{ id: 'x' }]), { status: 200 })
      : new Response('{}', { status: 401 });
    const leaked = await runAttackChecks(step5, key);
    assert.match(leaked.find(entry => entry.attackId === 'anon_original_api_read').observed, /자료가 반환됨/u);

    for (const bad of ['http://project.supabase.co/rest/v1/notes', 'https://project.supabase.co/rest/v1/notes?select=*',
      'https://evil.example/rest/v1/notes', null]) {
      await assert.rejects(() => runAttackChecks({ ...step5, originalApiUrl: bad }, key));
    }
    await assert.rejects(() => runAttackChecks(step5, { SUPABASE_PUBLISHABLE_KEY: 'TEST_FAKE_KEY' }));
    sent.length = 0;
    globalThis.fetch = async (url, init) => { sent.push(new URL(url).host); return new Response('{}', { status: 401 }); };
    const noKey = await runAttackChecks(step5, {});
    assert.match(noKey.find(entry => entry.attackId === 'anon_original_api_read').observed, /^미실행/u);
    assert.equal(sent.includes('project.supabase.co'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 7 attack check leaves same-login data blocking unrun without its contract', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  const step7 = { ...config, step: 7, originalApiUrl: 'https://project.supabase.co/rest/v1/notes' };
  try {
    globalThis.fetch = async (url, init) => {
      sent.push({ path: new URL(url).pathname, method: init.method });
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401 });
    };
    const results = await runAttackChecks(step7, {});
    assert.deepEqual(sent, []);
    const check = results.find(item => item.attackId === 'same_login_step_up_material_block');
    assert.match(check.expected, /재로그인/u);
    assert.match(check.observed, /^미실행/u);
    assert.match(check.observed, /같은 로그인/u);
    assert.equal(JSON.stringify(results).includes('accessToken'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 12 attack check sends no request and records every app check as not_run', async () => {
  const originalFetch = globalThis.fetch;
  const sent = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      sent.push({ path: new URL(String(url)).pathname, method: init.method ?? 'GET' });
      return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), { status: 401 });
    };
    const results = await runAttackChecks({ ...config, step: 12, originalApiUrl: 'https://abcdefghijklmnop.supabase.co/rest/v1/notes' }, {});
    // 심판의 격리 환경 기록과 맞도록 배포 앱에 요청을 보내지 않고, 쓰기·읽기 점검 9개 모두 not_run 입니다.
    assert.deepEqual(sent, []);
    for (const attackId of ['anonymous_notes_create', 'anonymous_notice_update', 'anonymous_restore_call', 'anonymous_device_approval',
      'anonymous_notes_read', 'forged_token_notes_read', 'anonymous_notices_read', 'forged_device_signature_read', 'anonymous_ops_summary']) {
      assert.equal(results.find(item => item.attackId === attackId).observed, 'not_run', attackId);
    }
    assert.equal(results.some(item => /HTTP \d/u.test(item.observed) || /^\d{3}$/u.test(item.observed)), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
