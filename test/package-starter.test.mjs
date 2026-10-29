import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';

const baseline = JSON.parse(await readFile(new URL('../package/baseline-functions.json', import.meta.url)));

test('패키징 함수 기준표는 시작 틀의 실제 API와 일치한다', async () => {
  const actual = (await readdir(new URL('../api/', import.meta.url)))
    .filter(name => /\.(?:m?js|ts)$/u.test(name))
    .map(name => join('api', name).replaceAll('\\', '/')).sort();
  assert.equal(baseline.version, 1);
  assert.equal(baseline.starter, 'ChoiTimo/aleph-defense-starter');
  assert.deepEqual(baseline.functions, ['api/notes.js']);
  assert.deepEqual(baseline.allowedNew, ['api/ai.js', 'api/threat-intel.js']);
  assert.deepEqual(actual, [...baseline.functions, ...baseline.allowedNew].sort());
});

test('미구현 서버 뼈대는 성공이나 로그인 통과로 가장하지 않는다', async () => {
  for (const name of ['ai', 'threat-intel']) {
    const { default: handler } = await import(`../api/${name}.js`);
    const headers = new Map();
    let status;
    let body;
    handler({}, {
      setHeader: (key, value) => headers.set(key.toLowerCase(), value),
      status: value => { status = value; return { json: value => { body = value; } }; },
    });
    assert.equal(status, 501);
    assert.equal(headers.get('cache-control'), 'no-store');
    assert.match(body.error, /NOT_IMPLEMENTED$/u);
  }
});

test('P7 시작 틀 안내는 실제 빌드 조건과 새 배포 시험에 맞는다', async () => {
  const readme = await readFile(new URL('../package/README.md', import.meta.url), 'utf8');
  const selfCheck = await readFile(new URL('../package/SELF-CHECK.md', import.meta.url), 'utf8');
  assert.match(readme, /새 Vercel 프로젝트/u);
  assert.match(readme, /Vercel이 제공하는 저장소·커밋·배포 URL 정보/u);
  assert.doesNotMatch(readme, /npm start/u);
  assert.match(selfCheck, /P7-3\.png/u);
});

test('3단계 설정은 로그인 발급자와 실제 자료 API 경로를 기록하고 README에 흐름을 적는다', async () => {
  const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url)));
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
  const vercel = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url)));
  assert.equal(config.step, 3);
  const issuer = new URL(config.identityProvider.issuer);
  assert.equal(issuer.protocol, 'https:');
  assert.equal(issuer.pathname, '/auth/v1');
  assert.ok(issuer.hostname.endsWith('.supabase.co'));
  assert.equal(config.identityProvider.jwksUrl, `${config.identityProvider.issuer}/.well-known/jwks.json`);
  assert.equal(config.identityProvider.audience, 'authenticated');
  assert.deepEqual(config.allowedRoutes, ['GET /api/notes', 'POST /api/notes', 'GET /api/notes/:id',
    'PUT /api/notes/:id', 'DELETE /api/notes/:id']);
  assert.equal(/sb_secret_|service_role/u.test(JSON.stringify(config)), false);
  assert.deepEqual(vercel.rewrites, [{ source: '/api/notes/:id', destination: '/api/notes?id=:id' }]);
  assert.match(readme, /\/api\/notes/u);
  assert.match(readme, /SUPABASE_SECRET_KEY/u);
  assert.match(readme, /verify-login/u);
});
