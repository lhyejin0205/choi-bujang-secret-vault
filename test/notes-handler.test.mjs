import assert from 'node:assert/strict';
import { test } from 'node:test';
import { handleNotesRequest } from '../src/notes-handler.mjs';

function responseRecorder() {
  const headers = new Map();
  return {
    headers,
    statusCode: undefined,
    body: undefined,
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    status(statusCode) { this.statusCode = statusCode; return this; },
    json(body) { this.body = body; return this; },
  };
}

const configured = {
  SUPABASE_URL: 'https://project.supabase.co',
  SUPABASE_SECRET_KEY: 'test-secret-not-a-real-key',
};

test('GET returns only note titles and contents from Supabase without caching', async () => {
  const response = responseRecorder();
  let requestedUrl;
  let requestOptions;
  await handleNotesRequest({ method: 'GET' }, response, configured, async (url, options) => {
    requestedUrl = new URL(url);
    requestOptions = options;
    return new Response(JSON.stringify([
      { title: '가상 제목', content: '가상 내용', owner_id: 'not-exposed', id: 'not-exposed' },
    ]), { status: 200 });
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, [{ title: '가상 제목', content: '가상 내용' }]);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(requestedUrl.href, 'https://project.supabase.co/rest/v1/notes?select=title%2Ccontent');
  assert.equal(requestOptions.headers.apikey, configured.SUPABASE_SECRET_KEY);
  assert.equal(requestOptions.headers.authorization, `Bearer ${configured.SUPABASE_SECRET_KEY}`);
  assert.equal(requestOptions.redirect, 'error');
});

test('non-GET requests are rejected without contacting Supabase', async () => {
  const response = responseRecorder();
  let called = false;
  await handleNotesRequest({ method: 'POST' }, response, configured, async () => { called = true; });

  assert.equal(response.statusCode, 405);
  assert.equal(response.headers.get('allow'), 'GET');
  assert.deepEqual(response.body, { error: 'METHOD_NOT_ALLOWED' });
  assert.equal(called, false);
});

test('missing configuration and upstream failures return fixed errors without secret details', async () => {
  const unconfigured = responseRecorder();
  await handleNotesRequest({ method: 'GET' }, unconfigured, {}, async () => {});
  assert.equal(unconfigured.statusCode, 503);
  assert.deepEqual(unconfigured.body, { error: 'NOTES_NOT_CONFIGURED' });

  const failed = responseRecorder();
  await handleNotesRequest({ method: 'GET' }, failed, configured, async () => {
    throw new Error(configured.SUPABASE_SECRET_KEY);
  });
  assert.equal(failed.statusCode, 502);
  assert.deepEqual(failed.body, { error: 'NOTES_UPSTREAM_FAILED' });
  assert.equal(JSON.stringify(failed.body).includes(configured.SUPABASE_SECRET_KEY), false);
});
