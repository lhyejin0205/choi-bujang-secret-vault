function sendJson(response, status, body) {
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('cache-control', 'no-store');
  return response.status(status).json(body);
}

function supabaseRestUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) return null;
  url.pathname = '/rest/v1/notes';
  url.searchParams.set('select', 'title,content');
  return url;
}

export async function handleNotesRequest(request, response, env = process.env, fetchImpl = globalThis.fetch) {
  if (request.method !== 'GET') {
    response.setHeader('allow', 'GET');
    return sendJson(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }

  const endpoint = supabaseRestUrl(env.SUPABASE_URL);
  const secretKey = env.SUPABASE_SECRET_KEY;
  if (!endpoint || typeof secretKey !== 'string' || secretKey.length === 0) {
    return sendJson(response, 503, { error: 'NOTES_NOT_CONFIGURED' });
  }

  try {
    const upstream = await fetchImpl(endpoint, {
      headers: {
        apikey: secretKey,
        authorization: `Bearer ${secretKey}`,
        accept: 'application/json',
      },
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    if (!upstream.ok) return sendJson(response, 502, { error: 'NOTES_UPSTREAM_FAILED' });

    const rows = await upstream.json();
    if (!Array.isArray(rows) || rows.some(note => !note || typeof note.title !== 'string'
        || typeof note.content !== 'string')) {
      return sendJson(response, 502, { error: 'NOTES_UPSTREAM_FAILED' });
    }
    return sendJson(response, 200, rows.map(({ title, content }) => ({ title, content })));
  } catch {
    return sendJson(response, 502, { error: 'NOTES_UPSTREAM_FAILED' });
  }
}
