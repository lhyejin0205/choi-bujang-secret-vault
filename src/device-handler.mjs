import { createHash } from 'node:crypto';
import { canonicalJson } from './policy-backup.mjs';

// 11단계: 기기 승인과 요청 서명.
// - 브라우저는 내보낼 수 없는 ECDSA P-256 서명 키를 메모리에서만 만들고, 공개키만 POST /api/devices 로 보냅니다.
//   서버는 그 공개키를 "승인 대기"로 등록할 뿐이며, 승인은 DB(supabase/stage11-devices.sql ③)에서만 합니다.
// - 보호 요청(메모·공지 API)은 아래 문자열에 대한 서명을 머리글로 함께 보내야 합니다.
//     aleph-device-v1 \n 동작 \n 경로 \n 시각(ms) \n SHA-256(정렬한 JSON 본문 또는 빈 문자열)
//   서버는 실제로 받은 동작·경로·본문으로 같은 문자열을 다시 만들어 검증하므로,
//   서명 뒤 경로나 본문을 바꾸면 검증에 실패합니다. 서명이 없거나 기기가 승인되지 않았으면 거부합니다.
// - 기기 키·토큰은 브라우저 저장소에 두지 않고, 서버도 개인키를 받지 않습니다.
export const SIGNATURE_VERSION = 'aleph-device-v1';
export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/u;
const THUMBPRINT = /^[0-9a-f]{64}$/u;

const sha256Hex = text => createHash('sha256').update(text, 'utf8').digest('hex');

export function isPublicJwk(jwk) {
  return jwk !== null && typeof jwk === 'object' && !Array.isArray(jwk) && jwk.kty === 'EC' && jwk.crv === 'P-256'
    && typeof jwk.x === 'string' && B64URL_32.test(jwk.x) && typeof jwk.y === 'string' && B64URL_32.test(jwk.y)
    && !Object.hasOwn(jwk, 'd');
}

// RFC 7638 방식의 공개키 지문(정해진 네 값만 정렬해 SHA-256). 기기 번호로 씁니다.
export function keyThumbprint(jwk) {
  return sha256Hex(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
}

// 본문을 정렬한 JSON으로 바꿔 해시합니다. 본문이 없으면 빈 문자열의 해시입니다.
export function bodyDigest(body) {
  let value = body;
  if (typeof value === 'string') {
    if (value.length === 0) return sha256Hex('');
    try { value = JSON.parse(value); } catch { return sha256Hex(value); }
  }
  if (value === undefined || value === null) return sha256Hex('');
  if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) return sha256Hex('');
  return sha256Hex(canonicalJson(value));
}

export function signingString({ method, path, time, body }) {
  return [SIGNATURE_VERSION, String(method).toUpperCase(), path, String(time), bodyDigest(body)].join('\n');
}

function sendJson(response, status, body) {
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('cache-control', 'no-store');
  return response.status(status).json(body);
}

function supabaseOrigin(value) {
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) return null;
  return url.origin;
}

function deviceTable(env, fetchImpl) {
  const origin = supabaseOrigin(env.SUPABASE_URL);
  const secretKey = env.SUPABASE_SECRET_KEY;
  if (!origin || typeof secretKey !== 'string' || secretKey.length === 0) return null;
  return (method, params, body, prefer) => {
    const url = new URL('/rest/v1/device_approvals', origin);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    const headers = { apikey: secretKey, authorization: `Bearer ${secretKey}`, accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (prefer) headers.prefer = prefer;
    return fetchImpl(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error', signal: AbortSignal.timeout(10000) });
  };
}

function jsonBody(request) {
  let body = request.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

// POST /api/devices : 로그인한 사용자가 이 기기의 공개키를 "승인 대기"로 등록하거나, 이미 등록한 기기의 상태를 묻습니다.
// 본문의 status·approved 같은 값은 보지 않습니다. 응답은 서버 DB의 상태 그대로입니다.
export async function handleDeviceRequest(request, response, options = {}) {
  const { env = process.env, fetchImpl = globalThis.fetch, verifyLogin, log = () => {} } = options;
  const deny = (status, error, reason) => {
    log({ event: 'api_denied', zone: 'device', method: request.method, reason });
    return sendJson(response, status, { error });
  };
  if (request.method !== 'POST') {
    response.setHeader('allow', 'POST');
    return deny(405, 'METHOD_NOT_ALLOWED', 'method');
  }
  let user;
  try {
    if (typeof verifyLogin !== 'function') throw new TypeError('missing_verifier');
    user = await verifyLogin(request.headers?.authorization);
  } catch {
    return sendJson(response, 503, { error: 'AUTH_NOT_CONFIGURED' });
  }
  if (!user || user.kind !== 'student' || typeof user.userId !== 'string' || !UUID.test(user.userId)) {
    response.setHeader('www-authenticate', 'Bearer');
    return deny(401, 'UNAUTHORIZED', 'no_valid_login');
  }
  const publicKey = jsonBody(request)?.publicKey;
  if (!isPublicJwk(publicKey)) return deny(400, 'INVALID_PUBLIC_KEY', 'bad_key');
  const table = deviceTable(env, fetchImpl);
  if (!table) return sendJson(response, 503, { error: 'DEVICES_NOT_CONFIGURED' });
  const thumbprint = keyThumbprint(publicKey);
  const fail = () => sendJson(response, 502, { error: 'DEVICES_UPSTREAM_FAILED' });
  try {
    const found = await table('GET', { select: 'owner_id,status', key_thumbprint: `eq.${thumbprint}`, limit: '1' });
    if (!found.ok) return fail();
    const rows = await found.json();
    if (!Array.isArray(rows)) return fail();
    if (rows.length) {
      if (rows[0].owner_id !== user.userId) return deny(409, 'DEVICE_KEY_IN_USE', 'other_owner');
      return sendJson(response, 200, { deviceKey: thumbprint, status: rows[0].status });
    }
    const created = await table('POST', {}, {
      key_thumbprint: thumbprint, owner_id: user.userId,
      public_key_jwk: { kty: 'EC', crv: 'P-256', x: publicKey.x, y: publicKey.y },
    }, 'return=minimal');
    if (!created.ok) return fail();
    return sendJson(response, 201, { deviceKey: thumbprint, status: 'pending' });
  } catch {
    return fail();
  }
}

const header = (request, name) => {
  const value = request.headers?.[name];
  return typeof value === 'string' ? value : undefined;
};

// 보호 요청의 서명을 검증합니다. path 는 서버가 라우팅으로 아는 실제 경로입니다(요청이 주장하는 값이 아님).
export async function verifyDeviceRequest(request, user, options = {}) {
  const { path, env = process.env, fetchImpl = globalThis.fetch, now = Date.now(), subtle = globalThis.crypto.subtle } = options;
  const key = header(request, 'x-device-key');
  const time = header(request, 'x-device-time');
  const signature = header(request, 'x-device-signature');
  if (!key || !time || !signature) return { ok: false, error: 'DEVICE_SIGNATURE_REQUIRED', reason: 'unsigned' };
  if (!THUMBPRINT.test(key) || !/^[0-9]{13}$/u.test(time) || !/^[A-Za-z0-9_-]{86}$/u.test(signature)) {
    return { ok: false, error: 'DEVICE_SIGNATURE_INVALID', reason: 'bad_signature_format' };
  }
  if (Math.abs(now - Number(time)) > MAX_CLOCK_SKEW_MS) {
    return { ok: false, error: 'DEVICE_SIGNATURE_EXPIRED', reason: 'stale_signature' };
  }
  if (!user || typeof user.userId !== 'string' || !UUID.test(user.userId) || typeof path !== 'string') {
    return { ok: false, error: 'DEVICE_NOT_APPROVED', reason: 'not_approved' };
  }
  const table = deviceTable(env, fetchImpl);
  if (!table) return { ok: false, status: 503, error: 'DEVICES_NOT_CONFIGURED', reason: 'not_configured' };
  let rows;
  try {
    const found = await table('GET', { select: 'public_key_jwk', key_thumbprint: `eq.${key}`,
      owner_id: `eq.${user.userId}`, status: 'eq.approved', limit: '1' });
    if (!found.ok) throw new Error('upstream');
    rows = await found.json();
  } catch {
    return { ok: false, status: 502, error: 'DEVICE_CHECK_FAILED', reason: 'upstream_error' };
  }
  const jwk = Array.isArray(rows) && rows.length === 1 ? rows[0].public_key_jwk : null;
  if (!isPublicJwk(jwk) || keyThumbprint(jwk) !== key) return { ok: false, error: 'DEVICE_NOT_APPROVED', reason: 'not_approved' };
  try {
    const publicKey = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const message = new TextEncoder().encode(signingString({ method: request.method, path, time, body: request.body }));
    const valid = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey,
      Buffer.from(signature, 'base64url'), message);
    return valid ? { ok: true } : { ok: false, error: 'DEVICE_SIGNATURE_INVALID', reason: 'bad_signature' };
  } catch {
    return { ok: false, error: 'DEVICE_SIGNATURE_INVALID', reason: 'bad_signature' };
  }
}
