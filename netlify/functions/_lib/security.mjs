import crypto from 'node:crypto';

export const SESSION_COOKIE = '__Host-portfolio-admin';
export const SESSION_TTL_SECONDS = 8 * 60 * 60;

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function jsonResponse(statusCode, value, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, max-age=0',
      Pragma: 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      Vary: 'Cookie',
      ...extraHeaders,
    },
    body: value === null ? '' : JSON.stringify(value),
  };
}

export function methodNotAllowed(allow) {
  return jsonResponse(405, { error: 'Method not allowed.' }, { Allow: allow });
}

export function header(event, name) {
  const headers = event?.headers || {};
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
  return key ? String(headers[key] || '') : '';
}

function normalizedOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return '';
  }
}

export function sameOriginRequest(event) {
  const origin = normalizedOrigin(header(event, 'origin'));
  if (!origin) return false;
  const allowed = new Set([
    process.env.SITE_ORIGIN,
    process.env.URL,
    process.env.DEPLOY_PRIME_URL,
    process.env.DEPLOY_URL,
    event?.rawUrl,
  ].map(normalizedOrigin).filter(Boolean));
  return allowed.has(origin);
}

export function parseJsonBody(event) {
  try {
    const raw = event?.body || '';
    const text = event?.isBase64Encoded ? Buffer.from(raw, 'base64').toString('utf8') : raw;
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, 'Invalid JSON request.');
  }
}

export function readCookie(event) {
  const cookieHeader = header(event, 'cookie');
  for (const item of cookieHeader.split(';')) {
    const part = item.trim();
    const splitAt = part.indexOf('=');
    if (splitAt < 0) continue;
    if (part.slice(0, splitAt) === SESSION_COOKIE) return part.slice(splitAt + 1);
  }
  return '';
}

export function sessionCookie(value, maxAge = SESSION_TTL_SECONDS) {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.max(0, Math.floor(maxAge))}`;
}

export function clearedSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

export function publicConfig() {
  const url = String(process.env.SUPABASE_URL || '').replace(/\/+$/, '');
  const anonKey = String(process.env.SUPABASE_ANON_KEY || '');
  if (!/^https:\/\//i.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(url)) {
    throw new Error('SUPABASE_URL must be a valid HTTPS URL (or loopback for local development).');
  }
  if (!anonKey) throw new Error('SUPABASE_ANON_KEY is not configured.');
  return { url, anonKey };
}

export function adminConfig() {
  const { url, anonKey } = publicConfig();
  const serviceRoleKey = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '');
  const encryptionHex = String(process.env.SESSION_ENCRYPTION_KEY || '');
  const adminEmail = String(process.env.SUPABASE_ADMIN_EMAIL || '').trim().toLowerCase();
  const adminUserIds = new Set(String(process.env.ADMIN_USER_IDS || '').split(',').map((id) => id.trim().toLowerCase()).filter(Boolean));
  if (!serviceRoleKey) throw new Error('SUPABASE_SERVICE_ROLE_KEY is not configured.');
  if (!/^[0-9a-f]{64}$/i.test(encryptionHex)) throw new Error('SESSION_ENCRYPTION_KEY must be 32 bytes encoded as 64 hexadecimal characters.');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(adminEmail)) throw new Error('SUPABASE_ADMIN_EMAIL is not configured.');
  if (!adminUserIds.size || [...adminUserIds].some((id) => !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id))) {
    throw new Error('ADMIN_USER_IDS must contain one or more Supabase Auth user UUIDs.');
  }
  return { url, anonKey, serviceRoleKey, encryptionKey: Buffer.from(encryptionHex, 'hex'), adminUserIds, adminEmail };
}

export function isAuthorizedUser(userId, allowedIds) {
  return Boolean(userId && allowedIds.has(String(userId).toLowerCase()));
}

export function hashSessionId(sessionId) {
  return crypto.createHash('sha256').update(sessionId).digest('hex');
}

export function encryptSession(value, encryptionKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return JSON.stringify({
    v: 1,
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    data: ciphertext.toString('base64url'),
  });
}

export function decryptSession(value, encryptionKey) {
  const record = JSON.parse(value);
  if (!record || record.v !== 1 || !record.iv || !record.tag || !record.data) throw new Error('Invalid encrypted session record.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(record.iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64url'));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(record.data, 'base64url')), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

async function serviceRest(method, path, body, prefer = '') {
  const { url, serviceRoleKey } = adminConfig();
  const headers = {
    apikey: serviceRoleKey,
    Accept: 'application/json',
  };
  // Current Supabase secret API keys (sb_secret_...) are not JWTs and must be
  // sent only as apikey. Legacy service_role keys are JWTs and accept both.
  if (!serviceRoleKey.startsWith('sb_secret_')) headers.Authorization = `Bearer ${serviceRoleKey}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (prefer) headers.Prefer = prefer;
  let response;
  try {
    response = await fetch(`${url}/rest/v1/${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new HttpError(503, 'Secure session storage is temporarily unavailable.');
  }
  if (!response.ok) throw new HttpError(503, 'Secure session storage is temporarily unavailable.');
  const text = await response.text();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

export async function createServerSession(userId, authPayload) {
  const cfg = adminConfig();
  const sessionId = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_SECONDS * 1000;
  const accessExpiresAt = now + Math.max(60, Number(authPayload.expires_in) || 3600) * 1000;
  const tokenState = {
    userId,
    accessToken: authPayload.access_token,
    refreshToken: authPayload.refresh_token,
    accessExpiresAt,
  };
  const sessionHash = hashSessionId(sessionId);
  await serviceRest('POST', 'admin_sessions', {
    session_hash: sessionHash,
    user_id: userId,
    token_ciphertext: encryptSession(tokenState, cfg.encryptionKey),
    expires_at: new Date(expiresAt).toISOString(),
  }, 'return=minimal');
  return { sessionId, expiresAt };
}

async function readServerSession(sessionHash) {
  const rows = await serviceRest('GET', `admin_sessions?session_hash=eq.${encodeURIComponent(sessionHash)}&select=session_hash,user_id,token_ciphertext,expires_at`);
  return Array.isArray(rows) ? rows[0] || null : null;
}

async function updateServerSession(row, tokenState) {
  const cfg = adminConfig();
  await serviceRest('PATCH', `admin_sessions?session_hash=eq.${encodeURIComponent(row.session_hash)}`, {
    token_ciphertext: encryptSession(tokenState, cfg.encryptionKey),
  }, 'return=minimal');
}

export async function deleteServerSession(sessionHash) {
  await serviceRest('DELETE', `admin_sessions?session_hash=eq.${encodeURIComponent(sessionHash)}`);
}

async function authRequest(path, { method = 'GET', body, accessToken } = {}) {
  const { url, anonKey } = publicConfig();
  const headers = { apikey: anonKey, Accept: 'application/json' };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  try {
    const response = await fetch(`${url}/auth/v1/${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let payload = null;
    try { payload = await response.json(); } catch {}
    return { response, payload };
  } catch {
    throw new HttpError(503, 'Supabase Auth is temporarily unavailable.');
  }
}

export async function revokeAuthSession(accessToken) {
  if (!accessToken) return;
  try {
    await authRequest('logout?scope=local', { method: 'POST', accessToken });
  } catch {
    // The server-side opaque session is still deleted; a transient revoke failure
    // cannot make the browser session usable again.
  }
}

async function refreshAuthTokens(refreshToken) {
  if (!refreshToken) return null;
  const { response, payload } = await authRequest('token?grant_type=refresh_token', {
    method: 'POST',
    body: { refresh_token: refreshToken },
  });
  if (!response.ok || !payload?.access_token || !payload?.refresh_token) return null;
  return payload;
}

async function verifyAccessToken(accessToken) {
  const { response, payload } = await authRequest('user', { accessToken });
  return { ok: response.ok, user: payload && payload.id ? payload : null, status: response.status };
}

async function saveRefreshedTokens(row, oldState, refreshed) {
  const tokenState = {
    userId: row.user_id,
    accessToken: refreshed.access_token,
    refreshToken: refreshed.refresh_token,
    accessExpiresAt: Date.now() + Math.max(60, Number(refreshed.expires_in) || 3600) * 1000,
  };
  await updateServerSession(row, tokenState);
  return tokenState;
}

export async function loadAdminSession(event) {
  const sessionId = readCookie(event);
  if (!/^[0-9a-f]{64}$/i.test(sessionId)) return null;
  const cfg = adminConfig();
  const sessionHash = hashSessionId(sessionId);
  let row = await readServerSession(sessionHash);
  if (!row) return null;
  if (Date.parse(row.expires_at) <= Date.now() || !isAuthorizedUser(row.user_id, cfg.adminUserIds)) {
    await deleteServerSession(sessionHash);
    return null;
  }

  let tokenState;
  try { tokenState = decryptSession(row.token_ciphertext, cfg.encryptionKey); }
  catch {
    await deleteServerSession(sessionHash);
    return null;
  }
  if (tokenState.userId !== row.user_id || !tokenState.accessToken || !tokenState.refreshToken) {
    await deleteServerSession(sessionHash);
    return null;
  }

  let verified = null;
  if (Number(tokenState.accessExpiresAt) > Date.now() + 60_000) {
    verified = await verifyAccessToken(tokenState.accessToken);
  }
  if (!verified?.ok) {
    const refreshed = await refreshAuthTokens(tokenState.refreshToken);
    if (!refreshed) {
      await deleteServerSession(sessionHash);
      return null;
    }
    tokenState = await saveRefreshedTokens(row, tokenState, refreshed);
    verified = await verifyAccessToken(tokenState.accessToken);
  }
  if (!verified?.ok || verified.user?.id?.toLowerCase() !== row.user_id.toLowerCase() || !isAuthorizedUser(verified.user.id, cfg.adminUserIds)) {
    await deleteServerSession(sessionHash);
    return null;
  }

  return {
    sessionId,
    sessionHash,
    userId: row.user_id,
    accessToken: tokenState.accessToken,
    expiresAt: Date.parse(row.expires_at),
  };
}

export async function userRestRequest(session, method, path, body, prefer = '') {
  const { url, anonKey } = publicConfig();
  const headers = {
    apikey: anonKey,
    Authorization: `Bearer ${session.accessToken}`,
    Accept: 'application/json',
  };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (prefer) headers.Prefer = prefer;
  try {
    return await fetch(`${url}/rest/v1/${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new HttpError(503, 'Supabase Database is temporarily unavailable.');
  }
}

export function adminCookieHeaders(sessionId, expiresAt) {
  return { 'Set-Cookie': sessionCookie(sessionId, Math.ceil((expiresAt - Date.now()) / 1000)) };
}

export function clearCookieHeaders() {
  return { 'Set-Cookie': clearedSessionCookie() };
}
