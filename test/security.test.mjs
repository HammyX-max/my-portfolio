import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { handler as login } from '../netlify/functions/admin-login.mjs';
import { handler as session } from '../netlify/functions/admin-session.mjs';
import { handler as logout } from '../netlify/functions/admin-logout.mjs';
import { handler as content } from '../netlify/functions/admin-content.mjs';
import { handler as saveContent } from '../netlify/functions/admin-save.mjs';
import { handler as publishContent } from '../netlify/functions/admin-publish.mjs';
import { handler as published } from '../netlify/functions/portfolio-content.mjs';
import { handler as upload } from '../netlify/functions/admin-upload.mjs';

const ADMIN_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_ID = '22222222-2222-4222-8222-222222222222';
const ORIGIN = 'https://portfolio.test';
const TEST_PASSWORD = crypto.randomBytes(24).toString('base64url');
const MOCK_SERVICE_KEY = crypto.randomBytes(32).toString('hex');
const MOCK_ANON_KEY = crypto.randomBytes(32).toString('hex');
const MOCK_ADMIN_ACCESS = crypto.randomBytes(32).toString('base64url');
const MOCK_ADMIN_REFRESH = crypto.randomBytes(32).toString('base64url');
const MOCK_OTHER_ACCESS = crypto.randomBytes(32).toString('base64url');
const MOCK_OTHER_REFRESH = crypto.randomBytes(32).toString('base64url');
let sessions;
let activeServiceKey;
let authTokens;
let siteContent;
let revoked;
let recordedContentAuth;
let recordedStorageAuth;

function response(status, payload = null) {
  return new Response(payload === null ? null : JSON.stringify(payload), {
    status,
    headers: payload === null ? {} : { 'content-type': 'application/json' },
  });
}

function event(method, path, body, cookie = '', extraHeaders = {}) {
  const headers = { origin: ORIGIN, ...extraHeaders };
  if (cookie) headers.cookie = cookie;
  if (body !== undefined && !headers['content-type']) headers['content-type'] = 'application/json';
  return {
    httpMethod: method,
    rawUrl: `${ORIGIN}/.netlify/functions/${path}`,
    headers,
    body: body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body),
    isBase64Encoded: false,
  };
}

function cookieFrom(result) {
  const value = result.headers['Set-Cookie'];
  assert.ok(value, 'login should set an HttpOnly session cookie');
  return value.split(';')[0];
}

beforeEach(() => {
  process.env.SUPABASE_URL = 'https://mock-project.supabase.co';
  process.env.SUPABASE_ANON_KEY = MOCK_ANON_KEY;
  process.env.SUPABASE_SERVICE_ROLE_KEY = MOCK_SERVICE_KEY;
  activeServiceKey = MOCK_SERVICE_KEY;
  process.env.SUPABASE_ADMIN_EMAIL = 'admin@example.test';
  process.env.SESSION_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
  process.env.ADMIN_USER_IDS = ADMIN_ID;
  process.env.SITE_ORIGIN = ORIGIN;
  process.env.URL = ORIGIN;
  sessions = new Map();
  authTokens = new Map([
    [MOCK_ADMIN_ACCESS, { id: ADMIN_ID, email: 'admin@example.test' }],
    [MOCK_OTHER_ACCESS, { id: OTHER_ID, email: 'other@example.test' }],
  ]);
  siteContent = { draft: { from: 'saved draft' }, published: { from: 'published site' }, updated_at: '2026-01-01T00:00:00.000Z' };
  revoked = [];
  recordedContentAuth = [];
  recordedStorageAuth = [];

  globalThis.fetch = async (input, options = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    const method = String(options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined));
    const auth = headers.get('authorization') || '';
    const requestType = headers.get('content-type') || '';
    const payload = options.body && requestType.includes('application/json')
      ? JSON.parse(Buffer.isBuffer(options.body) ? options.body.toString() : String(options.body))
      : null;

    if (url.pathname === '/auth/v1/token' && url.searchParams.get('grant_type') === 'password' && method === 'POST') {
      if (payload.email === 'admin@example.test' && payload.password === TEST_PASSWORD) {
        return response(200, { access_token: MOCK_ADMIN_ACCESS, refresh_token: MOCK_ADMIN_REFRESH, expires_in: 3600, user: { id: ADMIN_ID, email: payload.email } });
      }
      return response(400, { error: 'invalid_grant' });
    }
    if (url.pathname === '/auth/v1/user' && method === 'GET') {
      const user = authTokens.get(auth.replace(/^Bearer\s+/i, ''));
      return user ? response(200, user) : response(401, { error: 'invalid_token' });
    }
    if (url.pathname === '/auth/v1/token' && url.searchParams.get('grant_type') === 'refresh_token' && method === 'POST') {
      if (payload.refresh_token === MOCK_ADMIN_REFRESH) return response(200, { access_token: MOCK_ADMIN_ACCESS, refresh_token: MOCK_ADMIN_REFRESH, expires_in: 3600, user: { id: ADMIN_ID } });
      return response(400, { error: 'invalid_grant' });
    }
    if (url.pathname === '/auth/v1/logout' && method === 'POST') {
      revoked.push(auth);
      return response(204);
    }
    if (url.pathname === '/rest/v1/admin_sessions') {
      const expectedServiceAuthorization = activeServiceKey.startsWith('sb_secret_') ? '' : `Bearer ${activeServiceKey}`;
      if (headers.get('apikey') !== activeServiceKey || auth !== expectedServiceAuthorization) return response(401, { error: 'service role required' });
      if (method === 'POST') {
        sessions.set(payload.session_hash, payload);
        return response(201);
      }
      const hash = url.searchParams.get('session_hash')?.replace(/^eq\./, '');
      if (method === 'GET') return response(200, sessions.has(hash) ? [sessions.get(hash)] : []);
      if (method === 'PATCH') {
        const row = sessions.get(hash);
        if (row) sessions.set(hash, { ...row, ...payload });
        return response(204);
      }
      if (method === 'DELETE') {
        sessions.delete(hash);
        return response(204);
      }
    }
    if (url.pathname === '/rest/v1/site_content') {
      recordedContentAuth.push({ method, auth, apiKey: headers.get('apikey') });
      if (method === 'GET' && !auth) {
        assert.equal(url.searchParams.get('select'), 'published', 'public read may select only published content');
        return response(200, [{ published: siteContent.published }]);
      }
      const currentUser = authTokens.get(auth.replace(/^Bearer\s+/i, ''));
      if (!currentUser || currentUser.id !== ADMIN_ID || headers.get('apikey') !== MOCK_ANON_KEY) return response(403, { error: 'RLS denied' });
      if (method === 'GET') return response(200, [siteContent]);
      if (method === 'PATCH') {
        siteContent = { ...siteContent, ...payload };
        return response(200, [siteContent]);
      }
    }
    if (url.pathname.startsWith('/storage/v1/object/portfolio-media/') && method === 'POST') {
      recordedStorageAuth.push({ auth, apiKey: headers.get('apikey'), type: headers.get('content-type') });
      const currentUser = authTokens.get(auth.replace(/^Bearer\s+/i, ''));
      if (!currentUser || currentUser.id !== ADMIN_ID || headers.get('apikey') !== MOCK_ANON_KEY) return response(403, { error: 'RLS denied' });
      return response(200, { Key: url.pathname });
    }
    return response(404, { error: `Unexpected mocked request: ${method} ${url.pathname}` });
  };
});

test('login verifies Supabase credentials server-side and returns only an HttpOnly opaque cookie', async () => {
  const bad = await login(event('POST', 'admin-login', { password: TEST_PASSWORD + '-wrong' }));
  assert.equal(bad.statusCode, 401);
  assert.equal(bad.headers['Set-Cookie'], undefined);

  const result = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }));
  assert.equal(result.statusCode, 200);
  assert.deepEqual(JSON.parse(result.body), { ok: true });
  const setCookie = result.headers['Set-Cookie'];
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /SameSite=Strict/);
  assert.match(setCookie, /Path=\//);
  assert.ok(!result.body.includes(MOCK_ADMIN_ACCESS) && !result.body.includes(MOCK_ADMIN_REFRESH) && !result.body.includes(TEST_PASSWORD));
  const cookie = cookieFrom(result);
  assert.match(cookie, /^__Host-portfolio-admin=[0-9a-f]{64}$/);
  assert.equal(sessions.size, 1);
  assert.equal([...sessions.values()][0].user_id, ADMIN_ID);
  assert.ok(![...sessions.values()][0].token_ciphertext.includes(MOCK_ADMIN_ACCESS) && ![...sessions.values()][0].token_ciphertext.includes(MOCK_ADMIN_REFRESH));
});

test('current sb_secret API keys are sent in apikey without an invalid Bearer JWT', async () => {
  activeServiceKey = 'sb_secret_mock_key';
  process.env.SUPABASE_SERVICE_ROLE_KEY = activeServiceKey;
  const result = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }));
  assert.equal(result.statusCode, 200);
  assert.equal(sessions.size, 1);
});

test('valid Supabase credentials are still rejected unless the Auth UUID is allowlisted', async () => {
  process.env.ADMIN_USER_IDS = OTHER_ID;
  const result = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }));
  assert.equal(result.statusCode, 401);
  assert.equal(sessions.size, 0);
  assert.ok(revoked.some((value) => value === `Bearer ${MOCK_ADMIN_ACCESS}`));
});

test('session endpoint validates the opaque cookie without returning tokens', async () => {
  const denied = await session(event('GET', 'admin-session'));
  assert.equal(denied.statusCode, 401);
  const loginResult = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }));
  const cookie = cookieFrom(loginResult);
  const verified = await session(event('GET', 'admin-session', undefined, cookie));
  assert.equal(verified.statusCode, 200);
  assert.deepEqual(JSON.parse(verified.body), { authenticated: true });
  assert.doesNotMatch(verified.body, /access_token|refresh_token/);
});

test('unauthenticated requests cannot read or update admin content', async () => {
  const get = await content(event('GET', 'admin-content'));
  assert.equal(get.statusCode, 401);
  const save = await saveContent(event('POST', 'admin-save', { content: {} }));
  assert.equal(save.statusCode, 401);
  assert.equal(recordedContentAuth.length, 0);
});

test('admin draft Save and Publish use the user JWT so Supabase RLS remains in force', async () => {
  const loginResult = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }));
  const cookie = cookieFrom(loginResult);
  const loaded = await content(event('GET', 'admin-content', undefined, cookie));
  assert.equal(loaded.statusCode, 200);
  assert.deepEqual(JSON.parse(loaded.body).draft, { from: 'saved draft' });
  assert.deepEqual(JSON.parse(loaded.body).published, { from: 'published site' });

  const newContent = { texts: { heading: 'Updated' }, images: {}, links: {}, catalog: { categories: [], works: [] } };
  const saved = await saveContent(event('POST', 'admin-save', { content: newContent }, cookie));
  assert.equal(saved.statusCode, 200);
  assert.deepEqual(siteContent.draft, newContent);
  assert.deepEqual(siteContent.published, { from: 'published site' }, 'Save must not publish drafts');
  assert.ok(recordedContentAuth.some((request) => request.method === 'PATCH' && request.auth === `Bearer ${MOCK_ADMIN_ACCESS}` && request.apiKey === MOCK_ANON_KEY));
  assert.ok(!recordedContentAuth.some((request) => request.auth === `Bearer ${MOCK_SERVICE_KEY}`));

  const publishResult = await publishContent(event('POST', 'admin-publish', { content: newContent }, cookie));
  assert.equal(publishResult.statusCode, 200);
  assert.deepEqual(siteContent.draft, newContent);
  assert.deepEqual(siteContent.published, newContent);
});

test('content writes reject malformed fields and work/category mismatches before contacting the database', async () => {
  const loginResult = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }));
  const cookie = cookieFrom(loginResult);
  const badField = { texts: { heading: 7 }, images: {}, links: {}, catalog: { categories: [], works: [] } };
  const wrongFieldType = await saveContent(event('POST', 'admin-save', { content: badField }, cookie));
  assert.equal(wrongFieldType.statusCode, 400);
  const orphanWork = { texts: {}, images: {}, links: {}, catalog: { categories: [], works: [{ slug: 'orphan', title: 'Orphan', category: 'missing' }] } };
  const mismatchedCategory = await publishContent(event('POST', 'admin-publish', { content: orphanWork }, cookie));
  assert.equal(mismatchedCategory.statusCode, 400);
  assert.equal(recordedContentAuth.length, 0, 'invalid payloads should not reach the content table');
});

test('public content endpoint exposes only published content, never the draft', async () => {
  siteContent.draft = { secretDraft: 'not public' };
  siteContent.published = { publicTitle: 'Visible' };
  const result = await published(event('GET', 'portfolio-content'));
  assert.equal(result.statusCode, 200);
  assert.deepEqual(JSON.parse(result.body), { content: { publicTitle: 'Visible' } });
  assert.doesNotMatch(result.body, /secretDraft/);
});

test('logout deletes the server session, revokes Auth where possible, and clears the cookie', async () => {
  const loginResult = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }));
  const cookie = cookieFrom(loginResult);
  const result = await logout(event('POST', 'admin-logout', undefined, cookie));
  assert.equal(result.statusCode, 200);
  assert.match(result.headers['Set-Cookie'], /Max-Age=0/);
  assert.equal(sessions.size, 0);
  assert.ok(revoked.some((value) => value === `Bearer ${MOCK_ADMIN_ACCESS}`));
  const after = await content(event('GET', 'admin-content', undefined, cookie));
  assert.equal(after.statusCode, 401);
});

test('image uploads require an admin session and use the user JWT (not the service-role key)', async () => {
  const denied = await upload(event('POST', 'admin-upload', 'image-bytes', '', { 'content-type': 'image/png' }));
  assert.equal(denied.statusCode, 401);
  assert.equal(recordedStorageAuth.length, 0);

  const loginResult = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }));
  const cookie = cookieFrom(loginResult);
  const bytes = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const result = await upload({ ...event('POST', 'admin-upload', bytes.toString('base64'), cookie, { 'content-type': 'image/png' }), isBase64Encoded: true });
  assert.equal(result.statusCode, 200);
  const body = JSON.parse(result.body);
  assert.match(body.url, /\/storage\/v1\/object\/public\/portfolio-media\/portfolio\//);
  assert.deepEqual(recordedStorageAuth.at(-1), { auth: `Bearer ${MOCK_ADMIN_ACCESS}`, apiKey: MOCK_ANON_KEY, type: 'image/png' });
});

test('mutating endpoints reject cross-origin requests', async () => {
  const result = await login(event('POST', 'admin-login', { password: TEST_PASSWORD }, '', { origin: 'https://attacker.test' }));
  assert.equal(result.statusCode, 403);
  assert.equal(sessions.size, 0);
});
