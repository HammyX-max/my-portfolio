import {
  HttpError,
  adminConfig,
  createServerSession,
  jsonResponse,
  isAuthorizedUser,
  methodNotAllowed,
  publicConfig,
  revokeAuthSession,
  sameOriginRequest,
} from './_lib/security.mjs';

export async function handler(event) {
  if (event.httpMethod !== 'POST') return methodNotAllowed('POST');
  if (!sameOriginRequest(event)) return jsonResponse(403, { error: 'Request origin is not allowed.' });

  let input;
  try { input = JSON.parse(event.body || '{}'); }
  catch { return jsonResponse(400, { error: 'Invalid sign-in request.' }); }
  const password = typeof input.password === 'string' ? input.password : '';
  if (!password || password.length > 1024) return jsonResponse(400, { error: 'Enter the admin password.' });

  try {
    const { url, anonKey } = publicConfig();
    const cfg = adminConfig();
    const authResponse = await fetch(`${url}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: { apikey: anonKey, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ email: cfg.adminEmail, password }),
    });
    let authResult = null;
    try { authResult = await authResponse.json(); } catch {}
    if (!authResponse.ok || !authResult?.access_token || !authResult?.refresh_token || !authResult?.user?.id) {
      return jsonResponse(401, { error: 'Incorrect admin password.' });
    }

    const userId = String(authResult.user.id).toLowerCase();
    const authenticatedEmail = String(authResult.user.email || '').trim().toLowerCase();
    if (authenticatedEmail !== cfg.adminEmail || !isAuthorizedUser(userId, cfg.adminUserIds)) {
      await revokeAuthSession(authResult.access_token);
      return jsonResponse(401, { error: 'Incorrect admin password.' });
    }

    const session = await createServerSession(userId, authResult);
    return jsonResponse(200, { ok: true }, {
      'Set-Cookie': `__Host-portfolio-admin=${session.sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor((session.expiresAt - Date.now()) / 1000)}`,
    });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 503;
    const message = status === 400 ? error.message : 'Secure sign-in is temporarily unavailable.';
    return jsonResponse(status, { error: message });
  }
}
