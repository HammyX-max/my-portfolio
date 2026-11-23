import {
  HttpError,
  clearCookieHeaders,
  jsonResponse,
  loadAdminSession,
  methodNotAllowed,
} from './_lib/security.mjs';

export async function handler(event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed('GET');
  try {
    const session = await loadAdminSession(event);
    if (!session) return jsonResponse(401, { authenticated: false }, clearCookieHeaders());
    return jsonResponse(200, { authenticated: true });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 503;
    return jsonResponse(status, { authenticated: false, error: 'Secure session verification is temporarily unavailable.' });
  }
}
