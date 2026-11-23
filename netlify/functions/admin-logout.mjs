import {
  clearCookieHeaders,
  deleteServerSession,
  hashSessionId,
  jsonResponse,
  loadAdminSession,
  readCookie,
  revokeAuthSession,
  sameOriginRequest,
} from './_lib/security.mjs';

export async function handler(event) {
  if (event.httpMethod !== 'POST') return jsonResponse(405, { error: 'Method not allowed.' }, { Allow: 'POST' });
  if (!sameOriginRequest(event)) return jsonResponse(403, { error: 'Request origin is not allowed.' }, clearCookieHeaders());

  const sessionId = readCookie(event);
  try {
    const session = await loadAdminSession(event);
    if (session) await revokeAuthSession(session.accessToken);
  } catch {
    // Always clear the browser cookie, even if Supabase is temporarily unreachable.
  }
  if (/^[0-9a-f]{64}$/i.test(sessionId)) {
    try { await deleteServerSession(hashSessionId(sessionId)); } catch {}
  }
  return jsonResponse(200, { ok: true }, clearCookieHeaders());
}
