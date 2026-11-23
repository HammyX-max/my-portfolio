import { HttpError, jsonResponse, methodNotAllowed, publicConfig } from './_lib/security.mjs';

export async function handler(event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed('GET');
  try {
    const { url, anonKey } = publicConfig();
    const response = await fetch(`${url}/rest/v1/site_content?id=eq.1&select=published`, {
      headers: { apikey: anonKey, Accept: 'application/json' },
    });
    if (!response.ok) return jsonResponse(503, { error: 'Published portfolio content is temporarily unavailable.' });
    const rows = await response.json();
    const content = Array.isArray(rows) && rows[0] ? rows[0].published : null;
    return jsonResponse(200, { content });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 503;
    return jsonResponse(status, { error: 'Published portfolio content is temporarily unavailable.' });
  }
}
