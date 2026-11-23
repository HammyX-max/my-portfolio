import crypto from 'node:crypto';
import {
  HttpError,
  clearCookieHeaders,
  jsonResponse,
  loadAdminSession,
  methodNotAllowed,
  publicConfig,
  sameOriginRequest,
} from './_lib/security.mjs';
import { header } from './_lib/security.mjs';

const IMAGE_TYPES = new Map([
  ['image/png', 'png'],
  ['image/jpeg', 'jpg'],
  ['image/webp', 'webp'],
  ['image/gif', 'gif'],
]);

export async function handler(event) {
  if (event.httpMethod !== 'POST') return methodNotAllowed('POST');
  if (!sameOriginRequest(event)) return jsonResponse(403, { error: 'Request origin is not allowed.' });

  try {
    const session = await loadAdminSession(event);
    if (!session) return jsonResponse(401, { error: 'Admin sign-in required.' }, clearCookieHeaders());

    const mimeType = header(event, 'content-type').split(';')[0].trim().toLowerCase();
    const extension = IMAGE_TYPES.get(mimeType);
    if (!extension) return jsonResponse(415, { error: 'Choose a PNG, JPG, WebP, or GIF image.' });
    if (!event.body) return jsonResponse(400, { error: 'The image upload was empty.' });

    const bytes = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64')
      : Buffer.from(event.body, 'utf8');
    if (!bytes.length) return jsonResponse(400, { error: 'The image upload was empty.' });

    const { url, anonKey } = publicConfig();
    const objectPath = `portfolio/${session.userId}/${crypto.randomUUID()}.${extension}`;
    let storageResponse;
    try {
      storageResponse = await fetch(`${url}/storage/v1/object/portfolio-media/${objectPath}`, {
        method: 'POST',
        headers: {
          apikey: anonKey,
          Authorization: `Bearer ${session.accessToken}`,
          'Content-Type': mimeType,
          'Cache-Control': '31536000',
          'x-upsert': 'false',
        },
        body: bytes,
      });
    } catch {
      return jsonResponse(503, { error: 'Supabase Storage is temporarily unavailable.' });
    }
    if (!storageResponse.ok) {
      const status = storageResponse.status === 401 || storageResponse.status === 403 ? 403 : 502;
      return jsonResponse(status, { error: status === 403 ? 'The database policy denied this upload.' : 'Supabase Storage rejected the image upload.' });
    }

    return jsonResponse(200, {
      url: `${url}/storage/v1/object/public/portfolio-media/${objectPath}`,
    });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 503;
    return jsonResponse(status, { error: status === 401 ? 'Admin sign-in required.' : 'Secure image upload is temporarily unavailable.' }, status === 401 ? clearCookieHeaders() : {});
  }
}
