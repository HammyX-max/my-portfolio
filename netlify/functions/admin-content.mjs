import {
  HttpError,
  clearCookieHeaders,
  jsonResponse,
  loadAdminSession,
  methodNotAllowed,
  sameOriginRequest,
  userRestRequest,
} from './_lib/security.mjs';

async function readJson(response) {
  try { return await response.json(); } catch { return null; }
}

async function authorize(event) {
  const session = await loadAdminSession(event);
  if (!session) return { response: jsonResponse(401, { error: 'Admin sign-in required.' }, clearCookieHeaders()) };
  return { session };
}

export async function readAdminContent(event) {
  if (event.httpMethod !== 'GET') return methodNotAllowed('GET');
  try {
    const auth = await authorize(event);
    if (auth.response) return auth.response;
    const response = await userRestRequest(auth.session, 'GET', 'site_content?id=eq.1&select=draft,published,updated_at');
    const rows = await readJson(response);
    if (response.status === 401) return jsonResponse(401, { error: 'Admin session expired.' }, clearCookieHeaders());
    if (response.status === 403) return jsonResponse(403, { error: 'This account is not authorized by the database policy.' });
    if (!response.ok) return jsonResponse(503, { error: 'Could not load the site content from Supabase.' });
    if (!Array.isArray(rows) || !rows[0]) return jsonResponse(503, { error: 'Site content is not initialized. Apply the Supabase SQL setup.' });
    return jsonResponse(200, {
      draft: rows[0].draft || {},
      published: rows[0].published || {},
      updatedAt: rows[0].updated_at || null,
    });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 503;
    return jsonResponse(status, { error: status === 503 ? 'Secure content service is temporarily unavailable.' : error.message });
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validPortfolioContent(content) {
  if (!isRecord(content) || !isRecord(content.texts) || !isRecord(content.images) || !isRecord(content.links) || !isRecord(content.catalog)) return false;
  if (![content.texts, content.images, content.links].every(map => Object.values(map).every(value => typeof value === 'string'))) return false;
  const categories = content.catalog.categories, works = content.catalog.works;
  if (!Array.isArray(categories) || !Array.isArray(works)) return false;
  const categorySlugs = new Set();
  for (const category of categories) {
    if (!isRecord(category) || typeof category.slug !== 'string' || !category.slug.trim() || typeof category.title !== 'string' || !category.title.trim()) return false;
    if (categorySlugs.has(category.slug)) return false;
    categorySlugs.add(category.slug);
    if (category.note !== undefined && typeof category.note !== 'string') return false;
    if (category.showOnHome !== undefined && typeof category.showOnHome !== 'boolean') return false;
  }
  const workSlugs = new Set();
  for (const work of works) {
    if (!isRecord(work) || typeof work.slug !== 'string' || !work.slug.trim() || typeof work.title !== 'string' || !work.title.trim() || typeof work.category !== 'string' || !categorySlugs.has(work.category)) return false;
    if (workSlugs.has(work.slug)) return false;
    workSlugs.add(work.slug);
    for (const key of ['year', 'kind', 'medium', 'role', 'description', 'image', 'resultImage', 'processImage']) if (work[key] !== undefined && typeof work[key] !== 'string') return false;
    if (work.processMode !== undefined && !['with-process', 'without-process', 'with', 'without'].includes(work.processMode)) return false;
    if (work.hasProcess !== undefined && typeof work.hasProcess !== 'boolean') return false;
    if (work.imageStyle !== undefined && !isRecord(work.imageStyle)) return false;
  }
  return true;
}

export async function writeAdminContent(event, action) {
  if (event.httpMethod !== 'POST') return methodNotAllowed('POST');
  if (!['save', 'publish'].includes(action)) return jsonResponse(400, { error: 'Invalid content action.' });
  if (!sameOriginRequest(event)) return jsonResponse(403, { error: 'Request origin is not allowed.' });

  try {
    const auth = await authorize(event);
    if (auth.response) return auth.response;
    let input;
    try { input = JSON.parse(event.body || '{}'); }
    catch { return jsonResponse(400, { error: 'Invalid content update.' }); }
    const content = input?.content;
    if (!validPortfolioContent(content)) return jsonResponse(400, { error: 'Invalid portfolio content.' });

    const now = new Date().toISOString();
    const update = { draft: content, updated_by: auth.session.userId, updated_at: now };
    if (action === 'publish') update.published = content;
    const response = await userRestRequest(auth.session, 'PATCH', 'site_content?id=eq.1', update, 'return=representation');
    const rows = await readJson(response);
    if (response.status === 401) return jsonResponse(401, { error: 'Admin session expired.' }, clearCookieHeaders());
    if (response.status === 403) return jsonResponse(403, { error: 'This account is not authorized by the database policy.' });
    if (!response.ok) return jsonResponse(503, { error: 'Supabase rejected the content update. Check the database setup and RLS policies.' });
    if (!Array.isArray(rows) || !rows.length) return jsonResponse(503, { error: 'The site content row is missing. Apply the Supabase SQL setup.' });
    return jsonResponse(200, { ok: true, action, updatedAt: now });
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 503;
    return jsonResponse(status, { error: status === 503 ? 'Secure content service is temporarily unavailable.' : error.message });
  }
}

export async function handler(event) {
  return readAdminContent(event);
}
