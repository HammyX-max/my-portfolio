# Portfolio with server-secured Admin Panel

This is the existing single-file portfolio (`index.html`) with the Admin Panel's authentication and persistence moved to Netlify Functions and Supabase. The portfolio layout, motion, contact buttons, Admin tabs, live preview, and editing controls remain in the existing HTML. Supabase credentials and content writes are not handled by browser storage.

## Security model

- The existing seven-click About shortcut is retained as a convenience to open the sign-in dialog; it is **not** an authorization check.
- The existing password-only sign-in UI is retained. The Netlify Function combines the submitted password with `SUPABASE_ADMIN_EMAIL` (a Functions-only environment variable), verifies both through Supabase Auth, and checks the resulting Auth user UUID against `ADMIN_USER_IDS`. The email is not entered in the browser.
- The browser receives only an opaque, random session cookie: `HttpOnly; Secure; SameSite=Strict; Path=/`, with an eight-hour maximum lifetime. Supabase access/refresh tokens are encrypted with AES-256-GCM and stored server-side in `admin_sessions`; the raw session ID is SHA-256 hashed in that table.
- `SUPABASE_SERVICE_ROLE_KEY` is used only by server functions to access the locked session table. Admin content updates and image uploads use the user's Supabase Auth JWT from the encrypted server session and are checked again by Supabase RLS.
- Visitors can read only the published JSON column and public portfolio images. They cannot read drafts, session rows, or write content.
- Logout revokes the Supabase Auth session where available, deletes the server session, and clears the cookie.
- The retired browser-only password/hash/salt check is removed. The old localStorage credential key is cleared. A prior local draft/published-content snapshot is imported to the server only after a successful admin sign-in, then its legacy storage entries are removed.

**Browser limitation:** a password login necessarily sends the password from the admin's browser to the same-origin Netlify Function over HTTPS. The password is not in source code, local/session storage, or a response, but someone controlling that browser can inspect their own request in DevTools. Likewise, an HttpOnly cookie is not readable by page JavaScript, though browser tooling may display cookie headers. A web app cannot make credentials invisible to the person controlling their browser. This implementation keeps Supabase tokens out of frontend JavaScript and response JSON and uses standard TLS + HttpOnly cookie handling.

## Project files

- `index.html` — existing portfolio and Admin UI.
- `netlify/functions/` — `admin-login`, `admin-logout`, `admin-session`, `admin-content` (authenticated read), `admin-save`, `admin-publish`, `admin-upload`, and public `portfolio-content` handlers.
- `supabase/migrations/001_admin_security.sql` — content/session tables, private admin allowlist, JSON shape/catalog relationship constraints, RLS policies, and Storage policies.
- `netlify.toml` — Netlify build, functions, and security headers.
- `scripts/build.mjs` — copies the root `index.html` into Netlify's static publish directory (`dist/`).
- `.env.example` — variable names/placeholders only; contains no real credentials.

## Data model derived from the existing Admin code

The migration matches the data structure already assembled by `catalogFromDOM()`, the Content/Links/Images forms, and the Add/Edit Work forms; it does not introduce a separate, invented portfolio model.

- `public.site_content` is a singleton row (`id = 1`) with `draft` and `published` JSONB documents, `updated_by` referencing `auth.users(id)`, and `updated_at`.
- Each document contains the existing top-level `texts`, `images`, `links`, and `catalog` values. `catalog.categories` stores the existing `slug`, `title`, `note`, and `showOnHome` fields. `catalog.works` stores the existing `slug`, `title`, `category`, `year`, `kind`, `medium`, `role`, `description`, `image`, and optional Process/Result fields (`processMode`, `processImage`, legacy `resultImage`/`hasProcess`) and `imageStyle` settings.
- SQL constraints validate the document shapes, require unique category/work slugs, and ensure every work's `category` matches a category `slug`. This enforces the relationship present in the existing Admin without forcing a redesign of its JSON editing workflow.
- `private.admin_users.user_id` references `auth.users(id)` and is the RLS allowlist. `public.admin_sessions` stores a hash of the opaque cookie ID plus encrypted Auth tokens and expiry; browser roles have no access to it.

## Netlify Function endpoints

All function names below are files under `netlify/functions/`; mutating calls use same-origin POST requests and an HttpOnly session cookie.

- `admin-login` — POST the password; the server adds `SUPABASE_ADMIN_EMAIL` and verifies with Supabase Auth.
- `admin-session` — GET validates the session without returning tokens.
- `admin-logout` — POST revokes/deletes the session and clears the cookie.
- `admin-content` — GET returns the signed-in admin's draft and published documents.
- `admin-save` — POST `{ "content": ... }` saves the draft without publishing.
- `admin-publish` — POST `{ "content": ... }` writes draft and published values.
- `admin-upload` — POST raw PNG/JPG/WebP/GIF bytes; server auth and Storage RLS are checked.
- `portfolio-content` — public GET returns only the published document.

## Supabase setup

1. Create a Supabase project and note its project URL, publishable/anon key, and **service-role secret**. Do not place the service-role key in `index.html`, a public environment variable, or a committed file.
2. In Supabase **Authentication → Settings**, disable public sign-ups after the admin user exists. Configure Auth's password/rate-limit settings and use a unique strong password. Create the admin in **Authentication → Users** (email/password, confirmed) and copy its user UUID. The Admin UI remains password-only; the account email is supplied to the server through `SUPABASE_ADMIN_EMAIL`. Do not put the password in this project.
3. Open **SQL Editor** and run `supabase/migrations/001_admin_security.sql`.
4. In SQL Editor, authorize the account by inserting its UUID into the private allowlist:

   ```sql
   insert into private.admin_users (user_id)
   values ('PASTE_THE_SUPABASE_AUTH_USER_UUID_HERE')
   on conflict (user_id) do nothing;
   ```

   The `private` schema is not exposed to the browser API. The same UUID must be listed in Netlify's `ADMIN_USER_IDS` variable. The existing password-only sign-in is configured for one Auth email in `SUPABASE_ADMIN_EMAIL`; supporting distinct Admin accounts would require an email selector in the login UI.
5. The migration seeds a singleton `site_content` row. First publish starts from the current portfolio content; visitors continue to see the static original content until the first Publish.

## Netlify deployment

1. Push this project to a Git repository and connect it to Netlify. `netlify.toml` configures `npm run build`, `dist/` publishing, and `netlify/functions/` deployment.
2. In **Site configuration → Environment variables**, add these for the **Functions/runtime** scope (and for deploy previews if those previews should have Admin access):

   | Variable | Value |
   | --- | --- |
   | `SUPABASE_URL` | Supabase project URL, e.g. `https://<project-ref>.supabase.co` |
   | `SUPABASE_ANON_KEY` | Supabase publishable/anon key (kept server-side in this app) |
   | `SUPABASE_SERVICE_ROLE_KEY` | Supabase elevated server key: either the legacy `service_role` JWT or current `sb_secret_...` key; functions only. The handler sends `sb_secret_...` as `apikey` only. |
   | `SUPABASE_ADMIN_EMAIL` | Email for the authorized Supabase Auth user; functions only (not entered in the browser) |
   | `SESSION_ENCRYPTION_KEY` | 32 random bytes as 64 hex characters; generate with `openssl rand -hex 32` |
   | `ADMIN_USER_IDS` | Authorized Supabase Auth user UUID(s), comma-separated |
   | `SITE_ORIGIN` | Canonical site origin, e.g. `https://your-site.netlify.app` |

   Keep populated `.env` files out of Git. `.env.example` is safe to copy but contains placeholders only. Netlify's `URL` and `DEPLOY_PRIME_URL` are also accepted when validating same-origin POST requests.
3. Deploy and ensure Netlify HTTPS is enabled. Netlify Functions read these variables at runtime; no Supabase key is injected into the public build.
4. For local function testing, install the Netlify CLI, copy `.env.example` to `.env`, fill it locally, then run `netlify dev`. The `__Host-` cookie requires HTTPS; modern browsers treat `localhost` as a secure context for local development. Never commit `.env`.

## How data is stored

- **Save** writes a private draft row in Supabase; it does not alter the public site.
- **Publish** atomically updates the draft and published JSON values in the singleton row. The public page fetches only `published` from the read-only function.
- **Undo** remains an in-memory Admin history action.
- **Export HTML** still downloads a portable single-file portfolio with the current content baked into the exported file. The export contains no service-role key or password/hash/salt. Admin editing on a separately hosted exported file requires this Netlify Functions backend.
- Replaced images are sent to a Netlify Function, which checks the server session and uploads through Supabase Storage using the user's Auth JWT (RLS applies). The bucket is public-read for portfolio rendering, but only allowlisted admins can write. No app-level file-size check is added; Netlify request and Supabase project/bucket limits still apply.

## Validation

Run the automated server tests and build:

```sh
npm test
npm run build
```

The automated tests use a mocked Supabase Auth/REST/Storage service to exercise the Netlify handlers without real credentials. For final deployment validation, also perform a real sign-in, unauthorized-account rejection, sign-out, draft Save, Publish, visitor-side content fetch, and image upload against your own Supabase project after setting its environment variables and RLS allowlist.
