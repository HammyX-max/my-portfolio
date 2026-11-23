-- Portfolio Admin security schema for Supabase.
-- Apply this migration from the Supabase SQL Editor as the project owner.
-- After creating the Auth user, add its UUID to private.admin_users (see README.md).

begin;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists private.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table private.admin_users enable row level security;
revoke all on table private.admin_users from public, anon, authenticated;

create or replace function public.is_portfolio_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from private.admin_users as au
    where au.user_id = (select auth.uid())
  );
$$;
revoke all on function public.is_portfolio_admin() from public;
grant execute on function public.is_portfolio_admin() to anon, authenticated;

create or replace function public.is_valid_portfolio_document(doc jsonb)
returns boolean
language plpgsql
immutable
set search_path = ''
as $$
declare
  category_items jsonb;
  work_items jsonb;
  item jsonb;
  total_count bigint;
  distinct_count bigint;
  value_key text;
begin
  -- Empty documents are reserved for the first-deploy, unpublished state.
  if doc = '{}'::jsonb then return true; end if;
  if doc is null or jsonb_typeof(doc) is distinct from 'object' then return false; end if;
  if jsonb_typeof(doc->'texts') is distinct from 'object'
     or jsonb_typeof(doc->'images') is distinct from 'object'
     or jsonb_typeof(doc->'links') is distinct from 'object'
     or jsonb_typeof(doc->'catalog') is distinct from 'object' then return false; end if;
  category_items := doc #> '{catalog,categories}';
  work_items := doc #> '{catalog,works}';
  if jsonb_typeof(category_items) is distinct from 'array'
     or jsonb_typeof(work_items) is distinct from 'array' then return false; end if;

  if exists (select 1 from jsonb_each(doc->'texts') as e(key, value) where jsonb_typeof(e.value) is distinct from 'string')
     or exists (select 1 from jsonb_each(doc->'images') as e(key, value) where jsonb_typeof(e.value) is distinct from 'string')
     or exists (select 1 from jsonb_each(doc->'links') as e(key, value) where jsonb_typeof(e.value) is distinct from 'string') then return false; end if;

  for item in select value from jsonb_array_elements(category_items) as x(value) loop
    if jsonb_typeof(item) is distinct from 'object'
       or jsonb_typeof(item->'slug') is distinct from 'string'
       or length(btrim(item->>'slug')) = 0
       or jsonb_typeof(item->'title') is distinct from 'string'
       or length(btrim(item->>'title')) = 0 then return false; end if;
    if item ? 'note' and jsonb_typeof(item->'note') is distinct from 'string' then return false; end if;
    if item ? 'showOnHome' and jsonb_typeof(item->'showOnHome') is distinct from 'boolean' then return false; end if;
  end loop;
  select count(*), count(distinct value->>'slug') into total_count, distinct_count
    from jsonb_array_elements(category_items) as x(value);
  if total_count <> distinct_count then return false; end if;

  for item in select value from jsonb_array_elements(work_items) as x(value) loop
    if jsonb_typeof(item) is distinct from 'object'
       or jsonb_typeof(item->'slug') is distinct from 'string'
       or length(btrim(item->>'slug')) = 0
       or jsonb_typeof(item->'title') is distinct from 'string'
       or length(btrim(item->>'title')) = 0
       or jsonb_typeof(item->'category') is distinct from 'string'
       or length(btrim(item->>'category')) = 0 then return false; end if;
    foreach value_key in array array['year','kind','medium','role','description','image','resultImage','processImage'] loop
      if item ? value_key and jsonb_typeof(item->value_key) is distinct from 'string' then return false; end if;
    end loop;
    if item ? 'processMode' and (jsonb_typeof(item->'processMode') is distinct from 'string' or item->>'processMode' not in ('with-process','without-process','with','without')) then return false; end if;
    if item ? 'hasProcess' and jsonb_typeof(item->'hasProcess') is distinct from 'boolean' then return false; end if;
    if item ? 'imageStyle' and jsonb_typeof(item->'imageStyle') is distinct from 'object' then return false; end if;
  end loop;
  select count(*), count(distinct value->>'slug') into total_count, distinct_count
    from jsonb_array_elements(work_items) as x(value);
  if total_count <> distinct_count then return false; end if;
  -- This is the website's catalog relationship: each work.category must match one category.slug.
  if exists (
    select 1 from jsonb_array_elements(work_items) as witem(value)
    where not exists (
      select 1 from jsonb_array_elements(category_items) as cat(value)
      where cat.value->>'slug' = witem.value->>'category'
    )
  ) then return false; end if;
  return true;
exception when others then
  return false;
end;
$$;
revoke all on function public.is_valid_portfolio_document(jsonb) from public;
grant execute on function public.is_valid_portfolio_document(jsonb) to authenticated;

create table if not exists public.site_content (
  id smallint primary key check (id = 1),
  draft jsonb not null default '{}'::jsonb,
  published jsonb not null default '{}'::jsonb,
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.site_content drop constraint if exists site_content_draft_valid;
alter table public.site_content add constraint site_content_draft_valid check (public.is_valid_portfolio_document(draft));
alter table public.site_content drop constraint if exists site_content_published_valid;
alter table public.site_content add constraint site_content_published_valid check (public.is_valid_portfolio_document(published));
insert into public.site_content (id, draft, published)
values (1, '{}'::jsonb, '{}'::jsonb)
on conflict (id) do nothing;

alter table public.site_content enable row level security;
revoke all on table public.site_content from public, anon, authenticated;
-- Visitors can read only the published column; the draft column is not granted to anon.
grant select (id, published, updated_at) on public.site_content to anon;
-- Authenticated users receive SQL privileges, but RLS still limits them to listed admin UUIDs.
grant select (id, draft, published, updated_by, updated_at) on public.site_content to authenticated;
grant update (draft, published, updated_by, updated_at) on public.site_content to authenticated;

drop policy if exists "Public can read published portfolio content" on public.site_content;
create policy "Public can read published portfolio content"
on public.site_content
for select to anon
using (published is not null);

drop policy if exists "Portfolio admins can read site content" on public.site_content;
create policy "Portfolio admins can read site content"
on public.site_content
for select to authenticated
using ((select public.is_portfolio_admin()));

drop policy if exists "Portfolio admins can update site content" on public.site_content;
create policy "Portfolio admins can update site content"
on public.site_content
for update to authenticated
using ((select public.is_portfolio_admin()))
with check ((select public.is_portfolio_admin()) and updated_by = (select auth.uid()));

-- Restrictive policies prevent any additional permissive project policies from
-- accidentally making drafts visible or allowing non-admin content writes.
drop policy if exists "Restrict site content to listed admins" on public.site_content;
create policy "Restrict site content to listed admins"
on public.site_content as restrictive
for all to authenticated
using ((select public.is_portfolio_admin()))
with check ((select public.is_portfolio_admin()));

drop policy if exists "Restrict anonymous reads to published content" on public.site_content;
create policy "Restrict anonymous reads to published content"
on public.site_content as restrictive
for select to anon
using (published is not null);

-- Opaque browser session IDs are SHA-256 hashed before storage. Supabase Auth
-- access/refresh tokens are AES-256-GCM encrypted by Netlify Functions.
-- This table is not readable/writable by anon or authenticated API clients.
create table if not exists public.admin_sessions (
  session_hash text primary key check (session_hash ~ '^[0-9a-f]{64}$'),
  user_id uuid not null references auth.users(id) on delete cascade,
  token_ciphertext text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
alter table public.admin_sessions enable row level security;
alter table public.admin_sessions force row level security;
revoke all on table public.admin_sessions from public, anon, authenticated;
grant all on table public.admin_sessions to service_role;

-- Portfolio images are public because the portfolio itself is public. Only
-- listed admins can write to the bucket; browser code never receives the
-- Supabase service-role key or a signed upload token.
insert into storage.buckets (id, name, public)
values ('portfolio-media', 'portfolio-media', true)
on conflict (id) do update set public = true;

drop policy if exists "Portfolio media is publicly readable" on storage.objects;
create policy "Portfolio media is publicly readable"
on storage.objects
for select to public
using (bucket_id = 'portfolio-media');

drop policy if exists "Portfolio admins can upload media" on storage.objects;
create policy "Portfolio admins can upload media"
on storage.objects
for insert to authenticated
with check (bucket_id = 'portfolio-media' and (select public.is_portfolio_admin()));

drop policy if exists "Portfolio admins can update media" on storage.objects;
create policy "Portfolio admins can update media"
on storage.objects
for update to authenticated
using (bucket_id = 'portfolio-media' and (select public.is_portfolio_admin()))
with check (bucket_id = 'portfolio-media' and (select public.is_portfolio_admin()));

drop policy if exists "Portfolio admins can delete media" on storage.objects;
create policy "Portfolio admins can delete media"
on storage.objects
for delete to authenticated
using (bucket_id = 'portfolio-media' and (select public.is_portfolio_admin()));

-- These restrictive policies keep any unrelated permissive Storage rules from
-- granting non-admin write access to the portfolio bucket.
drop policy if exists "Restrict portfolio media inserts to admins" on storage.objects;
create policy "Restrict portfolio media inserts to admins"
on storage.objects as restrictive
for insert to public
with check (bucket_id <> 'portfolio-media' or (select public.is_portfolio_admin()));

drop policy if exists "Restrict portfolio media updates to admins" on storage.objects;
create policy "Restrict portfolio media updates to admins"
on storage.objects as restrictive
for update to public
using (bucket_id <> 'portfolio-media' or (select public.is_portfolio_admin()))
with check (bucket_id <> 'portfolio-media' or (select public.is_portfolio_admin()));

drop policy if exists "Restrict portfolio media deletes to admins" on storage.objects;
create policy "Restrict portfolio media deletes to admins"
on storage.objects as restrictive
for delete to public
using (bucket_id <> 'portfolio-media' or (select public.is_portfolio_admin()));

commit;
