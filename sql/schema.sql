-- sql/schema.sql
-- Zero-Knowledge Vault — Supabase Postgres schema.
-- Run this once in the Supabase SQL editor.

create extension if not exists "pgcrypto";

-- Single-user table. The /api/setup route is the ONLY way a row can ever
-- be inserted, and the unique index below makes a second row physically
-- impossible — any second attempt fails atomically at the database level,
-- regardless of timing or concurrent requests.
create table if not exists app_user (
  id            uuid primary key default gen_random_uuid(),
  username      text unique not null,
  srp_salt      text not null,      -- hex, SRP-6a salt
  srp_verifier  text not null,      -- hex, SRP-6a verifier — never the passphrase
  master_salt   text not null,      -- hex, salt for local PBKDF2/Argon2id key derivation (non-secret)
  created_at    timestamptz not null default now()
);

create unique index if not exists app_user_singleton on app_user ((true));

-- Short-lived slot for the in-progress SRP handshake between step1 and
-- step2. A real table (rather than an in-memory Map) is used because
-- serverless function invocations are not guaranteed to land on the same
-- instance.
create table if not exists pending_login (
  id                       text primary key,
  server_secret_ephemeral  text not null,
  expires_at               timestamptz not null
);

-- One row per uploaded file. The server only ever sees ciphertext and an
-- encrypted metadata envelope — never the plaintext filename or content.
create table if not exists vault_files (
  id                   uuid primary key default gen_random_uuid(),
  owner_id             uuid not null references app_user(id) on delete cascade,
  object_key           text unique not null,  -- random opaque key; the object's name in Supabase Storage
  envelope_ciphertext  text not null,         -- base64: Layer-2 AES-GCM ciphertext (fileKey + filename + ext + size + mime)
  envelope_iv          text not null,         -- base64, 12-byte IV for the Layer-2 envelope
  file_iv              text not null,         -- base64, 12-byte IV for the Layer-1 file ciphertext
  ciphertext_size      bigint not null,       -- size in bytes of the Layer-1 ciphertext object in storage
  status               text not null default 'pending' check (status in ('pending','complete','failed')),
  scan_status          text not null default 'unscanned' check (scan_status in ('unscanned','clean','flagged','skipped')),
  created_at           timestamptz not null default now()
);

create index if not exists idx_vault_files_owner on vault_files(owner_id);

-- Defense in depth on our own tables: enable RLS even though only the
-- service_role key (server-side only, never shipped to the browser) ever
-- touches these. service_role bypasses RLS by design; no policies are
-- defined for anon/authenticated, so a leaked anon key grants nothing here.
alter table app_user enable row level security;
alter table pending_login enable row level security;
alter table vault_files enable row level security;

revoke all on app_user from anon, authenticated;
revoke all on pending_login from anon, authenticated;
revoke all on vault_files from anon, authenticated;

-- Storage policies. Create the "vault-files" bucket first (Storage -> New
-- bucket -> name it vault-files -> keep it Private), then run this.
-- Supabase Storage refuses all operations on a bucket with no policies, so
-- these two are required for the signed-upload/signed-download flow to
-- work at all. They are scoped ONLY to this one bucket, INSERT and SELECT
-- only (no UPDATE, no DELETE). This does not expose file content: nothing
-- is ever listed or fetched by your app without the matching row in
-- vault_files (not exposed to anon) plus your Master Key. The one
-- realistic residual exposure is that someone holding your public anon
-- key could enumerate the random object names in this bucket — harmless,
-- since those names are meaningless without the Postgres row and your key.
create policy "vault bucket insert" on storage.objects
  for insert to anon
  with check (bucket_id = 'vault-files');

create policy "vault bucket select" on storage.objects
  for select to anon
  using (bucket_id = 'vault-files');
