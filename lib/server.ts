// lib/server.ts
// Server-only infrastructure. CHANGED: storage now uses Supabase Storage's
// own signed-URL API instead of Cloudflare R2 — no second account, no
// credit card, one fewer service to configure. Everything else (session,
// SRP) is unchanged.

import 'server-only';
import { createClient } from '@supabase/supabase-js';
import { createSRPServer } from '@swan-io/srp';
import { SignJWT, jwtVerify } from 'jose';
import type { NextRequest } from 'next/server';

// ---------- Supabase (service role — bypasses RLS; server only, never NEXT_PUBLIC_) ----------

export const supabaseAdmin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
  auth: { persistSession: false },
});

// ---------- Object storage: a private bucket inside the same Supabase project ----------

const BUCKET = 'vault-files';
const PRESIGN_TTL_SECONDS = 300;

export async function presignUpload(objectKey: string) {
  const { data, error } = await supabaseAdmin.storage.from(BUCKET).createSignedUploadUrl(objectKey);
  if (error) throw error;
  return { path: data.path, token: data.token }; // browser uses these with uploadToSignedUrl(), not a raw PUT
}

export async function presignDownload(objectKey: string) {
  const { data, error } = await supabaseAdmin.storage.from(BUCKET).createSignedUrl(objectKey, PRESIGN_TTL_SECONDS);
  if (error) throw error;
  return data.signedUrl;
}

// ---------- Session (short-lived JWT cookie, ProtonMail-style) ----------

const SESSION_COOKIE = 'zkv_session';
const SESSION_TTL_SECONDS = 15 * 60;
const secret = () => new TextEncoder().encode(process.env.SESSION_JWT_SECRET!);

export async function createSessionCookie(userId: string) {
  const token = await new SignJWT({ sub: userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .sign(secret());
  return {
    name: SESSION_COOKIE,
    value: token,
    httpOnly: true,
    secure: true,
    sameSite: 'strict' as const,
    path: '/',
    maxAge: SESSION_TTL_SECONDS,
  };
}

export async function verifySession(req: NextRequest): Promise<string | null> {
  const token = req.cookies.get(SESSION_COOKIE)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, secret());
    return (payload.sub as string) ?? null;
  } catch {
    return null;
  }
}

export const clearSessionCookie = () => ({ name: SESSION_COOKIE, value: '', path: '/', maxAge: 0 });

// ---------- SRP-6a server half ----------
// The server stores only srp_salt + srp_verifier — never the passphrase.

export const srpServer = createSRPServer('SHA-256', 2048);

const PENDING_LOGIN_ID = 'primary'; // single-user app: one fixed handshake slot

export async function getSingleUser() {
  const { data } = await supabaseAdmin
    .from('app_user')
    .select('id, srp_salt, srp_verifier, master_salt')
    .limit(1)
    .maybeSingle();
  return data;
}

export async function storePendingLogin(serverSecretEphemeral: string) {
  await supabaseAdmin.from('pending_login').upsert({
    id: PENDING_LOGIN_ID,
    server_secret_ephemeral: serverSecretEphemeral,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
}

export async function takePendingLogin(): Promise<string | null> {
  const { data } = await supabaseAdmin
    .from('pending_login')
    .select('server_secret_ephemeral, expires_at')
    .eq('id', PENDING_LOGIN_ID)
    .maybeSingle();
  await supabaseAdmin.from('pending_login').delete().eq('id', PENDING_LOGIN_ID);
  if (!data || new Date(data.expires_at) < new Date()) return null;
  return data.server_secret_ephemeral;
}
