// app/api/setup/route.ts
//
// One-time, self-disabling account creation. This is the ONLY way an
// account can ever be created — there is no other registration path in
// this app. It is safe to leave deployed: sql/schema.sql adds a unique
// index that makes a second row in app_user physically impossible at the
// database level, so a second call always fails with a 409, atomically,
// even under concurrent requests. Delete app/setup and app/api/setup
// afterwards if you'd rather not leave the route reachable at all — purely
// optional, not required for safety.

import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/server';

export async function POST(req: NextRequest) {
  const { username, srpSaltHex, srpVerifierHex, masterSaltHex } = await req.json();
  if (!username || !srpSaltHex || !srpVerifierHex || !masterSaltHex) {
    return NextResponse.json({ error: 'Missing fields' }, { status: 400 });
  }

  const { error } = await supabaseAdmin.from('app_user').insert({
    username,
    srp_salt: srpSaltHex,
    srp_verifier: srpVerifierHex,
    master_salt: masterSaltHex,
  });

  if (error) {
    if ((error as any).code === '23505') {
      // unique_violation — the singleton index already has a row
      return NextResponse.json({ error: 'A vault account already exists' }, { status: 409 });
    }
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ ok: true });
}
