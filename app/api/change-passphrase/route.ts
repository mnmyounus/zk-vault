// app/api/change-passphrase/route.ts
//
// Order matters here for safety: every file's re-wrapped envelope is
// saved FIRST. The account's SRP credentials + master_salt are only
// swapped over if every single file update succeeded. If anything fails
// partway through, the old passphrase is left fully working and nothing
// is left half-migrated — safe to just retry.

import { NextRequest, NextResponse } from 'next/server';
import { verifySession, supabaseAdmin } from '@/lib/server';

export async function POST(req: NextRequest) {
  const userId = await verifySession(req);
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { newSrpSaltHex, newSrpVerifierHex, newMasterSaltHex, fileUpdates } = await req.json();
  if (!newSrpSaltHex || !newSrpVerifierHex || !newMasterSaltHex || !Array.isArray(fileUpdates)) {
    return NextResponse.json({ error: 'Missing fields' }, { status: 400 });
  }

  for (const update of fileUpdates) {
    const { error } = await supabaseAdmin
      .from('vault_files')
      .update({ envelope_ciphertext: update.envelopeCiphertextB64, envelope_iv: update.envelopeIvB64 })
      .eq('id', update.id)
      .eq('owner_id', userId);
    if (error) {
      return NextResponse.json(
        { error: `Failed re-wrapping a file — nothing else changed, your old passphrase still works: ${error.message}` },
        { status: 500 }
      );
    }
  }

  const { error: userError } = await supabaseAdmin
    .from('app_user')
    .update({ srp_salt: newSrpSaltHex, srp_verifier: newSrpVerifierHex, master_salt: newMasterSaltHex })
    .eq('id', userId);
  if (userError) {
    return NextResponse.json(
      { error: `Files were re-wrapped but credentials failed to save: ${userError.message}` },
      { status: 500 }
    );
  }

  return NextResponse.json({ ok: true });
}
