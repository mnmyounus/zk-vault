// app/api/storage/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { randomUUID } from 'crypto';
import { verifySession, supabaseAdmin, presignUpload, presignDownload } from '@/lib/server';

export async function POST(req: NextRequest) {
  const userId = await verifySession(req);
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await req.json();

  if (body.action === 'presign-upload') {
    const objectKey = randomUUID(); // nameless, high-entropy — no relation to the original filename
    const { error } = await supabaseAdmin.from('vault_files').insert({
      owner_id: userId,
      object_key: objectKey,
      envelope_ciphertext: body.envelopeCiphertextB64,
      envelope_iv: body.envelopeIvB64,
      file_iv: body.fileIvB64,
      ciphertext_size: body.ciphertextSize,
      status: 'pending',
      scan_status: body.scanStatus ?? 'unscanned',
    });
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    // CHANGED: Supabase Storage signed uploads hand back a path+token pair,
    // not a plain PUT url — the browser uses uploadToSignedUrl() with these.
    const { path, token } = await presignUpload(objectKey);
    return NextResponse.json({ objectKey, path, token });
  }

  if (body.action === 'confirm') {
    const { error } = await supabaseAdmin
      .from('vault_files')
      .update({ status: 'complete' })
      .eq('object_key', body.objectKey)
      .eq('owner_id', userId);
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json({ ok: true });
  }

  if (body.action === 'presign-download') {
    const { data: file } = await supabaseAdmin
      .from('vault_files')
      .select('object_key, envelope_ciphertext, envelope_iv, file_iv')
      .eq('id', body.fileId)
      .eq('owner_id', userId)
      .maybeSingle();
    if (!file) return NextResponse.json({ error: 'Not found' }, { status: 404 });

    const downloadUrl = await presignDownload(file.object_key);
    return NextResponse.json({
      downloadUrl,
      envelopeCiphertextB64: file.envelope_ciphertext,
      envelopeIvB64: file.envelope_iv,
      fileIvB64: file.file_iv,
    });
  }

  return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
}

export async function GET(req: NextRequest) {
  const userId = await verifySession(req);
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { data, error } = await supabaseAdmin
    .from('vault_files')
    .select('id, envelope_ciphertext, envelope_iv, ciphertext_size, status, scan_status, created_at')
    .eq('owner_id', userId)
    .eq('status', 'complete')
    .order('created_at', { ascending: false });

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ files: data }); // filenames live inside envelope_ciphertext; client decrypts locally
}
