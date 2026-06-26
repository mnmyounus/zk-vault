// app/api/scan/route.ts
//
// Pre-flight malware check, run before encryption. Two paths, dispatched
// by content-type:
//
// 1. hash-lookup (default, application/json body): the browser computes
//    SHA-256 of the PLAINTEXT file locally and sends ONLY the hash — never
//    the file content. We look it up against VirusTotal's database of
//    previously-analyzed samples. A miss means "not previously scanned,"
//    not "safe" — this only catches already-known malware, but nothing
//    more than a 64-character hash ever leaves the device.
//
// 2. full-scan (opt-in only, multipart/form-data body, must be triggered
//    by an explicit user action behind a clear UI warning): forwards the
//    PLAINTEXT file to VirusTotal for a fresh scan. This is a deliberate,
//    visible exception to the zero-knowledge guarantee — VirusTotal (a
//    third party) sees the file content. Never call this path silently.
//    Also subject to the Vercel Hobby body-size/timeout limits, since the
//    file passes through this function — only practical for small files.

import { NextRequest, NextResponse } from 'next/server';
import { verifySession } from '@/lib/server';

export const maxDuration = 10;

export async function POST(req: NextRequest) {
  const userId = await verifySession(req);
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const apiKey = process.env.VIRUSTOTAL_API_KEY!;
  const contentType = req.headers.get('content-type') ?? '';

  if (contentType.includes('multipart/form-data')) {
    const formData = await req.formData();
    const file = formData.get('file') as File | null;
    if (!file) return NextResponse.json({ error: 'No file provided' }, { status: 400 });

    const upstream = new FormData();
    upstream.append('file', file);
    const vtRes = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: { 'x-apikey': apiKey },
      body: upstream,
    });
    if (!vtRes.ok) return NextResponse.json({ error: 'Scan submission failed' }, { status: 502 });
    const { data } = await vtRes.json();
    return NextResponse.json({ analysisId: data.id }); // poll GET .../api/v3/analyses/{id} for the verdict
  }

  const { sha256 } = await req.json();
  if (!/^[a-f0-9]{64}$/i.test(sha256)) {
    return NextResponse.json({ error: 'Invalid hash' }, { status: 400 });
  }

  const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
    headers: { 'x-apikey': apiKey },
  });
  if (vtRes.status === 404) return NextResponse.json({ verdict: 'unknown' });
  if (!vtRes.ok) return NextResponse.json({ error: 'Scan service unavailable' }, { status: 502 });

  const body = await vtRes.json();
  const stats = body.data.attributes.last_analysis_stats;
  const hits = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
  const total = Object.values(stats).reduce((a: number, b: any) => a + b, 0);

  return NextResponse.json({ verdict: hits > 0 ? 'malicious' : 'clean', engineHits: hits, engineTotal: total });
}
