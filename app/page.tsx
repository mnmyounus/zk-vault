// app/page.tsx
'use client';

import { useEffect, useState } from 'react';
import {
  keyStore,
  deriveMasterKeyPBKDF2,
  sha256Hex,
  encryptFile,
  decryptFile,
  sealEnvelope,
  openEnvelope,
  toHex,
  fromHex,
  bufToB64,
} from '@/lib/crypto';
import { srpLogin, logout } from '@/lib/srp-client';
import { supabasePublic } from '@/lib/supabase-browser';

const BUCKET = 'vault-files';

interface VaultFile {
  id: string;
  name: string;
  size: number;
  mimeType: string;
  createdAt: string;
}

export default function VaultPage() {
  const [unlocked, setUnlocked] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('');
  const [files, setFiles] = useState<VaultFile[]>([]);

  useEffect(() => {
    keyStore.onWipe(() => setUnlocked(false));
  }, []);

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { masterSaltHex } = await srpLogin(passphrase);
      const masterKey = await deriveMasterKeyPBKDF2(passphrase, masterSaltHex);
      keyStore.set(masterKey);
      setPassphrase(''); // drop the plaintext passphrase from component state immediately
      setUnlocked(true);
      await refreshList();
    } catch (err: any) {
      setError(err.message ?? 'Login failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleLockNow() {
    await logout();
    keyStore.wipe();
  }

  async function refreshList() {
    const masterKey = keyStore.get();
    if (!masterKey) return;
    const res = await fetch('/api/storage');
    if (!res.ok) return;
    const { files: rows } = await res.json();
    const decrypted = await Promise.all(
      rows.map(async (row: any) => {
        const meta = await openEnvelope(masterKey, { ciphertextB64: row.envelope_ciphertext, ivB64: row.envelope_iv });
        return { id: row.id, name: `${meta.filename}${meta.extension}`, size: meta.size, mimeType: meta.mimeType, createdAt: row.created_at };
      })
    );
    setFiles(decrypted);
  }

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    const masterKey = keyStore.get();
    if (!file || !masterKey) return;

    try {
      setStatus('Checking for known malware…');
      const hash = await sha256Hex(file);
      const scanRes = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sha256: hash }),
      });
      const scan = await scanRes.json();
      if (scan.verdict === 'malicious') {
        setStatus(`Blocked: ${scan.engineHits}/${scan.engineTotal} engines flagged this file. Upload aborted.`);
        e.target.value = '';
        return;
      }

      setStatus('Encrypting…');
      const { ciphertext, iv, fileKeyRaw } = await encryptFile(file);
      const parts = file.name.split('.');
      const extension = parts.length > 1 ? '.' + parts.pop() : '';
      const filename = parts.join('.');
      const envelope = await sealEnvelope(masterKey, {
        fileKeyHex: toHex(fileKeyRaw),
        filename,
        extension,
        size: file.size,
        mimeType: file.type,
      });

      setStatus('Requesting upload slot…');
      const presign = await fetch('/api/storage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'presign-upload',
          envelopeCiphertextB64: envelope.ciphertextB64,
          envelopeIvB64: envelope.ivB64,
          fileIvB64: bufToB64(iv),
          ciphertextSize: ciphertext.byteLength,
          scanStatus: scan.verdict === 'clean' ? 'clean' : 'unscanned',
        }),
      });
      const { objectKey, path, token } = await presign.json();

      setStatus('Uploading…');
      const ciphertextBlob = new Blob([ciphertext]);
      const { error: uploadError } = await supabasePublic.storage.from(BUCKET).uploadToSignedUrl(path, token, ciphertextBlob);
      if (uploadError) throw new Error(uploadError.message);

      await fetch('/api/storage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'confirm', objectKey }),
      });

      setStatus('Done.');
      e.target.value = '';
      await refreshList();
    } catch (err: any) {
      setStatus(`Upload failed: ${err.message}`);
    }
  }

  async function handleDownload(fileId: string) {
    const masterKey = keyStore.get();
    if (!masterKey) return;

    const res = await fetch('/api/storage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'presign-download', fileId }),
    });
    const { downloadUrl, envelopeCiphertextB64, envelopeIvB64, fileIvB64 } = await res.json();
    const meta = await openEnvelope(masterKey, { ciphertextB64: envelopeCiphertextB64, ivB64: envelopeIvB64 });

    const ciphertext = await (await fetch(downloadUrl)).arrayBuffer();
    const iv = new Uint8Array(atob(fileIvB64).split('').map(c => c.charCodeAt(0)));
    const fileKeyRaw = fromHex(meta.fileKeyHex);
    const plaintext = await decryptFile(ciphertext, iv, fileKeyRaw);

    const blob = new Blob([plaintext], { type: meta.mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${meta.filename}${meta.extension}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (!unlocked) {
    return (
      <main style={{ maxWidth: 340, margin: '4rem auto', padding: '0 1rem' }}>
        <h1>Vault</h1>
        <form onSubmit={handleUnlock}>
          <input
            type="password"
            placeholder="Master passphrase"
            value={passphrase}
            onChange={e => setPassphrase(e.target.value)}
            autoFocus
            style={{ width: '100%', padding: 8, boxSizing: 'border-box' }}
          />
          <button disabled={busy} style={{ width: '100%', marginTop: 8, padding: 8 }}>
            {busy ? 'Unlocking…' : 'Unlock'}
          </button>
        </form>
        {error && <p style={{ color: 'crimson' }}>{error}</p>}
        <p style={{ fontSize: 13 }}><a href="/setup">First time? Create your account →</a></p>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 600, margin: '2rem auto', padding: '0 1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Vault</h1>
        <button onClick={handleLockNow}>Lock</button>
      </div>
      <input type="file" onChange={handleUpload} />
      <p>{status}</p>
      <ul style={{ listStyle: 'none', padding: 0 }}>
        {files.map(f => (
          <li key={f.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #eee' }}>
            <span>{f.name} ({f.size} bytes)</span>
            <button onClick={() => handleDownload(f.id)}>Download</button>
          </li>
        ))}
      </ul>
    </main>
  );
}
