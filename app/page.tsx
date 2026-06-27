// app/page.tsx
'use client';

import { useState } from 'react';
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

  // The file list is collapsed by default: the page only ever shows a
  // count fetched from Postgres. Names and download buttons only appear
  // after an explicit tap, and only after decrypting the envelopes in
  // this browser with the in-memory Master Key — nothing extra is ever
  // sent to, or held by, the server to make that possible.
  const [rawFiles, setRawFiles] = useState<any[]>([]);
  const [decryptedFiles, setDecryptedFiles] = useState<VaultFile[]>([]);
  const [revealed, setRevealed] = useState(false);

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { masterSaltHex } = await srpLogin(passphrase);
      const masterKey = await deriveMasterKeyPBKDF2(passphrase, masterSaltHex);
      keyStore.set(masterKey);
      keyStore.onWipe(() => setUnlocked(false));
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
    setRevealed(false);
    setDecryptedFiles([]);
  }

  async function refreshList() {
    const res = await fetch('/api/storage');
    if (!res.ok) return;
    const { files: rows } = await res.json();
    setRawFiles(rows);
    if (revealed) await decryptAll(rows);
  }

  async function decryptAll(rows: any[]) {
    const masterKey = keyStore.get();
    if (!masterKey) return;
    const decrypted = await Promise.all(
      rows.map(async (row: any) => {
        const meta = await openEnvelope(masterKey, { ciphertextB64: row.envelope_ciphertext, ivB64: row.envelope_iv });
        return { id: row.id, name: `${meta.filename}${meta.extension}`, size: meta.size, mimeType: meta.mimeType, createdAt: row.created_at };
      })
    );
    setDecryptedFiles(decrypted);
  }

  async function handleReveal() {
    await decryptAll(rawFiles);
    setRevealed(true);
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
        setStatus(`Blocked — ${scan.engineHits}/${scan.engineTotal} engines flagged this file.`);
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
    const iv = new Uint8Array(atob(fileIvB64).split('').map(c => c.charCodeAt(0))) as Uint8Array<ArrayBuffer>;
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
      <main className="vault-shell">
        <div className="vault-plate">
          <p className="vault-eyebrow">Personal vault</p>
          <h1 className="vault-heading">Vault</h1>
          <form onSubmit={handleUnlock}>
            <input
              className="field"
              type="password"
              placeholder="Master passphrase"
              value={passphrase}
              onChange={e => setPassphrase(e.target.value)}
              autoFocus
            />
            <button className="btn" disabled={busy}>
              {busy ? 'Unlocking…' : 'Unlock'}
            </button>
          </form>
          {error && <p className="error-text">{error}</p>}
          <p className="hint-text">
            First time? <a href="/setup">Create your account →</a>
          </p>
        </div>
      </main>
    );
  }

  return (
    <main className="vault-shell">
      <div className="vault-plate">
        <div className="vault-header">
          <h1 className="vault-heading" style={{ marginBottom: 0 }}>
            Vault
          </h1>
          <button className="btn-ghost" onClick={handleLockNow}>
            Lock
          </button>
        </div>

        <input type="file" onChange={handleUpload} />
        <div className="ledger">
          {status && <span className="ledger-dot" />}
          {status}
        </div>

        <div className="count-row">
          <div>
            <div className="count-number">{rawFiles.length}</div>
            <div className="count-label">file{rawFiles.length === 1 ? '' : 's'} stored, encrypted</div>
          </div>
          <button className="btn-ghost" onClick={revealed ? () => setRevealed(false) : handleReveal} disabled={rawFiles.length === 0}>
            {revealed ? 'Hide' : 'Show files'}
          </button>
        </div>

        {revealed && (
          <ul className="file-list">
            {decryptedFiles.map(f => (
              <li key={f.id} className="file-row">
                <div>
                  <div className="file-name">{f.name}</div>
                  <div className="file-meta">{f.size.toLocaleString()} bytes</div>
                </div>
                <button className="btn-ghost" onClick={() => handleDownload(f.id)}>
                  Download
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}
