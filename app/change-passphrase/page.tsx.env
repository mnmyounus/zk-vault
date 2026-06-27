// app/change-passphrase/page.tsx
'use client';

import { useState } from 'react';
import { createSRPClient } from '@swan-io/srp';
import { deriveMasterKeyPBKDF2, openEnvelope, sealEnvelope, randomBytes, toHex } from '@/lib/crypto';
import { srpLogin } from '@/lib/srp-client';

const srp = createSRPClient('SHA-256', 2048);

export default function ChangePassphrasePage() {
  const [oldPassphrase, setOldPassphrase] = useState('');
  const [newPassphrase, setNewPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (newPassphrase.length < 12) {
      setStatus('New passphrase should be 12+ characters.');
      return;
    }
    if (newPassphrase !== confirm) {
      setStatus('New passphrases do not match.');
      return;
    }
    if (newPassphrase === oldPassphrase) {
      setStatus('New passphrase must be different from the current one.');
      return;
    }

    setBusy(true);
    try {
      setStatus('Verifying current passphrase…');
      const { masterSaltHex: oldSaltHex } = await srpLogin(oldPassphrase);
      const oldMasterKey = await deriveMasterKeyPBKDF2(oldPassphrase, oldSaltHex);

      setStatus('Fetching your file list…');
      const listRes = await fetch('/api/storage');
      if (!listRes.ok) throw new Error('Could not fetch file list');
      const { files } = await listRes.json();

      setStatus(`Re-wrapping ${files.length} file key${files.length === 1 ? '' : 's'} locally…`);
      const newSaltHex = toHex(randomBytes(16));
      const newMasterSaltHex = toHex(randomBytes(16));
      const newMasterKey = await deriveMasterKeyPBKDF2(newPassphrase, newMasterSaltHex);

      // Only the small envelope (file key + filename/size/type) gets
      // decrypted and re-sealed here — the actual file ciphertext in
      // storage is never touched, never re-uploaded.
      const fileUpdates = await Promise.all(
        files.map(async (row: any) => {
          const meta = await openEnvelope(oldMasterKey, { ciphertextB64: row.envelope_ciphertext, ivB64: row.envelope_iv });
          const newEnvelope = await sealEnvelope(newMasterKey, meta);
          return { id: row.id, envelopeCiphertextB64: newEnvelope.ciphertextB64, envelopeIvB64: newEnvelope.ivB64 };
        })
      );

      setStatus('Computing new account credentials…');
      const newPrivateKey = await srp.deriveSafePrivateKey(newSaltHex, newPassphrase);
      const newVerifierHex = await srp.deriveVerifier(newPrivateKey);

      setStatus('Saving…');
      const res = await fetch('/api/change-passphrase', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          newSrpSaltHex: newSaltHex,
          newSrpVerifierHex: newVerifierHex,
          newMasterSaltHex,
          fileUpdates,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error ?? 'Save failed — nothing was changed, your old passphrase still works.');
      }

      setOldPassphrase('');
      setNewPassphrase('');
      setConfirm('');
      setDone(true);
    } catch (err: any) {
      setStatus(err.message ?? 'Failed — your old passphrase should still work.');
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <main className="vault-shell">
        <div className="vault-plate">
          <p className="vault-eyebrow">Personal vault</p>
          <h1 className="vault-heading">Passphrase changed</h1>
          <p className="vault-copy">Every file's key is re-wrapped under the new passphrase. Unlock with it from now on.</p>
          <p className="hint-text">
            Any offline-decrypt export files you made before today still need the OLD passphrase to open — re-export
            after this if you want fresh copies.
          </p>
          <p className="hint-text">
            <a href="/">Go to vault →</a>
          </p>
        </div>
      </main>
    );
  }

  return (
    <main className="vault-shell">
      <div className="vault-plate">
        <p className="vault-eyebrow">Personal vault</p>
        <h1 className="vault-heading">Change passphrase</h1>
        <p className="vault-copy">
          Re-encrypts every file's key, locally, in this browser. Your files themselves are never touched or
          re-uploaded — only the small wrapped key for each one.
        </p>
        <form onSubmit={handleSubmit}>
          <input
            className="field"
            type="password"
            placeholder="Current passphrase"
            value={oldPassphrase}
            onChange={e => setOldPassphrase(e.target.value)}
          />
          <input
            className="field"
            type="password"
            placeholder="New passphrase"
            value={newPassphrase}
            onChange={e => setNewPassphrase(e.target.value)}
          />
          <input
            className="field"
            type="password"
            placeholder="Confirm new passphrase"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
          />
          <button className="btn" disabled={busy}>
            {busy ? 'Working…' : 'Change passphrase'}
          </button>
        </form>
        {status && <p className="error-text">{status}</p>}
      </div>
    </main>
  );
}
