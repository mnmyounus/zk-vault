// app/setup/page.tsx
'use client';

import { useState } from 'react';
import { createSRPClient } from '@swan-io/srp';
import { randomBytes, toHex } from '@/lib/crypto';

const srp = createSRPClient('SHA-256', 2048);

export default function SetupPage() {
  const [username, setUsername] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [status, setStatus] = useState('');
  const [done, setDone] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (passphrase.length < 12) {
      setStatus('Use a longer passphrase — 12 characters or more.');
      return;
    }
    if (passphrase !== confirm) {
      setStatus('Passphrases do not match.');
      return;
    }

    setStatus('Generating credentials locally…');
    const srpSaltHex = toHex(randomBytes(16));
    const masterSaltHex = toHex(randomBytes(16));
    const privateKey = await srp.deriveSafePrivateKey(srpSaltHex, passphrase);
    const srpVerifierHex = await srp.deriveVerifier(privateKey);
    // the passphrase itself never leaves this point — only the two values above do

    const res = await fetch('/api/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, srpSaltHex, srpVerifierHex, masterSaltHex }),
    });

    if (res.status === 409) {
      setStatus('A vault account already exists. This page only ever works once.');
      return;
    }
    if (!res.ok) {
      setStatus('Setup failed — check the server logs.');
      return;
    }

    setPassphrase('');
    setConfirm('');
    setDone(true);
  }

  if (done) {
    return (
      <main className="vault-shell">
        <div className="vault-plate">
          <p className="vault-eyebrow">Personal vault</p>
          <h1 className="vault-heading">Account created</h1>
          <p className="vault-copy">Go to the home page and unlock it with your passphrase.</p>
          <p className="hint-text">
            This page will refuse to run again. Delete <code>app/setup</code> and{' '}
            <code>app/api/setup</code> whenever you like — it's no longer needed.
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
        <h1 className="vault-heading">One-time setup</h1>
        <p className="vault-copy">
          This only works if no account exists yet. Your passphrase is never sent anywhere — only a
          cryptographic proof derived from it is.
        </p>
        <form onSubmit={handleSubmit}>
          <input
            className="field"
            placeholder="Username (any identifier)"
            value={username}
            onChange={e => setUsername(e.target.value)}
          />
          <input
            className="field"
            type="password"
            placeholder="Master passphrase"
            value={passphrase}
            onChange={e => setPassphrase(e.target.value)}
          />
          <input
            className="field"
            type="password"
            placeholder="Confirm passphrase"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
          />
          <button className="btn">Create vault account</button>
        </form>
        {status && <p className="error-text">{status}</p>}
      </div>
    </main>
  );
}
