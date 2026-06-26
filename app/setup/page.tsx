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
      <main style={{ maxWidth: 340, margin: '4rem auto', padding: '0 1rem' }}>
        <h1>Done</h1>
        <p>Your vault account is created. Go to the home page and unlock it with your passphrase.</p>
        <p>This page will refuse to run again. Delete <code>app/setup</code> and <code>app/api/setup</code> whenever you like — it's no longer needed.</p>
        <p><a href="/">Go to vault →</a></p>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 340, margin: '4rem auto', padding: '0 1rem' }}>
      <h1>One-time setup</h1>
      <p>This only works if no account exists yet. Your passphrase is never sent anywhere — only a cryptographic proof derived from it is.</p>
      <form onSubmit={handleSubmit}>
        <input
          placeholder="Username (any identifier)"
          value={username}
          onChange={e => setUsername(e.target.value)}
          style={{ width: '100%', padding: 8, marginBottom: 8, boxSizing: 'border-box' }}
        />
        <input
          type="password"
          placeholder="Master passphrase"
          value={passphrase}
          onChange={e => setPassphrase(e.target.value)}
          style={{ width: '100%', padding: 8, marginBottom: 8, boxSizing: 'border-box' }}
        />
        <input
          type="password"
          placeholder="Confirm passphrase"
          value={confirm}
          onChange={e => setConfirm(e.target.value)}
          style={{ width: '100%', padding: 8, marginBottom: 8, boxSizing: 'border-box' }}
        />
        <button style={{ width: '100%', padding: 8 }}>Create vault account</button>
      </form>
      {status && <p>{status}</p>}
    </main>
  );
}
