// lib/srp-client.ts
// Runs in the browser. SRP-6a client half via @swan-io/srp. The passphrase
// is used locally to compute a zero-knowledge proof and is never sent to
// the server in any form — only the proof is.
//
// Verify call signatures against @swan-io/srp's installed version before
// deploying. `await` is used defensively on every call here since some
// methods are synchronous and some are async depending on version —
// awaiting a non-promise value is harmless.

import { createSRPClient } from '@swan-io/srp';

const srp = createSRPClient('SHA-256', 2048);

export async function srpLogin(passphrase: string): Promise<{ masterSaltHex: string }> {
  const ephemeral = await srp.generateEphemeral();

  const step1 = await fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'srp-step1' }),
  });
  if (!step1.ok) throw new Error('Login failed');
  const { saltHex, serverPublicEphemeral } = await step1.json();

  const privateKey = await srp.deriveSafePrivateKey(saltHex, passphrase);
  const clientSession = await srp.deriveSession(ephemeral.secret, serverPublicEphemeral, saltHex, '', privateKey);

  const step2 = await fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'srp-step2',
      clientPublicEphemeral: ephemeral.public,
      clientSessionProof: clientSession.proof,
    }),
  });
  if (!step2.ok) throw new Error((await step2.json().catch(() => ({})))?.error ?? 'Invalid passphrase');
  const { serverSessionProof, masterSaltHex } = await step2.json();

  await srp.verifySession(ephemeral.public, clientSession, serverSessionProof); // mutual auth: server proves it knew the verifier too

  return { masterSaltHex };
}

export async function logout(): Promise<void> {
  await fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'logout' }),
  });
}
