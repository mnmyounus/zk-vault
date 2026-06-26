// app/api/auth/route.ts
import { NextRequest, NextResponse } from 'next/server';
import {
  srpServer,
  getSingleUser,
  storePendingLogin,
  takePendingLogin,
  createSessionCookie,
  clearSessionCookie,
} from '@/lib/server';

export async function POST(req: NextRequest) {
  const body = await req.json();

  if (body.action === 'srp-step1') {
    const user = await getSingleUser();
    if (!user) {
      return NextResponse.json({ error: 'Vault not provisioned yet — visit /setup once' }, { status: 500 });
    }
    const serverEphemeral = await srpServer.generateEphemeral(user.srp_verifier);
    await storePendingLogin(serverEphemeral.secret);
    return NextResponse.json({ saltHex: user.srp_salt, serverPublicEphemeral: serverEphemeral.public });
  }

  if (body.action === 'srp-step2') {
    const user = await getSingleUser();
    const serverSecretEphemeral = await takePendingLogin();
    if (!user || !serverSecretEphemeral) {
      return NextResponse.json({ error: 'Login session expired, try again' }, { status: 401 });
    }

    try {
      const session = await srpServer.deriveSession(
        serverSecretEphemeral,
        body.clientPublicEphemeral,
        user.srp_salt,
        '',
        user.srp_verifier,
        body.clientSessionProof
      );
      const res = NextResponse.json({ serverSessionProof: session.proof, masterSaltHex: user.master_salt });
      res.cookies.set(await createSessionCookie(user.id));
      return res;
    } catch {
      // srp throws if the client's proof doesn't match — i.e. wrong passphrase
      return NextResponse.json({ error: 'Invalid passphrase' }, { status: 401 });
    }
  }

  if (body.action === 'logout') {
    const res = NextResponse.json({ ok: true });
    res.cookies.set(clearSessionCookie());
    return res;
  }

  return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
}
