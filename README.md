# Zero-Knowledge Vault

Single-user, zero-knowledge file vault. Next.js 14 on Vercel (free, no card), Supabase Postgres + Storage (free, no card) — one service instead of two. VirusTotal (free) for pre-flight malware checks.

## Data flow

1. **One-time setup** (`/setup`) — browser generates an SRP salt+verifier and a separate master salt locally, then sends only those to `/api/setup`. The passphrase itself never crosses the network. The route can only ever succeed once — a database-level unique index makes a second account physically impossible.
2. **Unlock** — browser runs SRP-6a (`@swan-io/srp`) against `/api/auth`. Again, only a zero-knowledge proof crosses the network. Server stores only `srp_salt` + `srp_verifier`. On success it sets a 15-minute httpOnly/Secure/SameSite=Strict JWT cookie and returns `master_salt` (non-secret).
3. **Derive Master Key** — browser runs PBKDF2-SHA256 (600k iterations, native `SubtleCrypto`) over the passphrase + `master_salt`, producing a non-extractable AES-GCM-256 `CryptoKey`. Held only in memory, wiped on idle timeout, tab close, or logout.
4. **Pre-flight scan** — browser hashes the *plaintext* file (SHA-256) and sends only the hash to `/api/scan`, checked against VirusTotal's database. A malicious verdict aborts the upload before any encryption happens.
5. **Layer 1 encrypt** — random 256-bit File Key, AES-GCM-256 over the raw file, done locally.
6. **Layer 2 encrypt** — `{fileKey, filename, extension, size, mimeType}` encrypted under the Master Key — the "envelope."
7. **Upload** — `/api/storage` writes the envelope to Postgres and mints a signed upload token from Supabase Storage. The browser uploads ciphertext **directly to Storage** via `uploadToSignedUrl()` — never through a Vercel function, so Vercel's ~4.5MB body limit doesn't apply.
8. **Download** — `/api/storage` mints a signed download URL plus returns the envelope. Browser fetches ciphertext, opens the envelope with the Master Key to recover the File Key and filename, decrypts Layer 1.

The server, the storage bucket, and Postgres only ever hold: a random UUID object name, an AES-GCM ciphertext blob, and an AES-GCM-encrypted metadata envelope. None of it is reversible without the Master Key, which never leaves the browser.

## Setup — everything from a browser, no terminal, no card

1. **Supabase**: supabase.com → free project. Run `sql/schema.sql` in the SQL Editor.
2. **Storage bucket**: Storage → New bucket → name it `vault-files` → keep it **Private**.
3. **Keys**: Settings → API Keys. Copy the Project URL, the secret/service-role key, and the anon/publishable key.
4. **VirusTotal**: free account → profile → API key.
5. **GitHub**: create a repo, add every file in this project (GitHub's web "Create new file" lets you type a full path like `lib/crypto.ts` and paste the contents — no git CLI needed).
6. **Vercel**: import the repo, add the 6 environment variables from `.env.example`, deploy.
7. Open `https://<your-app>.vercel.app/setup` once to create your account, then go to `/` and unlock.

There is no other way to create an account — `/setup` is the only path, and it permanently refuses after the first success.

## Things worth knowing before you rely on this

- **Malware scanning vs. zero-knowledge is a real tension, not a detail.** The default hash-lookup path leaks nothing but a SHA-256 digest, and only catches previously-seen malware. `full-scan` is opt-in and explicitly breaks zero-knowledge for that one file — don't wire it to run silently.
- **Browser memory can't be securely wiped.** No `mlock`/explicit free in JS. `extractable: false` plus prompt dereferencing is the practical best-effort mitigation, not a guarantee against a local attacker with memory-inspection access to the device.
- **Argon2id isn't in the native Web Crypto API.** PBKDF2 is the default to keep the crypto module dependency-free; `deriveMasterKeyArgon2id` in `lib/crypto.ts` is a stronger drop-in via `hash-wasm` if you want it.
- **`@swan-io/srp` is smaller and less battle-tested than mainstream crypto primitives.** Give it a security review, or swap in a different audited SRP library, before trusting it with something you can't afford to lose access to.
- **Supabase free projects pause after 7 days of total inactivity.** If you haven't opened the app in a week, the first request after that will fail until you reopen the Supabase dashboard once and unpause it manually.
- **Storage policies are scoped but real.** The two policies in `sql/schema.sql` allow INSERT/SELECT on the `vault-files` bucket for the public anon key — required for direct browser uploads/downloads to work at all. Someone holding your anon key (extractable from the deployed site's JS, since anon keys are meant to be public) could enumerate the random object names in that bucket, but can't read content or filenames without your Master Key and your private `vault_files` table.
- **One passphrase, two jobs.** It authenticates you (via SRP) and derives the Master Key (via PBKDF2, separate salt) — intentional, same pattern Proton's products use. Use a long, genuinely random passphrase.
