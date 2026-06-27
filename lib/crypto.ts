// lib/crypto.ts
// All client-side cryptography. Runs entirely in the browser via the
// native Web Crypto API. The passphrase, the Master Key, and File Keys
// never leave this module as plaintext — nothing here ever touches the
// network.
//
// NOTE: every Uint8Array here is explicitly typed Uint8Array<ArrayBuffer>.
// Newer TypeScript made Uint8Array generic over its backing buffer
// (ArrayBuffer | SharedArrayBuffer); crypto.subtle's BufferSource type
// only accepts the ArrayBuffer-backed form, so a bare "Uint8Array" return
// type now fails to compile even though it's always correct at runtime.

// ---------- helpers ----------

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length)) as Uint8Array<ArrayBuffer>;
}

export function toHex(bytes: Uint8Array<ArrayBuffer>): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2) as Uint8Array<ArrayBuffer>;
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bufToB64(buf: ArrayBuffer | Uint8Array<ArrayBuffer>): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

export function b64ToBuf(b64: string): ArrayBuffer {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ---------- key derivation (passphrase -> Master Key) ----------

const PBKDF2_ITERATIONS = 600_000; // OWASP 2023 floor for PBKDF2-SHA256

/**
 * Default derivation path: native PBKDF2 via SubtleCrypto. Zero
 * dependencies — satisfies "native Web Crypto API" literally. The key is
 * created non-extractable: it can encrypt/decrypt but can never be read
 * back out as raw bytes, even by other code running in this page.
 */
export async function deriveMasterKeyPBKDF2(passphrase: string, masterSaltHex: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: fromHex(masterSaltHex), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Optional, stronger path: Argon2id via hash-wasm (adds a small WASM
 * dependency — Web Crypto itself has no native Argon2). Memory-hardness
 * makes GPU/ASIC brute force much costlier than PBKDF2 at equivalent
 * wall-clock cost.  npm install hash-wasm
 */
export async function deriveMasterKeyArgon2id(passphrase: string, masterSaltHex: string): Promise<CryptoKey> {
  const { argon2id } = await import('hash-wasm');
  const rawHex = await argon2id({
    password: passphrase,
    salt: fromHex(masterSaltHex),
    parallelism: 1,
    iterations: 4,
    memorySize: 65536, // 64MB — lower if targeting low-end mobile browsers
    hashLength: 32,
    outputType: 'hex',
  });
  return crypto.subtle.importKey('raw', fromHex(rawHex), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// ---------- Layer 1: per-file random key + AES-GCM over raw bytes ----------

export interface EncryptedFile {
  ciphertext: ArrayBuffer;
  iv: Uint8Array<ArrayBuffer>;
  fileKeyRaw: Uint8Array<ArrayBuffer>;
}

export async function encryptFile(file: File): Promise<EncryptedFile> {
  const fileKeyRaw = randomBytes(32);
  const key = await crypto.subtle.importKey('raw', fileKeyRaw, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, await file.arrayBuffer());
  return { ciphertext, iv, fileKeyRaw };
}

export async function decryptFile(
  ciphertext: ArrayBuffer,
  iv: Uint8Array<ArrayBuffer>,
  fileKeyRaw: Uint8Array<ArrayBuffer>
): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey('raw', fileKeyRaw, 'AES-GCM', false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
}

// ---------- Layer 2: envelope (file key + metadata) sealed under Master Key ----------

export interface FileMetadata {
  fileKeyHex: string;
  filename: string;
  extension: string;
  size: number;
  mimeType: string;
}

export interface SealedEnvelope {
  ciphertextB64: string;
  ivB64: string;
}

export async function sealEnvelope(masterKey: CryptoKey, metadata: FileMetadata): Promise<SealedEnvelope> {
  const iv = randomBytes(12);
  const plaintext = new TextEncoder().encode(JSON.stringify(metadata));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, masterKey, plaintext);
  return { ciphertextB64: bufToB64(ciphertext), ivB64: bufToB64(iv) };
}

export async function openEnvelope(masterKey: CryptoKey, envelope: SealedEnvelope): Promise<FileMetadata> {
  const iv = new Uint8Array(b64ToBuf(envelope.ivB64)) as Uint8Array<ArrayBuffer>;
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, b64ToBuf(envelope.ciphertextB64));
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ---------- pre-encryption hash, for the malware hash-lookup check ----------

export async function sha256Hex(file: File): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  return toHex(new Uint8Array(digest) as Uint8Array<ArrayBuffer>);
}

// ---------- in-memory key store: idle timeout + wipe-on-close ----------
//
// CAVEAT, stated plainly: JS in a browser cannot guarantee true memory
// zeroing the way native code can (no mlock, no explicit free; the GC may
// retain copies of "deleted" data for a while). extractable: false plus
// dropping references promptly is the practical best-effort mitigation
// available here — not a hard guarantee against a sufficiently capable
// local attacker with memory-inspection access to the device.
//
// Deliberately NOT listening for "pagehide": on several mobile browsers
// that event also fires when a native file picker or save/download sheet
// opens on top of the page — not just on a real navigation-away. Wiping
// on that false signal meant tapping the file input (upload) or Export
// (save dialog) would lock the vault before you could finish using it.
// beforeunload (real navigation/close) and the idle timer (walked away)
// are the actual protections; they don't share this false-positive.

type Listener = () => void;

class KeyStore {
  private masterKey: CryptoKey | null = null;
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private listeners: Listener[] = [];
  private readonly idleMs: number;

  constructor(idleMs = 10 * 60 * 1000) {
    this.idleMs = idleMs;
    if (typeof window !== 'undefined') {
      ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(evt =>
        window.addEventListener(evt, () => this.touch(), { passive: true })
      );
      window.addEventListener('beforeunload', () => this.wipe());
    }
  }

  set(key: CryptoKey) {
    this.masterKey = key;
    this.touch();
  }
  get() {
    return this.masterKey;
  }
  isUnlocked() {
    return this.masterKey !== null;
  }
  onWipe(fn: Listener) {
    this.listeners.push(fn);
  }

  wipe() {
    this.masterKey = null;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.listeners.forEach(fn => fn());
  }

  private touch() {
    if (!this.masterKey) return;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.wipe(), this.idleMs);
  }
}

export const keyStore = new KeyStore();
