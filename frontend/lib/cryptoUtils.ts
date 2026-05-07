import nacl from "tweetnacl";

// Base64 helpers (work in browser and Node)
export function bytesToBase64(b: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let binary = "";
  for (let i = 0; i < b.length; i++) binary += String.fromCharCode(b[i]);
  return btoa(binary);
}

export function base64ToBytes(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  const binary = atob(s);
  const u = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) u[i] = binary.charCodeAt(i);
  return u;
}

// No-op for compatibility; tweetnacl is synchronous
export async function initSodium() {
  // tweetnacl needs no init
}

// Identity keys: Ed25519 signing keys (used to sign prekeys)
export async function generateIdentityKeyPair() {
  const { publicKey, secretKey } = nacl.sign.keyPair();
  return {
    publicKey: bytesToBase64(publicKey),
    privateKey: bytesToBase64(secretKey),
  };
}

// X25519 DH key pair (used for identity-DH, signed prekeys, one-time prekeys, ephemeral keys)
export async function generateDHKeyPair() {
  const { publicKey, secretKey } = nacl.box.keyPair();
  return {
    publicKey: bytesToBase64(publicKey),
    privateKey: bytesToBase64(secretKey),
  };
}

/**
 * X25519 Diffie-Hellman: DH(privateA, publicB) → 32-byte shared secret.
 * Used as a primitive by the X3DH key agreement (see `lib/x3dh.ts`).
 */
export async function diffieHellman(
  privateKeyB64: string,
  publicKeyB64: string
): Promise<Uint8Array> {
  const priv = base64ToBytes(privateKeyB64);
  const pub = base64ToBytes(publicKeyB64);
  return nacl.scalarMult(priv, pub);
}

export async function signEd25519(
  message: Uint8Array,
  privateKeyB64: string
): Promise<string> {
  const priv = base64ToBytes(privateKeyB64);
  const sig = nacl.sign.detached(message, priv);
  return bytesToBase64(sig);
}

export async function verifyEd25519(
  message: Uint8Array,
  signatureB64: string,
  publicKeyB64: string
): Promise<boolean> {
  const sig = base64ToBytes(signatureB64);
  const pub = base64ToBytes(publicKeyB64);
  return nacl.sign.detached.verify(message, sig, pub);
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const keyBytes = new Uint8Array(key);
  const dataBytes = new Uint8Array(data);
  const keyBuffer = keyBytes.buffer.slice(
    keyBytes.byteOffset,
    keyBytes.byteOffset + keyBytes.byteLength
  );
  const dataBuffer = dataBytes.buffer.slice(
    dataBytes.byteOffset,
    dataBytes.byteOffset + dataBytes.byteLength
  );
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, dataBuffer);
  return Uint8Array.from(new Uint8Array(sig));
}

/**
 * RFC5869-style HKDF-SHA256.
 *
 * - ikm: input key material
 * - info: context/application label
 * - salt: optional random/secret salt (defaults to zero-filled hash length)
 * - length: output bytes
 */
export async function hkdf(
  ikm: Uint8Array,
  info: Uint8Array = new Uint8Array(0),
  salt?: Uint8Array,
  length = 32
) {
  const hkdfSalt = salt ?? new Uint8Array(32);
  const prk = await hmacSha256(hkdfSalt, ikm);

  const blocks: Uint8Array[] = [];
  let t = new Uint8Array(0);
  let generated = 0;
  let counter = 1;
  while (generated < length) {
    const input = new Uint8Array(t.length + info.length + 1);
    input.set(t, 0);
    input.set(info, t.length);
    input[input.length - 1] = counter;
    const nextT = await hmacSha256(prk, input);
    t = new Uint8Array(nextT);
    blocks.push(t);
    generated += t.length;
    counter += 1;
  }

  const okm = new Uint8Array(generated);
  let offset = 0;
  for (const block of blocks) {
    okm.set(block, offset);
    offset += block.length;
  }
  return new Uint8Array(okm.slice(0, length));
}

const SECRETBOX_NONCE_LENGTH = 24;

// AEAD: XSalsa20-Poly1305 via tweetnacl secretbox
export async function encryptAEAD(
  keyB64: string,
  plaintext: Uint8Array,
  ad?: Uint8Array
) {
  let key = base64ToBytes(keyB64);
  if (ad && ad.length > 0) {
    // secretbox has no native AD, so derive an AD-bound sub-key.
    key = await hkdf(key, new TextEncoder().encode("aead-subkey"), ad);
  }
  const nonce = nacl.randomBytes(SECRETBOX_NONCE_LENGTH);
  const box = nacl.secretbox(plaintext, nonce, key);
  const combined = new Uint8Array(nonce.length + box.length);
  combined.set(nonce, 0);
  combined.set(box, nonce.length);
  return bytesToBase64(combined);
}

export async function decryptAEAD(
  keyB64: string,
  combinedB64: string,
  ad?: Uint8Array
) {
  const rawKey = base64ToBytes(keyB64);
  let key = rawKey;
  if (ad && ad.length > 0) {
    key = await hkdf(rawKey, new TextEncoder().encode("aead-subkey"), ad);
  }
  const combined = base64ToBytes(combinedB64);
  const nonce = combined.slice(0, SECRETBOX_NONCE_LENGTH);
  const box = combined.slice(SECRETBOX_NONCE_LENGTH);
  const plaintext = nacl.secretbox.open(box, nonce, key);
  if (plaintext) return plaintext;
  // Backward-compatible fallback for messages created before AD binding.
  const legacy = nacl.secretbox.open(box, nonce, rawKey);
  if (!legacy) throw new Error("decryption failed");
  return legacy;
}
