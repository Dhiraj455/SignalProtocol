import {
  base64ToBytes,
  bytesToBase64,
  diffieHellman,
  generateDHKeyPair,
  hkdf,
  signEd25519,
  verifyEd25519,
} from "./cryptoUtils";

/**
 * X3DH (Extended Triple Diffie-Hellman) key agreement.
 * Both parties end up with the SAME 32-byte root key by doing 3 or 4 DH
 * operations and feeding the concatenation through HKDF.
 *
 *   Initiator (A)              Responder (B)
 *   ------------              ------------
 *   DH1 = DH(IK_A, SPK_B)     DH1 = DH(SPK_B, IK_A)
 *   DH2 = DH(EK_A, IK_B)      DH2 = DH(IK_B, EK_A)
 *   DH3 = DH(EK_A, SPK_B)     DH3 = DH(SPK_B, EK_A)
 *   DH4 = DH(EK_A, OPK_B)*    DH4 = DH(OPK_B, EK_A)*
 *
 *   root = HKDF-SHA256( DH1 || DH2 || DH3 [|| DH4] )
 *
 * The responder also needs to know which ephemeral key (EK_A) and which
 * one-time prekey id the initiator used, so those travel in the X3DH header
 * of the first message.
 */

// --- Public bundle types (shared with backend) ---

export type OneTimePreKeyPublic = {
  id: number;
  publicKey: string;
};

export type SignedPreKeyPublic = {
  publicKey: string;
  signature: string;
};

export type PrekeyBundle = {
  username: string;
  identityKey: string; // Ed25519 public, base64  (signs the signed prekey)
  identityDhKey: string; // X25519 public, base64 (used in DH1/DH2)
  signedPreKey: SignedPreKeyPublic;
  oneTimePrekeys: OneTimePreKeyPublic[];
};

// --- Private material kept only on the client ---

export type LocalPrekeyMaterial = {
  identityDhPrivate: string;
  /**
   * Legacy single-key field; kept for backward compatibility with old localStorage.
   */
  signedPreKeyPrivate?: string;
  /**
   * Keyed by signed prekey public key (base64) -> signed prekey private key (base64).
   * Supports future signed-prekey rotation overlap windows.
   */
  signedPreKeyPrivateByPublic?: Record<string, string>;
  oneTimePrekeyPrivateById: Record<number, string>;
  nextOneTimePrekeyId?: number;
  signedPreKeyRotatedAt?: number;
};

export type X3DHHandshakeHeader = {
  ephPublicKey: string;
  usedSignedPreKeyPublicKey?: string;
  usedOneTimePrekeyId?: number;
};

/**
 * Build the PUBLIC prekey bundle (+ return the PRIVATE half for local storage).
 * The signed prekey is signed with the Ed25519 identity key so peers can
 * verify its authenticity before running DH against it.
 */
export async function generatePrekeyBundle(
  username: string,
  identityPublicB64: string,
  identityDhPublicB64: string,
  identityDhPrivateB64: string,
  identityPrivateB64: string,
  oneTimeCount = 5
) {
  const signedPreKey = await generateSignedPreKeyMaterial(identityPrivateB64);
  const oneTime = await generateOneTimePrekeys(1, oneTimeCount);

  return {
    username,
    identityKey: identityPublicB64,
    identityDhKey: identityDhPublicB64,
    signedPreKey: {
      publicKey: signedPreKey.publicKey,
      signature: signedPreKey.signature,
    },
    oneTimePrekeys: oneTime.public,
    private: {
      identityDhPrivate: identityDhPrivateB64,
      signedPreKeyPrivate: signedPreKey.privateKey,
      signedPreKeyPrivateByPublic: {
        [signedPreKey.publicKey]: signedPreKey.privateKey,
      },
      oneTimePrekeyPrivateById: oneTime.privateById,
      nextOneTimePrekeyId: oneTime.nextId,
      signedPreKeyRotatedAt: Date.now(),
    } as LocalPrekeyMaterial,
  };
}

export async function generateSignedPreKeyMaterial(identityPrivateB64: string) {
  const signedPreKeyPair = await generateDHKeyPair();
  const spkPubBytes = base64ToBytes(signedPreKeyPair.publicKey);
  const signature = await signEd25519(spkPubBytes, identityPrivateB64);
  return {
    publicKey: signedPreKeyPair.publicKey,
    privateKey: signedPreKeyPair.privateKey,
    signature,
  };
}

export async function generateOneTimePrekeys(startId: number, count: number) {
  const pub: OneTimePreKeyPublic[] = [];
  const priv: Record<number, string> = {};
  let id = startId;
  for (let i = 0; i < count; i++) {
    const { publicKey, privateKey } = await generateDHKeyPair();
    pub.push({ id, publicKey });
    priv[id] = privateKey;
    id += 1;
  }
  return { public: pub, privateById: priv, nextId: id };
}

/** Check that the signed prekey was actually signed by the advertised identity key. */
export async function verifyBundle(bundle: PrekeyBundle) {
  const msg = base64ToBytes(bundle.signedPreKey.publicKey);
  return verifyEd25519(msg, bundle.signedPreKey.signature, bundle.identityKey);
}

// --- X3DH derivations ---

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

async function kdfX3dh(sharedSecrets: Uint8Array[]): Promise<string> {
  const seed = concatBytes(sharedSecrets);
  const info = new TextEncoder().encode("x3dh-root-v1");
  const root = await hkdf(seed, info);
  return bytesToBase64(root);
}

/** Initiator side: I (A) create the shared root using B's prekey bundle + my ephemeral key. */
export async function deriveX3DHAsInitiator(args: {
  selfIdentityDhPrivate: string;
  peerBundle: PrekeyBundle;
  ephPrivate: string;
  usedOneTimePrekeyId?: number;
}): Promise<string> {
  const { selfIdentityDhPrivate, peerBundle, ephPrivate, usedOneTimePrekeyId } = args;

  const dh1 = await diffieHellman(selfIdentityDhPrivate, peerBundle.signedPreKey.publicKey);
  const dh2 = await diffieHellman(ephPrivate, peerBundle.identityDhKey);
  const dh3 = await diffieHellman(ephPrivate, peerBundle.signedPreKey.publicKey);
  const pieces = [dh1, dh2, dh3];

  if (usedOneTimePrekeyId !== undefined) {
    const opk = peerBundle.oneTimePrekeys.find((p) => p.id === usedOneTimePrekeyId);
    if (opk) {
      const dh4 = await diffieHellman(ephPrivate, opk.publicKey);
      pieces.push(dh4);
    }
  }

  return kdfX3dh(pieces);
}

/** Responder side: I (B) re-derive the same shared root using my private prekeys + A's ephemeral public. */
export async function deriveX3DHAsResponder(args: {
  selfPrekeys: LocalPrekeyMaterial;
  peerIdentityDhPublic: string;
  ephPublicKey: string;
  usedSignedPreKeyPublicKey?: string;
  usedOneTimePrekeyId?: number;
}): Promise<string> {
  const {
    selfPrekeys,
    peerIdentityDhPublic,
    ephPublicKey,
    usedSignedPreKeyPublicKey,
    usedOneTimePrekeyId,
  } = args;

  let signedPreKeyPrivate: string | undefined;
  const spkMap = selfPrekeys.signedPreKeyPrivateByPublic ?? {};
  if (usedSignedPreKeyPublicKey && spkMap[usedSignedPreKeyPublicKey]) {
    signedPreKeyPrivate = spkMap[usedSignedPreKeyPublicKey];
  } else if (selfPrekeys.signedPreKeyPrivate) {
    signedPreKeyPrivate = selfPrekeys.signedPreKeyPrivate;
  } else {
    const first = Object.values(spkMap)[0];
    if (typeof first === "string") signedPreKeyPrivate = first;
  }
  if (!signedPreKeyPrivate) {
    throw new Error("missing signed prekey private material for responder X3DH");
  }

  const dh1 = await diffieHellman(signedPreKeyPrivate, peerIdentityDhPublic);
  const dh2 = await diffieHellman(selfPrekeys.identityDhPrivate, ephPublicKey);
  const dh3 = await diffieHellman(signedPreKeyPrivate, ephPublicKey);
  const pieces = [dh1, dh2, dh3];

  if (usedOneTimePrekeyId !== undefined) {
    const opkPriv = selfPrekeys.oneTimePrekeyPrivateById[usedOneTimePrekeyId];
    if (opkPriv) {
      const dh4 = await diffieHellman(opkPriv, ephPublicKey);
      pieces.push(dh4);
    }
  }

  return kdfX3dh(pieces);
}
