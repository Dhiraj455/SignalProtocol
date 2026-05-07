import {
  base64ToBytes,
  bytesToBase64,
  diffieHellman,
  encryptAEAD,
  decryptAEAD,
  hkdf,
  generateDHKeyPair,
} from "./cryptoUtils";

// Minimal, single-partner Double Ratchet suitable for the project.

export type DRHeader = {
  dhPub: string; // current sender ratchet public key
  n: number; // message number in this sending chain
  pn: number; // previous sending chain length
};

export type DREnvelope = {
  header: DRHeader;
  ciphertext: string; // base64
  debug?: {
    role: "send" | "recv";
    messageKeyFp: string;
    chainKeyFp: string;
  };
  /**
   * Present only on the first message of a session. Lets the responder
   * re-derive the X3DH shared root (ephemeral pub + which one-time prekey).
   */
  x3dh?: {
    ephPublicKey: string;
    usedSignedPreKeyPublicKey?: string;
    usedOneTimePrekeyId?: number;
  };
};

export type DRSerializedState = {
  v: 2;
  rootKey: string;
  sendingChainKey: string;
  receivingChainKey: string;
  sendingN: number;
  receivingN: number;
  previousSendingChainLength: number;
  remoteDhPub: string;
  localDh: { publicKey: string; privateKey: string };
  skippedMessageKeys: Record<string, string>;
};

type DRSerializedStateV1 = Omit<DRSerializedState, "v"> & { v: 1 };

function canonicalHeaderAd(h: Partial<DRHeader>): Uint8Array {
  const norm: DRHeader = {
    dhPub: typeof h.dhPub === "string" ? h.dhPub : "",
    n: Number(h.n),
    pn: Number(h.pn ?? 0),
  };
  const s = JSON.stringify({
    dhPub: norm.dhPub,
    n: norm.n,
    pn: norm.pn,
  });
  return new TextEncoder().encode(s);
}

async function shortFp(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  const bytes = new Uint8Array(digest).slice(0, 6);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export class DoubleRatchet {
  private sendingChainKey: Uint8Array;
  private receivingChainKey: Uint8Array;
  private sendingN: number;
  private receivingN: number;
  private previousSendingChainLength: number;
  private remoteDhPub: string;
  private localDh: { publicKey: string; privateKey: string };
  private skippedMessageKeys: Map<string, Uint8Array>;
  private rootKey: Uint8Array;
  private readonly maxSkip = 200;

  private constructor(
    rootKey: Uint8Array,
    localDh: { publicKey: string; privateKey: string },
    sendingChainKey: Uint8Array,
    receivingChainKey: Uint8Array
  ) {
    this.rootKey = rootKey;
    this.localDh = localDh;
    this.sendingChainKey = sendingChainKey;
    this.receivingChainKey = receivingChainKey;
    this.sendingN = 0;
    this.receivingN = 0;
    this.previousSendingChainLength = 0;
    this.remoteDhPub = "";
    this.skippedMessageKeys = new Map();
  }

  /**
   * Shared root from X3DH (demo: same base64 for both users).
   * `isLexicographicallyFirstParty`: true for the user whose name sorts first (e.g. "alice" before "bob").
   * That party uses (sending, receiving) = (HKDF(s), HKDF(r)); the other party swaps so their
   * "receiving" chain matches the first party's "sending" chain — required for encrypt/decrypt to match.
   */
  static async fromRootKey(
    rootKeyB64: string,
    isLexicographicallyFirstParty: boolean
  ) {
    const root = base64ToBytes(rootKeyB64);
    const localDh = await generateDHKeyPair();
    const sending = new TextEncoder().encode("sending");
    const receiving = new TextEncoder().encode("receiving");
    const s = await hkdf(root, sending);
    const r = await hkdf(root, receiving);
    if (isLexicographicallyFirstParty) {
      return new DoubleRatchet(root, localDh, s, r);
    }
    return new DoubleRatchet(root, localDh, r, s);
  }

  static fromSerialized(state: DRSerializedState | DRSerializedStateV1) {
    if (!state || (state.v !== 1 && state.v !== 2)) {
      throw new Error("invalid ratchet state version");
    }
    const dr = new DoubleRatchet(
      base64ToBytes(state.rootKey),
      state.localDh,
      base64ToBytes(state.sendingChainKey),
      base64ToBytes(state.receivingChainKey)
    );
    dr.sendingN = Number(state.sendingN) || 0;
    dr.receivingN = Number(state.receivingN) || 0;
    dr.previousSendingChainLength = Number(state.previousSendingChainLength) || 0;
    dr.remoteDhPub = state.remoteDhPub ?? "";
    const skipped = new Map<string, Uint8Array>();
    for (const [id, keyB64] of Object.entries(state.skippedMessageKeys ?? {})) {
      if (typeof keyB64 === "string") skipped.set(id, base64ToBytes(keyB64));
    }
    dr.skippedMessageKeys = skipped;
    return dr;
  }

  serialize(): DRSerializedState {
    const skipped: Record<string, string> = {};
    for (const [id, key] of this.skippedMessageKeys.entries()) {
      skipped[id] = bytesToBase64(key);
    }
    return {
      v: 2,
      rootKey: bytesToBase64(this.rootKey),
      sendingChainKey: bytesToBase64(this.sendingChainKey),
      receivingChainKey: bytesToBase64(this.receivingChainKey),
      sendingN: this.sendingN,
      receivingN: this.receivingN,
      previousSendingChainLength: this.previousSendingChainLength,
      remoteDhPub: this.remoteDhPub,
      localDh: this.localDh,
      skippedMessageKeys: skipped,
    };
  }

  private async nextLocalDhKeyPair() {
    return generateDHKeyPair();
  }

  private skippedKeyId(dhPub: string, n: number): string {
    return `${dhPub}:${n}`;
  }

  private async kdfRootAndChain(dhOut: Uint8Array) {
    const newRoot = await hkdf(
      dhOut,
      new TextEncoder().encode("dr-root"),
      this.rootKey
    );
    const chain = await hkdf(newRoot, new TextEncoder().encode("dr-chain"));
    this.rootKey = newRoot;
    return chain;
  }

  private async skipMessageKeys(until: number) {
    if (until < this.receivingN) return;
    if (until - this.receivingN > this.maxSkip) {
      throw new Error("too many skipped messages");
    }
    while (this.receivingN < until) {
      const mk = await this.nextReceivingMessageKey();
      const id = this.skippedKeyId(this.remoteDhPub, this.receivingN);
      this.skippedMessageKeys.set(id, mk);
      this.receivingN += 1;
      if (this.skippedMessageKeys.size > this.maxSkip) {
        const firstKey = this.skippedMessageKeys.keys().next().value;
        if (firstKey) this.skippedMessageKeys.delete(firstKey);
      }
    }
  }

  private async maybeTrySkipped(env: DREnvelope): Promise<string | null> {
    const id = this.skippedKeyId(env.header.dhPub, env.header.n);
    const mk = this.skippedMessageKeys.get(id);
    if (!mk) return null;
    this.skippedMessageKeys.delete(id);
    const keyB64 = bytesToBase64(mk);
    const headerAd = canonicalHeaderAd(env.header);
    const plaintextBytes = await decryptAEAD(keyB64, env.ciphertext, headerAd);
    return new TextDecoder().decode(plaintextBytes);
  }

  private async dhRatchet(receivedDhPub: string) {
    this.previousSendingChainLength = this.sendingN;
    this.sendingN = 0;
    this.receivingN = 0;
    this.remoteDhPub = receivedDhPub;

    const recvDh = await diffieHellman(this.localDh.privateKey, this.remoteDhPub);
    this.receivingChainKey = await this.kdfRootAndChain(recvDh);

    this.localDh = await this.nextLocalDhKeyPair();
    const sendDh = await diffieHellman(this.localDh.privateKey, this.remoteDhPub);
    this.sendingChainKey = await this.kdfRootAndChain(sendDh);
  }

  private async nextSendingMessageKey() {
    const mk = await hkdf(
      this.sendingChainKey,
      new TextEncoder().encode("dr-message-key")
    );
    this.sendingChainKey = await hkdf(
      this.sendingChainKey,
      new TextEncoder().encode("dr-chain-key")
    );
    return mk;
  }

  private async nextReceivingMessageKey() {
    const mk = await hkdf(
      this.receivingChainKey,
      new TextEncoder().encode("dr-message-key")
    );
    this.receivingChainKey = await hkdf(
      this.receivingChainKey,
      new TextEncoder().encode("dr-chain-key")
    );
    return mk;
  }

  async encrypt(plaintext: string): Promise<DREnvelope> {
    const mk = await this.nextSendingMessageKey();
    const keyB64 = bytesToBase64(mk);
    const header: DRHeader = {
      dhPub: this.localDh.publicKey,
      n: this.sendingN,
      pn: this.previousSendingChainLength,
    };
    const headerAd = canonicalHeaderAd(header);
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const ciphertextB64 = await encryptAEAD(keyB64, plaintextBytes, headerAd);
    const msgFp = await shortFp(mk);
    const chainFp = await shortFp(this.sendingChainKey);
    this.sendingN += 1;
    return {
      header,
      ciphertext: ciphertextB64,
      debug: {
        role: "send",
        messageKeyFp: msgFp,
        chainKeyFp: chainFp,
      },
    };
  }

  async decrypt(env: DREnvelope): Promise<string> {
    const fromSkipped = await this.maybeTrySkipped(env);
    if (fromSkipped !== null) return fromSkipped;

    if (!this.remoteDhPub) {
      this.remoteDhPub = env.header.dhPub;
    } else if (env.header.dhPub !== this.remoteDhPub) {
      await this.skipMessageKeys(env.header.pn);
      await this.dhRatchet(env.header.dhPub);
    }

    await this.skipMessageKeys(env.header.n);
    const mk = await this.nextReceivingMessageKey();
    const keyB64 = bytesToBase64(mk);
    const headerAd = canonicalHeaderAd(env.header);
    const plaintextBytes = await decryptAEAD(
      keyB64,
      env.ciphertext,
      headerAd
    );
    this.receivingN += 1;
    return new TextDecoder().decode(plaintextBytes);
  }

  /**
   * @deprecated The Double Ratchet does not support replaying your own sent
   * messages once the sending chain has advanced beyond them — the local DH
   * key the message was encrypted under is gone. Senders should cache their
   * own plaintext locally at {@link encrypt} time instead. Kept only for tests.
   */
  async decryptOwnSent(env: DREnvelope): Promise<string> {
    if (env.header.dhPub !== this.localDh.publicKey) {
      throw new Error("cannot replay own message from prior DH epoch without stored session state");
    }
    while (this.sendingN < env.header.n) {
      await this.nextSendingMessageKey();
      this.sendingN += 1;
    }
    const mk = await this.nextSendingMessageKey();
    const keyB64 = bytesToBase64(mk);
    const headerAd = canonicalHeaderAd(env.header);
    const plaintextBytes = await decryptAEAD(
      keyB64,
      env.ciphertext,
      headerAd
    );
    this.sendingN += 1;
    return new TextDecoder().decode(plaintextBytes);
  }
}

