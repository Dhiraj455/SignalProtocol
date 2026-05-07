import { describe, expect, test } from "vitest";
import nacl from "tweetnacl";
import { bytesToBase64, signEd25519 } from "./cryptoUtils";
import { deriveX3DHAsInitiator, deriveX3DHAsResponder, type LocalPrekeyMaterial } from "./x3dh";

function seed32(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

function dhPairFromSeed(fill: number) {
  const sk = seed32(fill);
  const kp = nacl.box.keyPair.fromSecretKey(sk);
  return {
    publicKey: bytesToBase64(kp.publicKey),
    privateKey: bytesToBase64(sk),
  };
}

async function makeFixture() {
  const aIdentityDh = dhPairFromSeed(11);
  const aEphemeralDh = dhPairFromSeed(12);

  const bIdentityDh = dhPairFromSeed(21);
  const bSignedPrekey = dhPairFromSeed(22);
  const bOneTimePrekey = { id: 1001, ...dhPairFromSeed(23) };

  const bIdentitySign = nacl.sign.keyPair.fromSeed(seed32(99));
  const bIdentityPubB64 = bytesToBase64(bIdentitySign.publicKey);
  const bIdentityPrivB64 = bytesToBase64(bIdentitySign.secretKey);

  const spkSig = await signEd25519(
    Uint8Array.from(Buffer.from(bSignedPrekey.publicKey, "base64")),
    bIdentityPrivB64
  );

  const peerBundle = {
    username: "bob",
    identityKey: bIdentityPubB64,
    identityDhKey: bIdentityDh.publicKey,
    signedPreKey: {
      publicKey: bSignedPrekey.publicKey,
      signature: spkSig,
    },
    oneTimePrekeys: [{ id: bOneTimePrekey.id, publicKey: bOneTimePrekey.publicKey }],
  };

  const responderPrekeys: LocalPrekeyMaterial = {
    identityDhPrivate: bIdentityDh.privateKey,
    signedPreKeyPrivate: bSignedPrekey.privateKey,
    signedPreKeyPrivateByPublic: {
      [bSignedPrekey.publicKey]: bSignedPrekey.privateKey,
    },
    oneTimePrekeyPrivateById: {
      [bOneTimePrekey.id]: bOneTimePrekey.privateKey,
    },
    nextOneTimePrekeyId: bOneTimePrekey.id + 1,
    signedPreKeyRotatedAt: 0,
  };

  return {
    aIdentityDh,
    aEphemeralDh,
    bIdentityDh,
    bSignedPrekey,
    bOneTimePrekey,
    peerBundle,
    responderPrekeys,
  };
}

describe("X3DH vectors and invariants", () => {
  test("initiator and responder derive same root with OPK", async () => {
    const f = await makeFixture();
    const rootA = await deriveX3DHAsInitiator({
      selfIdentityDhPrivate: f.aIdentityDh.privateKey,
      peerBundle: f.peerBundle,
      ephPrivate: f.aEphemeralDh.privateKey,
      usedOneTimePrekeyId: f.bOneTimePrekey.id,
    });
    const rootB = await deriveX3DHAsResponder({
      selfPrekeys: f.responderPrekeys,
      peerIdentityDhPublic: f.aIdentityDh.publicKey,
      ephPublicKey: f.aEphemeralDh.publicKey,
      usedSignedPreKeyPublicKey: f.bSignedPrekey.publicKey,
      usedOneTimePrekeyId: f.bOneTimePrekey.id,
    });
    expect(rootA).toBe(rootB);
    expect(rootA).toBe("I9e/mpTvhIdvqZr+EOU9ZVmgJWXO1NxeWPcNMswBoac=");
  });

  test("wrong signed prekey selection changes derived root", async () => {
    const f = await makeFixture();
    const rootA = await deriveX3DHAsInitiator({
      selfIdentityDhPrivate: f.aIdentityDh.privateKey,
      peerBundle: f.peerBundle,
      ephPrivate: f.aEphemeralDh.privateKey,
      usedOneTimePrekeyId: f.bOneTimePrekey.id,
    });
    const wrongSpk = dhPairFromSeed(77);
    const rootWrong = await deriveX3DHAsResponder({
      selfPrekeys: {
        ...f.responderPrekeys,
        signedPreKeyPrivateByPublic: {
          ...f.responderPrekeys.signedPreKeyPrivateByPublic,
          [wrongSpk.publicKey]: wrongSpk.privateKey,
        },
      },
      peerIdentityDhPublic: f.aIdentityDh.publicKey,
      ephPublicKey: f.aEphemeralDh.publicKey,
      usedSignedPreKeyPublicKey: wrongSpk.publicKey,
      usedOneTimePrekeyId: f.bOneTimePrekey.id,
    });
    expect(rootWrong).not.toBe(rootA);
  });
});
