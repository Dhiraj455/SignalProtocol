import { describe, expect, test } from "vitest";
import { DoubleRatchet, type DRSerializedState } from "./doubleRatchet";

async function makePair() {
  const root = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 zero bytes
  const alice = await DoubleRatchet.fromRootKey(root, true);
  const bob = await DoubleRatchet.fromRootKey(root, false);
  return { alice, bob };
}

describe("Double Ratchet invariants", () => {
  test("basic bidirectional encrypt/decrypt works", async () => {
    const { alice, bob } = await makePair();
    const a1 = await alice.encrypt("hi bob");
    expect(await bob.decrypt(a1)).toBe("hi bob");

    const b1 = await bob.encrypt("hi alice");
    expect(await alice.decrypt(b1)).toBe("hi alice");
  });

  test("out-of-order messages can be recovered from skipped keys", async () => {
    const { alice, bob } = await makePair();
    const m1 = await alice.encrypt("one");
    const m2 = await alice.encrypt("two");
    const m3 = await alice.encrypt("three");

    expect(await bob.decrypt(m3)).toBe("three");
    expect(await bob.decrypt(m1)).toBe("one");
    expect(await bob.decrypt(m2)).toBe("two");
  });

  test("serialized state restores ratchet continuity", async () => {
    const { alice, bob } = await makePair();
    const env1 = await alice.encrypt("persist me");
    expect(await bob.decrypt(env1)).toBe("persist me");

    const saved = bob.serialize();
    const restored = DoubleRatchet.fromSerialized(saved);
    const env2 = await alice.encrypt("after restore");
    expect(await restored.decrypt(env2)).toBe("after restore");
  });

  test("v1 serialized state remains compatible", async () => {
    const { bob } = await makePair();
    const v2 = bob.serialize();
    const v1 = { ...v2, v: 1 } as unknown as DRSerializedState;
    const restored = DoubleRatchet.fromSerialized(v1);
    const msg = await restored.encrypt("still valid");
    expect(typeof msg.ciphertext).toBe("string");
  });
});
