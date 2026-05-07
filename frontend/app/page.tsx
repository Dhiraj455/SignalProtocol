"use client";

import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  generateDHKeyPair,
  generateIdentityKeyPair,
  initSodium,
} from "../lib/cryptoUtils";
import {
  deriveX3DHAsInitiator,
  deriveX3DHAsResponder,
  generatePrekeyBundle,
  generateOneTimePrekeys,
  generateSignedPreKeyMaterial,
  verifyBundle,
  type LocalPrekeyMaterial,
  type PrekeyBundle,
} from "../lib/x3dh";
import {
  DoubleRatchet,
  type DREnvelope,
  type DRSerializedState,
} from "../lib/doubleRatchet";
import {
  fetchBundle,
  fetchChatPartners,
  fetchConversation,
  registerBundle,
  replenishOneTimePrekeys,
  rotateSignedPreKey,
  reserveBundle,
  sendEncryptedMessage,
  type ChatPartner,
  type ReceivedMessage,
} from "../lib/api";

type SessionState = {
  username: string;
  prekeyAuthToken: string;
  identityPublic: string;
  identityPrivate: string;
  identityDhPublic: string;
  identityDhPrivate: string;
  prekeys: LocalPrekeyMaterial;
};

/*
 * Local persistence so a reload doesn't forget identity keys + derived roots
 * (otherwise every stored ciphertext decrypts to "decryption failed").
 * Private keys stay client-side; this mirrors how Signal persists on device.
 */
const SESSION_KEY = "secure-chat:session:v1";
const ROOTS_KEY = "secure-chat:roots:v1";
// v3 invalidates pre-fix thread caches whose ratchet snapshots could be
// out of sync with the actual sending chain (caused decryption failures).
const THREADS_KEY = "secure-chat:threads:v3";
const SIGNED_PREKEY_ROTATE_INTERVAL_MS = 1000 * 60 * 60 * 24 * 3; // 3 days
const OPK_LOW_WATERMARK = 3;
const OPK_BATCH_SIZE = 10;

type PersistedThread = {
  ratchet: DRSerializedState;
  lastMessageId: number;
  lines: ChatLine[];
};

type PersistedSessionV2 = {
  v: 2;
  session: SessionState;
};

type PersistedThreadsV2 = {
  v: 2;
  threads: Record<string, PersistedThread>;
};

function persistThreads(threads: Record<string, PersistedThread>): void {
  if (typeof window === "undefined") return;
  try {
    const wrapped: PersistedThreadsV2 = { v: 2, threads };
    window.localStorage.setItem(THREADS_KEY, JSON.stringify(wrapped));
  } catch {
    /* ignore */
  }
}

function loadPersistedThreads(): Record<string, PersistedThread> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(THREADS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const payload =
      (parsed as { v?: number; threads?: unknown }).v === 2 &&
      parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      "threads" in parsed
        ? (parsed as PersistedThreadsV2).threads
        : parsed;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return {};
    const out: Record<string, PersistedThread> = {};
    for (const [peer, value] of Object.entries(payload)) {
      if (!value || typeof value !== "object" || Array.isArray(value)) continue;
      const v = value as Partial<PersistedThread>;
      if (
        v.ratchet &&
        typeof v.ratchet === "object" &&
        typeof v.lastMessageId === "number" &&
        Array.isArray(v.lines)
      ) {
        out[peer] = v as PersistedThread;
      }
    }
    return out;
  } catch {
    return {};
  }
}

function persistSession(s: SessionState | null): void {
  if (typeof window === "undefined") return;
  try {
    if (s) {
      const wrapped: PersistedSessionV2 = { v: 2, session: s };
      window.localStorage.setItem(SESSION_KEY, JSON.stringify(wrapped));
    }
    else window.localStorage.removeItem(SESSION_KEY);
  } catch {
    /* ignore quota / disabled storage */
  }
}

function loadPersistedSession(): SessionState | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const candidate =
      parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      (parsed as { v?: number; session?: unknown }).v === 2
        ? (parsed as PersistedSessionV2).session
        : parsed;
    const p = candidate as Partial<SessionState>;
    if (
      typeof p.username === "string" &&
      typeof p.identityPublic === "string" &&
      typeof p.identityPrivate === "string" &&
      typeof p.identityDhPublic === "string" &&
      typeof p.identityDhPrivate === "string" &&
      p.prekeys &&
      typeof p.prekeys === "object"
    ) {
      const prekeys = p.prekeys as LocalPrekeyMaterial;
      const migratedPrekeys: LocalPrekeyMaterial = {
        ...prekeys,
        signedPreKeyPrivateByPublic: {
          ...(prekeys.signedPreKeyPrivateByPublic ?? {}),
        },
        oneTimePrekeyPrivateById: {
          ...(prekeys.oneTimePrekeyPrivateById ?? {}),
        },
      };
      // Backfill signed prekey map for older sessions.
      if (
        prekeys.signedPreKeyPrivate &&
        Object.keys(migratedPrekeys.signedPreKeyPrivateByPublic ?? {}).length === 0
      ) {
        migratedPrekeys.signedPreKeyPrivateByPublic = {
          legacy: prekeys.signedPreKeyPrivate,
        };
      }
      // Backfill OPK id cursor for older sessions.
      if (typeof migratedPrekeys.nextOneTimePrekeyId !== "number") {
        const knownIds = Object.keys(migratedPrekeys.oneTimePrekeyPrivateById)
          .map((k) => Number(k))
          .filter((n) => Number.isFinite(n));
        migratedPrekeys.nextOneTimePrekeyId = knownIds.length ? Math.max(...knownIds) + 1 : 1;
      }
      const migrated: SessionState = {
        username: p.username,
        prekeyAuthToken: typeof p.prekeyAuthToken === "string" ? p.prekeyAuthToken : "",
        identityPublic: p.identityPublic,
        identityPrivate: p.identityPrivate,
        identityDhPublic: p.identityDhPublic,
        identityDhPrivate: p.identityDhPrivate,
        prekeys: migratedPrekeys,
      };
      return migrated;
    }
    return null;
  } catch {
    return null;
  }
}

function persistRoots(roots: Record<string, string>): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(ROOTS_KEY, JSON.stringify(roots));
  } catch {
    /* ignore */
  }
}

function loadPersistedRoots(): Record<string, string> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(ROOTS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === "string") out[k] = v;
      }
      return out;
    }
    return {};
  } catch {
    return {};
  }
}

function isRatchetInitiator(self: string, peer: string): boolean {
  const [first] = [self, peer].sort((x, y) => x.localeCompare(y));
  return self === first;
}

export type ChatLine = {
  id: string;
  direction: "out" | "in";
  at: number;
  plain?: string;
  ciphertextB64: string;
  cipherPreview: string;
  from?: string;
  decryptError?: string;
  header?: DREnvelope["header"];
  x3dh?: DREnvelope["x3dh"];
  debug?: DREnvelope["debug"];
};

function previewCipher(b64: string, len = 56): string {
  if (b64.length <= len) return b64;
  return `${b64.slice(0, len)}…`;
}

function initials(name: string): string {
  const t = name.trim();
  if (!t) return "?";
  const parts = t.split(/\s+/);
  if (parts.length >= 2) {
    return (parts[0]![0]! + parts[1]![0]!).toUpperCase();
  }
  return t.slice(0, 2).toUpperCase();
}

function formatTime(ts: number): string {
  try {
    return new Date(ts).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  } catch {
    return "";
  }
}

function formatListTime(iso: string): string {
  if (!iso) return "";
  const d = Date.parse(iso);
  if (Number.isNaN(d)) return "";
  const now = new Date();
  const day = new Date(d);
  if (day.toDateString() === now.toDateString()) {
    return formatTime(d);
  }
  return day.toLocaleDateString([], { month: "short", day: "numeric" });
}

function mergeChatsWithActivePeer(server: ChatPartner[], activePeer: string): ChatPartner[] {
  const map = new Map(server.map((c) => [c.peer, { ...c }]));
  if (activePeer && !map.has(activePeer)) {
    map.set(activePeer, { peer: activePeer, lastMessageAt: new Date().toISOString() });
  }
  return Array.from(map.values()).sort((a, b) => b.lastMessageAt.localeCompare(a.lastMessageAt));
}

function asEnvelope(raw: unknown): DREnvelope | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const header = o.header;
  const ciphertext = o.ciphertext;
  if (!header || typeof header !== "object" || typeof ciphertext !== "string") {
    return null;
  }
  const h = header as Record<string, unknown>;
  const x3dhRaw = o.x3dh;
  const debugRaw = o.debug;
  let x3dh: DREnvelope["x3dh"] | undefined;
  let debug: DREnvelope["debug"] | undefined;
  if (x3dhRaw && typeof x3dhRaw === "object") {
    const x = x3dhRaw as Record<string, unknown>;
    if (typeof x.ephPublicKey === "string") {
      x3dh = {
        ephPublicKey: x.ephPublicKey,
          usedSignedPreKeyPublicKey:
            typeof x.usedSignedPreKeyPublicKey === "string"
              ? x.usedSignedPreKeyPublicKey
              : undefined,
        usedOneTimePrekeyId:
          typeof x.usedOneTimePrekeyId === "number" ? x.usedOneTimePrekeyId : undefined,
      };
    }
  }
  if (debugRaw && typeof debugRaw === "object") {
    const d = debugRaw as Record<string, unknown>;
    if (
      (d.role === "send" || d.role === "recv") &&
      typeof d.messageKeyFp === "string" &&
      typeof d.chainKeyFp === "string"
    ) {
      debug = {
        role: d.role,
        messageKeyFp: d.messageKeyFp,
        chainKeyFp: d.chainKeyFp,
      };
    }
  }
  return {
    header: {
      dhPub: typeof h.dhPub === "string" ? h.dhPub : "",
      n: Number(h.n),
      pn: Number(h.pn ?? 0),
    },
    ciphertext,
    x3dh,
    debug,
  };
}

async function replayConversation(
  self: string,
  rootKeyB64: string,
  initiator: boolean,
  msgs: ReceivedMessage[],
  persisted?: PersistedThread
): Promise<{ lines: ChatLine[]; ratchet: DoubleRatchet; lastMessageId: number }> {
  let dr: DoubleRatchet;
  let lines: ChatLine[] = [];
  const sorted = [...msgs].sort((a, b) => a.id - b.id);
  let toProcess = sorted;

  // Plaintexts of our OWN previously-sent messages are stored locally as soon
  // as we encrypt them (sender knows the plaintext — there is no need to
  // "re-decrypt" via the ratchet). Trying to do so would also fail after any
  // ratchet reset, since the local DH key the message was encrypted under is
  // gone for good.
  const ownPlaintextById = new Map<string, string>();
  if (persisted?.lines) {
    for (const line of persisted.lines) {
      if (line.direction === "out" && typeof line.plain === "string") {
        ownPlaintextById.set(line.id, line.plain);
      }
    }
  }

  if (persisted) {
    try {
      dr = DoubleRatchet.fromSerialized(persisted.ratchet);
      lines = [...persisted.lines];
      toProcess = sorted.filter((m) => m.id > persisted.lastMessageId);
    } catch {
      dr = await DoubleRatchet.fromRootKey(rootKeyB64, initiator);
      lines = [];
      toProcess = sorted;
    }
  } else {
    dr = await DoubleRatchet.fromRootKey(rootKeyB64, initiator);
  }

  for (const m of toProcess) {
    const env = asEnvelope(m.message);
    const ct =
      env?.ciphertext ??
      (typeof m.message === "string" ? m.message : JSON.stringify(m.message));
    const id = `srv-${m.id}`;
    const isOut = m.from === self;
    const at = Date.parse(m.createdAt) || Date.now();

    if (!env) {
      lines.push({
        id,
        direction: isOut ? "out" : "in",
        at,
        ciphertextB64: ct,
        cipherPreview: previewCipher(ct),
        from: isOut ? undefined : m.from,
        decryptError: "Invalid message envelope",
      });
      continue;
    }

    if (isOut) {
      const known = ownPlaintextById.get(id);
      lines.push({
        id,
        direction: "out",
        at,
        plain: known,
        ciphertextB64: ct,
        cipherPreview: previewCipher(ct),
        header: env.header,
        x3dh: env.x3dh,
        debug: env.debug,
        decryptError: known
          ? undefined
          : "Sent earlier from another device or before chat history was reset",
      });
      continue;
    }

    try {
      const plain = await dr.decrypt(env);
      lines.push({
        id,
        direction: "in",
        at,
        plain,
        ciphertextB64: ct,
        cipherPreview: previewCipher(ct),
        from: m.from,
        header: env.header,
        x3dh: env.x3dh,
        debug: env.debug,
      });
    } catch (e) {
      lines.push({
        id,
        direction: "in",
        at,
        ciphertextB64: ct,
        cipherPreview: previewCipher(ct),
        from: m.from,
        header: env.header,
        x3dh: env.x3dh,
        debug: env.debug,
        decryptError:
          e instanceof Error ? e.message : "Could not decrypt (ratchet mismatch?)",
      });
    }
  }
  return {
    lines,
    ratchet: dr,
    lastMessageId: sorted.length ? sorted[sorted.length - 1]!.id : 0,
  };
}

export default function Home() {
  const [session, setSession] = useState<SessionState | null>(null);
  const [peer, setPeer] = useState("");
  const [dr, setDr] = useState<DoubleRatchet | null>(null);
  const [lines, setLines] = useState<ChatLine[]>([]);
  const [outgoing, setOutgoing] = useState("");
  const [banner, setBanner] = useState<string>("");
  const [isRightSidebarOpen, setIsRightSidebarOpen] = useState(true);
  const [showInternals, setShowInternals] = useState(false);
  const [showSecrets, setShowSecrets] = useState(false);
  const [chats, setChats] = useState<ChatPartner[]>([]);
  const [chatFilter, setChatFilter] = useState("");
  // Per-peer X3DH-derived root keys. Ref (not state) so writes are visible
  // immediately to any syncConversation call that happens right after.
  const peerRootsRef = useRef<Record<string, string>>({});
  const peerThreadsRef = useRef<Record<string, PersistedThread>>({});
  const bundleCacheRef = useRef<Map<string, PrekeyBundle>>(new Map());
  const openSeq = useRef(0);

  useEffect(() => {
    initSodium().catch(console.error);
    const saved = loadPersistedSession();
    if (saved) setSession(saved);
    peerRootsRef.current = loadPersistedRoots();
    peerThreadsRef.current = loadPersistedThreads();
  }, []);

  const syncConversation = useCallback(
    async (
      peerName: string,
      onSuccess?: (count: number) => string | null | undefined,
      /** If provided, run after network + decrypt; skip applying state when false (stale switch). */
      shouldApply?: () => boolean
    ) => {
      if (!session) return;
      const initiator = isRatchetInitiator(session.username, peerName);
      const msgs = await fetchConversation(session.username, peerName);
      let rootKeyB64 = peerRootsRef.current[peerName];

      // If we don't have a cached root yet, try to reconstruct it as RESPONDER
      // from the peer's first message (which must carry the X3DH handshake).
      if (!rootKeyB64 && msgs.length > 0) {
        const sorted = [...msgs].sort((a, b) => a.id - b.id);
        // IMPORTANT: only use messages FROM THE PEER. Our own outgoing message
        // also carries x3dh but we can't "respond" to ourselves.
        const firstFromPeer = sorted.find((m) => m.from === peerName);
        const env = firstFromPeer ? asEnvelope(firstFromPeer.message) : null;
        const handshake = env?.x3dh;
        if (handshake?.ephPublicKey) {
          let senderBundle = bundleCacheRef.current.get(peerName);
          if (!senderBundle) {
            senderBundle = await fetchBundle(peerName);
            bundleCacheRef.current.set(peerName, senderBundle);
          }
          rootKeyB64 = await deriveX3DHAsResponder({
            selfPrekeys: session.prekeys,
            peerIdentityDhPublic: senderBundle.identityDhKey,
            ephPublicKey: handshake.ephPublicKey,
            usedSignedPreKeyPublicKey: handshake.usedSignedPreKeyPublicKey,
            usedOneTimePrekeyId: handshake.usedOneTimePrekeyId,
          });
          peerRootsRef.current[peerName] = rootKeyB64;
          persistRoots(peerRootsRef.current);
        }
      }

      // No session yet (e.g. just opened a brand-new chat with nothing sent).
      // Leave the thread empty; sendMessage will initialize via X3DH as initiator.
      if (!rootKeyB64) {
        if (shouldApply && !shouldApply()) return;
        setDr(null);
        setLines([]);
        if (peerThreadsRef.current[peerName]) {
          delete peerThreadsRef.current[peerName];
          persistThreads(peerThreadsRef.current);
        }
        if (onSuccess) {
          const msg = onSuccess(0);
          if (msg) {
            if (shouldApply && !shouldApply()) return;
            setBanner(msg);
            setTimeout(() => setBanner(""), 2800);
          }
        }
        return;
      }

      const persisted = peerThreadsRef.current[peerName];
      const { lines: nextLines, ratchet, lastMessageId } = await replayConversation(
        session.username,
        rootKeyB64,
        initiator,
        msgs,
        persisted
      );
      peerThreadsRef.current[peerName] = {
        ratchet: ratchet.serialize(),
        lastMessageId,
        lines: nextLines,
      };
      persistThreads(peerThreadsRef.current);
      if (shouldApply && !shouldApply()) return;
      setDr(ratchet);
      setLines(nextLines);
      if (onSuccess) {
        const msg = onSuccess(msgs.length);
        if (msg) {
          if (shouldApply && !shouldApply()) return;
          setBanner(msg);
          setTimeout(() => setBanner(""), 2800);
        }
      }
    },
    [session]
  );

  const refreshChats = useCallback(
    async (activePeerForMerge: string) => {
      if (!session) return;
      try {
        const server = await fetchChatPartners(session.username);
        setChats(mergeChatsWithActivePeer(server, activePeerForMerge));
      } catch {
        /* keep list */
      }
    },
    [session]
  );

  useEffect(() => {
    if (!session) return;
    void refreshChats("");
  }, [session, refreshChats]);

  const maintainLocalPrekeys = useCallback(async () => {
    if (!session) return;
    try {
      const ownBundle = await fetchBundle(session.username);
      const nextPrekeys: LocalPrekeyMaterial = {
        ...session.prekeys,
        signedPreKeyPrivateByPublic: {
          ...(session.prekeys.signedPreKeyPrivateByPublic ?? {}),
        },
        oneTimePrekeyPrivateById: {
          ...session.prekeys.oneTimePrekeyPrivateById,
        },
      };
      let changed = false;

      const knownOpkIds = Object.keys(nextPrekeys.oneTimePrekeyPrivateById)
        .map((k) => Number(k))
        .filter((n) => Number.isFinite(n));
      let nextId =
        typeof nextPrekeys.nextOneTimePrekeyId === "number"
          ? nextPrekeys.nextOneTimePrekeyId
          : (knownOpkIds.length ? Math.max(...knownOpkIds) + 1 : 1);

      if (ownBundle.oneTimePrekeys.length < OPK_LOW_WATERMARK) {
        const generated = await generateOneTimePrekeys(nextId, OPK_BATCH_SIZE);
        await replenishOneTimePrekeys({
          username: session.username,
          authToken: session.prekeyAuthToken,
          oneTimePrekeys: generated.public,
        });
        Object.assign(nextPrekeys.oneTimePrekeyPrivateById, generated.privateById);
        nextId = generated.nextId;
        nextPrekeys.nextOneTimePrekeyId = nextId;
        changed = true;
      }

      const now = Date.now();
      const rotatedAt = nextPrekeys.signedPreKeyRotatedAt ?? 0;
      if (now - rotatedAt >= SIGNED_PREKEY_ROTATE_INTERVAL_MS) {
        const freshSpk = await generateSignedPreKeyMaterial(session.identityPrivate);
        await rotateSignedPreKey({
          username: session.username,
          authToken: session.prekeyAuthToken,
          signedPreKey: {
            publicKey: freshSpk.publicKey,
            signature: freshSpk.signature,
          },
        });
        nextPrekeys.signedPreKeyPrivate = freshSpk.privateKey;
        nextPrekeys.signedPreKeyPrivateByPublic = {
          ...(nextPrekeys.signedPreKeyPrivateByPublic ?? {}),
          [freshSpk.publicKey]: freshSpk.privateKey,
        };
        nextPrekeys.signedPreKeyRotatedAt = now;
        changed = true;
      }

      if (changed) {
        const nextSession: SessionState = { ...session, prekeys: nextPrekeys };
        setSession(nextSession);
        persistSession(nextSession);
      }
    } catch {
      // Keep chat usable even if maintenance calls fail.
    }
  }, [session]);

  useEffect(() => {
    if (!session) return;
    void maintainLocalPrekeys();
  }, [session, maintainLocalPrekeys]);

  async function openChatWithPeer(peerName: string) {
    if (!session) return;
    const self = session.username;
    if (peerName === self) {
      alert("Pick someone other than yourself.");
      return;
    }

    if (peerName === peer && dr) {
      setBanner("Refreshing…");
      try {
        const target = peerName;
        await syncConversation(target, () => null, () => target === peer);
        await refreshChats(peerName);
      } catch {
        setBanner("Could not refresh this chat");
        setTimeout(() => setBanner(""), 3000);
      } finally {
        setBanner("");
      }
      return;
    }

    const seq = ++openSeq.current;
    setPeer(peerName);
    setLines([]);
    setDr(null);
    setOutgoing("");
    setBanner("Opening chat…");

    let bundle: PrekeyBundle;
    try {
      bundle = await fetchBundle(peerName);
      bundleCacheRef.current.set(peerName, bundle);
    } catch {
      if (seq !== openSeq.current) return;
      setPeer("");
      setLines([]);
      setDr(null);
      setBanner("");
      alert(
        `Could not load "${peerName}". They may need to register in the app first.`
      );
      return;
    }

    if (seq !== openSeq.current) return;

    const ok = await verifyBundle(bundle);
    if (!ok) {
      if (seq !== openSeq.current) return;
      setPeer("");
      setLines([]);
      setDr(null);
      setBanner("");
      alert("Peer bundle signature invalid");
      return;
    }

    try {
      await syncConversation(
        peerName,
        (n) =>
          n === 0
            ? "Chat ready — send first message to complete X3DH"
            : `Loaded ${n} message(s)`,
        () => seq === openSeq.current
      );
    } catch {
      if (seq !== openSeq.current) return;
      setDr(null);
      setLines([]);
      setBanner("Could not load history");
      setTimeout(() => setBanner(""), 3000);
    }

    if (seq !== openSeq.current) return;
    await refreshChats(peerName);
  }

  const refreshConversationQuiet = useCallback(async () => {
    if (!session || !peer) return;
    const target = peer;
    try {
      await syncConversation(target, undefined, () => target === peer);
    } catch {
      if (target !== peer) return;
      setBanner("Could not sync — will retry");
      setTimeout(() => setBanner(""), 3500);
    }
  }, [session, peer, syncConversation]);

  useEffect(() => {
    if (!session || !peer) return;
    const t = setInterval(() => {
      void refreshConversationQuiet();
    }, 5000);
    return () => clearInterval(t);
  }, [session, peer, refreshConversationQuiet]);

  async function sendMessage() {
    if (!session || !peer || !outgoing.trim()) return;
    const text = outgoing.trim();
    let activeDr = dr;
    let handshakeForFirstMessage: DREnvelope["x3dh"];

    // First message with this peer in this session → run X3DH as initiator.
    if (!activeDr) {
      const peerBundle = await reserveBundle(peer);
      bundleCacheRef.current.set(peer, peerBundle);
      const oneTimePrekey = peerBundle.oneTimePrekeys[0];
      const eph = await generateDHKeyPair();
      const rootKeyB64 = await deriveX3DHAsInitiator({
        selfIdentityDhPrivate: session.identityDhPrivate,
        peerBundle,
        ephPrivate: eph.privateKey,
        usedOneTimePrekeyId: oneTimePrekey?.id,
      });
      const initiator = isRatchetInitiator(session.username, peer);
      activeDr = await DoubleRatchet.fromRootKey(rootKeyB64, initiator);
      // Write to the ref *before* await/setState so syncConversation below
      // can see the new root immediately (no stale-closure race).
      peerRootsRef.current[peer] = rootKeyB64;
      persistRoots(peerRootsRef.current);
      setDr(activeDr);
      handshakeForFirstMessage = {
        ephPublicKey: eph.publicKey,
        usedSignedPreKeyPublicKey: peerBundle.signedPreKey.publicKey,
        usedOneTimePrekeyId: oneTimePrekey?.id,
      };
    }

    const env: DREnvelope = await activeDr.encrypt(text);
    if (handshakeForFirstMessage) {
      env.x3dh = handshakeForFirstMessage;
    }

    let sendResult: { id: number; status?: string };
    try {
      sendResult = await sendEncryptedMessage({
        from: session.username,
        to: peer,
        message: env,
      });
    } catch {
      setBanner("Send failed — please try again");
      setTimeout(() => setBanner(""), 3500);
      return;
    }
    const newMsgId = sendResult.id;

    // Persist plaintext immediately so future replays never need to "decrypt"
    // our own message via the sending chain.
    const currentThread = peerThreadsRef.current[peer];
    const newLine: ChatLine = {
      id: `srv-${newMsgId}`,
      direction: "out",
      at: Date.now(),
      plain: text,
      ciphertextB64: env.ciphertext,
      cipherPreview: previewCipher(env.ciphertext),
      header: env.header,
      x3dh: env.x3dh,
      debug: env.debug,
    };
    const baseLines = (currentThread?.lines ?? []).filter((l) => l.id !== newLine.id);
    const newLines = [...baseLines, newLine];
    peerThreadsRef.current[peer] = {
      ratchet: activeDr.serialize(),
      lastMessageId: Math.max(currentThread?.lastMessageId ?? 0, newMsgId),
      lines: newLines,
    };
    persistThreads(peerThreadsRef.current);
    setLines(newLines);
    setDr(activeDr);
    setOutgoing("");

    try {
      const target = peer;
      await syncConversation(target, undefined, () => target === peer);
      if (target === peer) await refreshChats(peer);
    } catch {
      setBanner("Message sent — sync will retry automatically");
      setTimeout(() => setBanner(""), 4000);
    }
  }

  const lastPreview = useMemo(() => {
    if (!lines.length) return "No messages yet";
    const last = lines[lines.length - 1]!;
    if (last.decryptError) return "Unable to decrypt preview";
    return last.plain?.slice(0, 48) ?? "Encrypted";
  }, [lines]);

  const lastAt = lines.length ? lines[lines.length - 1]!.at : Date.now();

  const filteredChats = useMemo(() => {
    const q = chatFilter.trim().toLowerCase();
    if (!q) return chats;
    return chats.filter((c) => c.peer.toLowerCase().includes(q));
  }, [chats, chatFilter]);

  const internalSnapshot = useMemo(() => {
    const currentRoot = peer ? peerRootsRef.current[peer] : undefined;
    const currentThread = peer ? peerThreadsRef.current[peer] : undefined;
    const ratchetState = dr ? dr.serialize() : null;
    return {
      session: session
        ? {
            username: session.username,
            prekeyAuthToken: showSecrets ? session.prekeyAuthToken : "***",
            identityPublic: session.identityPublic,
            identityPrivate: showSecrets ? session.identityPrivate : "***",
            identityDhPublic: session.identityDhPublic,
            identityDhPrivate: showSecrets ? session.identityDhPrivate : "***",
            prekeys: {
              signedPreKeyRotatedAt: session.prekeys.signedPreKeyRotatedAt ?? null,
              nextOneTimePrekeyId: session.prekeys.nextOneTimePrekeyId ?? null,
              signedPreKeyPrivate: showSecrets
                ? (session.prekeys.signedPreKeyPrivate ?? null)
                : "***",
              signedPreKeyPrivateByPublicCount: Object.keys(
                session.prekeys.signedPreKeyPrivateByPublic ?? {}
              ).length,
              oneTimePrekeyPrivateCount: Object.keys(
                session.prekeys.oneTimePrekeyPrivateById ?? {}
              ).length,
            },
          }
        : null,
      activePeer: peer || null,
      peerRootKey: showSecrets ? (currentRoot ?? null) : currentRoot ? "***" : null,
      ratchet: ratchetState
        ? {
            v: ratchetState.v,
            sendingN: ratchetState.sendingN,
            receivingN: ratchetState.receivingN,
            previousSendingChainLength: ratchetState.previousSendingChainLength,
            localDhPublic: ratchetState.localDh.publicKey,
            localDhPrivate: showSecrets ? ratchetState.localDh.privateKey : "***",
            remoteDhPub: ratchetState.remoteDhPub,
            rootKey: showSecrets ? ratchetState.rootKey : "***",
            sendingChainKey: showSecrets ? ratchetState.sendingChainKey : "***",
            receivingChainKey: showSecrets ? ratchetState.receivingChainKey : "***",
            skippedMessageKeyCount: Object.keys(ratchetState.skippedMessageKeys).length,
          }
        : null,
      persistedThread: currentThread
        ? {
            lastMessageId: currentThread.lastMessageId,
            persistedLines: currentThread.lines.length,
          }
        : null,
    };
  }, [dr, peer, session, showSecrets]);

  const protocolMessageLog = useMemo(() => {
    return lines.map((line) => ({
      id: line.id,
      direction: line.direction,
      at: line.at,
      header: line.header
        ? {
            dhPub: line.header.dhPub ? `${line.header.dhPub.slice(0, 20)}...` : "∅",
            n: line.header.n,
            pn: line.header.pn,
          }
        : null,
      x3dh: line.x3dh
        ? {
            ephPublicKey: `${line.x3dh.ephPublicKey.slice(0, 20)}...`,
            usedSignedPreKeyPublicKey: line.x3dh.usedSignedPreKeyPublicKey
              ? `${line.x3dh.usedSignedPreKeyPublicKey.slice(0, 20)}...`
              : null,
            usedOneTimePrekeyId: line.x3dh.usedOneTimePrekeyId ?? null,
          }
        : null,
      ratchet: line.debug
        ? {
            role: line.debug.role,
            messageKeyFp: line.debug.messageKeyFp,
            chainKeyFp: line.debug.chainKeyFp,
          }
        : null,
    }));
  }, [lines]);

  async function handleRegister(username: string) {
    const { publicKey, privateKey } = await generateIdentityKeyPair();
    const { publicKey: identityDhPublic, privateKey: identityDhPrivate } =
      await generateDHKeyPair();
    const bundleInfo = await generatePrekeyBundle(
      username,
      publicKey,
      identityDhPublic,
      identityDhPrivate,
      privateKey
    );
    const reg = await registerBundle({
      username,
      identityKey: bundleInfo.identityKey,
      identityDhKey: bundleInfo.identityDhKey,
      signedPreKey: bundleInfo.signedPreKey,
      oneTimePrekeys: bundleInfo.oneTimePrekeys,
    });
    const next: SessionState = {
      username,
      prekeyAuthToken: reg.prekeyAuthToken,
      identityPublic: publicKey,
      identityPrivate: privateKey,
      identityDhPublic,
      identityDhPrivate,
      prekeys: bundleInfo.private,
    };
    setSession(next);
    persistSession(next);
    // Fresh registration invalidates old per-peer roots (different identity keys).
    peerRootsRef.current = {};
    persistRoots(peerRootsRef.current);
    peerThreadsRef.current = {};
    persistThreads(peerThreadsRef.current);
  }

  if (!session) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#eceff4] p-6">
        <div className="w-full max-w-md rounded-2xl border border-slate-200/80 bg-white p-8 shadow-sm">
          <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
            CS 588 · Secure messaging
          </div>
          <h1 className="mb-1 text-2xl font-semibold tracking-tight text-slate-900">
            Register
          </h1>
          <p className="mb-8 text-sm text-slate-600">
            Keys stay in your browser. Only your public bundle is stored on the server.
          </p>
          <RegisterForm onRegister={handleRegister} />
        </div>
      </div>
    );
  }

  return (
    <div
      className={`grid h-screen grid-cols-1 overflow-hidden bg-[#eceff4] text-slate-800 ${
        isRightSidebarOpen
          ? "lg:grid-cols-[minmax(260px,300px)_minmax(0,1fr)_minmax(360px,440px)]"
          : "lg:grid-cols-[minmax(260px,300px)_minmax(0,1fr)_68px]"
      }`}
    >
      {/* Left — conversations */}
      <aside className="flex min-h-0 flex-col overflow-hidden border-slate-200/90 bg-[#f0f2f5] lg:border-r">
        <div className="flex items-center gap-3 border-b border-slate-200/80 p-4">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-slate-300/90 text-sm font-semibold text-slate-700">
            {initials(session.username)}
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate font-semibold text-slate-900">{session.username}</div>
            <div className="truncate text-xs text-slate-500">End-to-end encrypted session</div>
          </div>
        </div>
        <div className="p-3">
          <div className="relative">
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">
              <IconSearch className="h-4 w-4" />
            </span>
            <input
              type="search"
              value={chatFilter}
              onChange={(e) => setChatFilter(e.target.value)}
              placeholder="Search chats…"
              className="w-full rounded-xl border border-slate-200/90 bg-white py-2.5 pl-9 pr-3 text-sm text-slate-800 placeholder:text-slate-400 shadow-sm outline-none ring-blue-500/20 focus:ring-2"
              aria-label="Filter chats by name"
            />
          </div>
        </div>
        <div className="min-h-0 flex-1 space-y-2 overflow-y-auto px-3 pb-3">
          {filteredChats.length === 0 ? (
            <p className="rounded-xl bg-white/60 p-4 text-center text-sm text-slate-500 ring-1 ring-slate-200/50">
              {chats.length === 0
                ? "No conversations yet. Open a new chat below, or pick someone you have messaged before once they appear here."
                : "No chats match your search."}
            </p>
          ) : (
            filteredChats.map((c) => {
              const active = c.peer === peer;
              const subtitle =
                active && lines.length
                  ? lastPreview
                  : active
                    ? "No messages yet"
                    : formatListTime(c.lastMessageAt) || "—";
              const timeLabel =
                active && lines.length ? formatTime(lastAt) : formatListTime(c.lastMessageAt);
              return (
                <button
                  key={c.peer}
                  type="button"
                  onClick={() => void openChatWithPeer(c.peer)}
                  className={`flex w-full items-center gap-3 rounded-xl border p-3 text-left shadow-sm transition ${
                    active
                      ? "border-white bg-white ring-2 ring-blue-200/80"
                      : "border-transparent bg-white/90 ring-1 ring-slate-200/50 hover:bg-white"
                  }`}
                >
                  <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-sky-200/80 text-sm font-semibold text-sky-900">
                    {initials(c.peer)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-semibold text-slate-900">{c.peer}</span>
                      <span className="shrink-0 text-xs text-slate-500">{timeLabel}</span>
                    </div>
                    <p className="truncate text-sm text-slate-500">{subtitle}</p>
                  </div>
                </button>
              );
            })
          )}
        </div>
        <div className="mt-auto border-t border-slate-200/80 p-3">
          <NewChatForm onOpen={(name) => openChatWithPeer(name)} />
        </div>
      </aside>

      {/* Center — thread */}
      <main className="flex h-full min-h-0 flex-col overflow-hidden bg-white">
        <header className="flex items-center justify-between gap-3 border-b border-slate-100 px-4 py-3 md:px-6">
          <div className="flex min-w-0 items-center gap-3">
            {peer ? (
              <>
                <div className="hidden h-10 w-10 shrink-0 items-center justify-center rounded-full bg-sky-100 text-sm font-semibold text-sky-800 sm:flex">
                  {initials(peer)}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h2 className="truncate text-lg font-semibold text-slate-900">{peer}</h2>
                    <span
                      className="h-2 w-2 shrink-0 rounded-full bg-emerald-500"
                      title="Session active"
                      aria-hidden
                    />
                  </div>
                  <p className="text-xs text-slate-500">Plaintext in bubbles · ciphertext stored on server</p>
                </div>
              </>
            ) : (
              <h2 className="text-lg font-semibold text-slate-400">Select a conversation</h2>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-1 text-slate-400">
            <IconButton label="Search">
              <IconSearch className="h-5 w-5" />
            </IconButton>
            <IconButton label="Favorites">
              <IconHeart className="h-5 w-5" />
            </IconButton>
            <IconButton label="Notifications">
              <IconBell className="h-5 w-5" />
            </IconButton>
          </div>
        </header>

        {banner ? (
          <div className="border-b border-slate-100 bg-sky-50 px-4 py-2 text-center text-sm text-sky-900 md:px-6">
            {banner}
          </div>
        ) : null}

        <div className="flex min-h-0 flex-1 flex-col">
          <div className="flex-1 space-y-1 overflow-y-auto px-4 py-4 md:px-6">
            {!peer && (
              <p className="py-12 text-center text-sm text-slate-400">
                Choose a chat on the left, or open a new conversation. The active thread syncs in
                the background every few seconds.
              </p>
            )}
            {peer && lines.length === 0 && (
              <p className="py-12 text-center text-sm text-slate-400">
                No messages yet. Say hello — ciphertext appears under each bubble for the demo.
              </p>
            )}
            {peer && lines.length > 0 && (
              <div className="mb-4 flex items-center gap-3">
                <div className="h-px flex-1 bg-slate-200" />
                <span className="text-xs font-medium text-slate-400">Conversation</span>
                <div className="h-px flex-1 bg-slate-200" />
              </div>
            )}
            {lines.map((line) => (
              <article
                key={line.id}
                className={`mb-4 flex gap-2 ${line.direction === "out" ? "flex-row-reverse" : "flex-row"}`}
              >
                <div
                  className={`mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${
                    line.direction === "out"
                      ? "bg-blue-100 text-blue-800"
                      : "bg-sky-100 text-sky-900"
                  }`}
                >
                  {initials(line.direction === "out" ? session.username : line.from ?? peer)}
                </div>
                <div className={`flex max-w-[min(100%,28rem)] flex-col gap-1.5 ${line.direction === "out" ? "items-end" : "items-start"}`}>
                  <div
                    className={
                      line.direction === "out"
                        ? "rounded-2xl rounded-tr-sm bg-[#1c6fe6] px-4 py-2.5 text-[15px] leading-relaxed text-white shadow-sm"
                        : "rounded-2xl rounded-tl-sm bg-[#e3f2fd] px-4 py-2.5 text-[15px] leading-relaxed text-slate-900 shadow-sm"
                    }
                  >
                    {line.direction === "in" && line.from && (
                      <div className="mb-1 text-[11px] font-medium text-sky-800/90">
                        {line.from}
                      </div>
                    )}
                    {line.plain && <p>{line.plain}</p>}
                    {line.decryptError && (
                      <p className="text-sm text-rose-100">{line.decryptError}</p>
                    )}
                  </div>
                  <div
                    className={`max-w-full rounded-lg px-2.5 py-1.5 font-mono text-[10px] leading-snug break-all text-slate-500 ring-1 ring-slate-200/80 ${
                      line.direction === "out" ? "bg-slate-50" : "bg-white"
                    }`}
                  >
                    <span className="mr-1.5 select-none text-slate-400">ciphertext</span>
                    {line.cipherPreview}
                  </div>
                </div>
              </article>
            ))}
          </div>

          <div className="border-t border-slate-100 bg-[#eef6fc] px-3 py-3 md:px-5">
            <div className="mx-auto flex max-w-4xl items-end gap-2">
              <input
                className="min-h-[44px] flex-1 rounded-2xl border border-slate-200/90 bg-white px-4 py-2.5 text-sm text-slate-800 shadow-sm outline-none ring-blue-500/30 placeholder:text-slate-400 focus:ring-2"
                placeholder={peer ? "Write something…" : "Select a chat to send"}
                value={outgoing}
                disabled={!peer}
                onChange={(e) => setOutgoing(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    void sendMessage();
                  }
                }}
              />
              <button
                type="button"
                className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-[#1c6fe6] text-white shadow-md transition hover:bg-[#155dcc] disabled:cursor-not-allowed disabled:opacity-40"
                onClick={() => void sendMessage()}
                disabled={!peer || !outgoing.trim()}
                aria-label="Send"
              >
                <IconSend className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </main>

      {/* Right — peer details + protocol internals */}
      <aside className="hidden min-h-0 overflow-hidden border-l border-slate-200/90 bg-[#f0f2f5] lg:flex lg:flex-col">
        <div className="border-b border-slate-200/80 p-3">
          <button
            type="button"
            onClick={() => setIsRightSidebarOpen((v) => !v)}
            className="w-full rounded-lg border border-slate-300/90 bg-white px-3 py-2 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
          >
            {isRightSidebarOpen ? "Collapse panel" : "<"}
          </button>
        </div>
        {isRightSidebarOpen ? (
          <div className="flex min-h-0 flex-1 flex-col items-center overflow-y-auto px-5 pb-6 pt-4 text-center">
            {/* <div className="mb-4 flex h-24 w-24 items-center justify-center rounded-full bg-sky-100 text-2xl font-semibold text-sky-900">
              {peer ? initials(peer) : "—"}
            </div>
            <h3 className="text-lg font-semibold text-slate-900">{peer || "No peer"}</h3> */}
            <p className="mt-1 text-sm text-slate-500">Chat partner · public keys verified at session start</p>

            <div className="mt-6 h-full w-full rounded-xl border border-slate-200/90 bg-white p-3 text-left shadow-sm">
              <div className="mb-2 flex items-center justify-between gap-2">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Protocol internals
                </p>
                <button
                  type="button"
                  onClick={() => setShowInternals((v) => !v)}
                  className="rounded-md border border-slate-300/90 px-2 py-1 text-[11px] font-semibold text-slate-700 hover:bg-slate-50"
                >
                  {showInternals ? "Hide" : "Show"}
                </button>
              </div>
              {showInternals ? (
                <>
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="text-[11px] text-slate-500">
                      Includes private key material for demo only.
                    </span>
                    <button
                      type="button"
                      onClick={() => setShowSecrets((v) => !v)}
                      className="rounded-md border border-amber-300/90 bg-amber-50 px-2 py-1 text-[11px] font-semibold text-amber-900 hover:bg-amber-100"
                    >
                      {showSecrets ? "Mask secrets" : "Reveal secrets"}
                    </button>
                  </div>
                  <pre className="max-h-60 overflow-auto rounded-lg bg-slate-950 p-3 text-[10px] leading-relaxed text-emerald-200">
                    {JSON.stringify(internalSnapshot, null, 2)}
                  </pre>
                  <div className="mt-3">
                    <p className="mb-1 text-[11px] font-semibold text-slate-600">
                      Per-message protocol log
                    </p>
                    <pre className="max-h-56 overflow-auto rounded-lg bg-slate-900 p-3 text-[10px] leading-relaxed text-sky-200">
                      {JSON.stringify(protocolMessageLog, null, 2)}
                    </pre>
                  </div>
                </>
              ) : (
                <p className="text-xs text-slate-500">
                  Show keys, X3DH metadata, ratchet counters, chain state, and persisted thread status.
                </p>
              )}
            </div>
          </div>
        ) : (
          <div className="flex flex-1 items-center justify-center p-2">
            <span className="rotate-90 text-xs font-semibold uppercase tracking-widest text-slate-500">
              Internals
            </span>
          </div>
        )}
      </aside>
    </div>
  );
}

function IconButton({ label, children }: { label: string; children: ReactNode }) {
  return (
    <button
      type="button"
      className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-100 hover:text-slate-600"
      aria-label={label}
    >
      {children}
    </button>
  );
}

function IconSearch(props: { className?: string }) {
  return (
    <svg className={props.className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M11 18a7 7 0 100-14 7 7 0 000 14z" />
    </svg>
  );
}

function IconHeart(props: { className?: string }) {
  return (
    <svg className={props.className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z"
      />
    </svg>
  );
}

function IconBell(props: { className?: string }) {
  return (
    <svg className={props.className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
      />
    </svg>
  );
}

function IconSend(props: { className?: string }) {
  return (
    <svg className={props.className} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
    </svg>
  );
}

function RegisterForm({ onRegister }: { onRegister: (username: string) => void }) {
  const [name, setName] = useState("");
  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        if (!name.trim()) return;
        onRegister(name.trim());
      }}
    >
      <label className="block text-sm font-medium text-slate-700">
        Username
        <input
          className="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-slate-900 shadow-sm outline-none ring-blue-500/25 placeholder:text-slate-400 focus:ring-2"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="alice"
        />
      </label>
      <button
        type="submit"
        className="w-full rounded-xl bg-[#1c6fe6] py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-[#155dcc]"
      >
        Generate keys & register
      </button>
    </form>
  );
}

function NewChatForm({ onOpen }: { onOpen: (peer: string) => Promise<void> }) {
  const [peerInput, setPeerInput] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <form
      className="space-y-2"
      onSubmit={async (e) => {
        e.preventDefault();
        const name = peerInput.trim();
        if (!name || busy) return;
        setBusy(true);
        try {
          await onOpen(name);
          setPeerInput("");
        } finally {
          setBusy(false);
        }
      }}
    >
      <label className="block text-xs font-medium uppercase tracking-wide text-slate-500">
        New chat
        <input
          className="mt-1.5 w-full rounded-xl border border-slate-200/90 bg-white px-3 py-2.5 text-sm text-slate-800 shadow-sm outline-none ring-blue-500/25 placeholder:text-slate-400 focus:ring-2"
          value={peerInput}
          onChange={(e) => setPeerInput(e.target.value)}
          placeholder="Username"
          disabled={busy}
        />
      </label>
      <button
        type="submit"
        disabled={busy || !peerInput.trim()}
        className="w-full rounded-xl bg-[#1c6fe6] py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-[#155dcc] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {busy ? "Opening…" : "Open chat"}
      </button>
      <p className="text-center text-[11px] leading-snug text-slate-500">
        Opens or switches the active session. Chats with message history appear above.
      </p>
    </form>
  );
}
