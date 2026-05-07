import type { PrekeyBundle } from "./x3dh";
import type { DREnvelope } from "./doubleRatchet";

/**
 * In the browser, default to same-origin `/api` (see next.config rewrites → FastAPI).
 * Set NEXT_PUBLIC_API_URL (e.g. http://localhost:3001) to call the backend directly.
 */
function apiBase(): string {
  if (typeof window === "undefined") {
    return process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://127.0.0.1:3001";
  }
  return process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "/api";
}

export async function registerBundle(payload: {
  username: string;
  identityKey: string;
  identityDhKey: string;
  signedPreKey: { publicKey: string; signature: string };
  oneTimePrekeys: { id: number; publicKey: string }[];
}): Promise<{ username: string; status: string; prekeyAuthToken: string }> {
  const res = await fetch(`${apiBase()}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`register failed: ${res.status}`);
  }
  return res.json();
}

export async function rotateSignedPreKey(payload: {
  username: string;
  authToken: string;
  signedPreKey: { publicKey: string; signature: string };
}) {
  const res = await fetch(`${apiBase()}/rotate-signed-prekey`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`rotate signed prekey failed: ${res.status}`);
  }
  return res.json();
}

export async function replenishOneTimePrekeys(payload: {
  username: string;
  authToken: string;
  oneTimePrekeys: { id: number; publicKey: string }[];
}) {
  const res = await fetch(`${apiBase()}/replenish-one-time-prekeys`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`replenish prekeys failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchBundle(username: string): Promise<PrekeyBundle> {
  const res = await fetch(`${apiBase()}/bundle/${encodeURIComponent(username)}`);
  if (!res.ok) {
    throw new Error(`bundle fetch failed: ${res.status}`);
  }
  return res.json();
}

/**
 * Reserve bundle material for a new initiator session.
 * Server consumes one OPK if available to avoid reuse.
 */
export async function reserveBundle(username: string): Promise<PrekeyBundle> {
  const res = await fetch(`${apiBase()}/bundle/${encodeURIComponent(username)}/reserve`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error(`bundle reserve failed: ${res.status}`);
  }
  return res.json();
}

export async function sendEncryptedMessage(args: {
  from: string;
  to: string;
  message: DREnvelope;
}) {
  const res = await fetch(`${apiBase()}/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!res.ok) {
    throw new Error(`send failed: ${res.status}`);
  }
  return res.json();
}

export type ReceivedMessage = {
  id: number;
  from: string;
  to: string;
  message: DREnvelope;
  createdAt: string;
};

export async function pollMessages(username: string): Promise<ReceivedMessage[]> {
  const res = await fetch(
    `${apiBase()}/messages?username=${encodeURIComponent(username)}`
  );
  if (!res.ok) {
    throw new Error(`messages fetch failed: ${res.status}`);
  }
  const data = await res.json();
  return data.messages ?? [];
}

/** Full encrypted thread between two users (both directions), oldest first. Read-only on server. */
export async function fetchConversation(
  me: string,
  peer: string
): Promise<ReceivedMessage[]> {
  const q = new URLSearchParams({ me, peer });
  const res = await fetch(`${apiBase()}/conversation?${q.toString()}`);
  if (!res.ok) {
    throw new Error(`conversation fetch failed: ${res.status}`);
  }
  const data = await res.json();
  return data.messages ?? [];
}

export type ChatPartner = {
  peer: string;
  lastMessageAt: string;
};

/** Users you have exchanged ciphertext with, most recent first. */
export async function fetchChatPartners(username: string): Promise<ChatPartner[]> {
  const res = await fetch(
    `${apiBase()}/chats?username=${encodeURIComponent(username)}`
  );
  if (!res.ok) {
    throw new Error(`chats list failed: ${res.status}`);
  }
  const data = await res.json();
  return data.chats ?? [];
}

