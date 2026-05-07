from __future__ import annotations

import hmac
import json
from datetime import datetime
from pathlib import Path
from typing import Any, List, Dict, Optional

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_FILE = DATA_DIR / "user_keys.json"
MESSAGES_FILE = DATA_DIR / "messages.json"


def ensure_data_files() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.exists():
        USERS_FILE.write_text("[]", encoding="utf-8")
    if not MESSAGES_FILE.exists():
        MESSAGES_FILE.write_text("[]", encoding="utf-8")


def _load_json_array(path: Path) -> List[Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def _save_json_array(path: Path, data: List[Any]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def upsert_user_keys(
    *,
    username: str,
    identity_key: str,
    identity_dh_key: str,
    signed_prekey_public: str,
    signed_prekey_signature: str,
    one_time_prekeys: List[Dict[str, Any]],
    prekey_auth_token: str,
) -> None:
    ensure_data_files()
    users = _load_json_array(USERS_FILE)

    record = {
        "username": username,
        "identityKey": identity_key,
        "identityDhKey": identity_dh_key,
        "signedPreKeyPublic": signed_prekey_public,
        "signedPreKeySignature": signed_prekey_signature,
        "oneTimePrekeys": one_time_prekeys,
        "prekeyAuthToken": prekey_auth_token,
    }

    existing_index: Optional[int] = next(
        (i for i, u in enumerate(users) if u.get("username") == username),
        None,
    )
    if existing_index is not None:
        users[existing_index] = record
    else:
        users.append(record)

    _save_json_array(USERS_FILE, users)


def get_user_bundle(username: str) -> Optional[Dict[str, Any]]:
    ensure_data_files()
    users = _load_json_array(USERS_FILE)
    return next((u for u in users if u.get("username") == username), None)


def reserve_user_bundle_with_one_time_prekey(username: str) -> Optional[Dict[str, Any]]:
    """
    Return user's public bundle and consume one one-time prekey if available.
    This prevents repeated OPK reuse across new session initializations.
    """
    ensure_data_files()
    users = _load_json_array(USERS_FILE)
    idx: Optional[int] = next(
        (i for i, u in enumerate(users) if u.get("username") == username),
        None,
    )
    if idx is None:
        return None

    row = users[idx]
    available = row.get("oneTimePrekeys") or []
    selected = available[0] if available else None
    row_copy = {
        **row,
        "oneTimePrekeys": [selected] if selected else [],
    }
    if selected:
        row["oneTimePrekeys"] = available[1:]
        users[idx] = row
        _save_json_array(USERS_FILE, users)
    return row_copy


def rotate_user_signed_prekey(
    username: str,
    signed_prekey_public: str,
    signed_prekey_signature: str,
    auth_token: str,
) -> bool:
    ensure_data_files()
    users = _load_json_array(USERS_FILE)
    idx: Optional[int] = next(
        (i for i, u in enumerate(users) if u.get("username") == username),
        None,
    )
    if idx is None:
        return False
    row = users[idx]
    expected = row.get("prekeyAuthToken")
    if not isinstance(expected, str) or not hmac.compare_digest(expected, auth_token):
        return False
    row["signedPreKeyPublic"] = signed_prekey_public
    row["signedPreKeySignature"] = signed_prekey_signature
    users[idx] = row
    _save_json_array(USERS_FILE, users)
    return True


def append_one_time_prekeys(
    username: str, one_time_prekeys: List[Dict[str, Any]], auth_token: str
) -> bool:
    ensure_data_files()
    users = _load_json_array(USERS_FILE)
    idx: Optional[int] = next(
        (i for i, u in enumerate(users) if u.get("username") == username),
        None,
    )
    if idx is None:
        return False
    row = users[idx]
    expected = row.get("prekeyAuthToken")
    if not isinstance(expected, str) or not hmac.compare_digest(expected, auth_token):
        return False
    existing = row.get("oneTimePrekeys") or []
    row["oneTimePrekeys"] = existing + one_time_prekeys
    users[idx] = row
    _save_json_array(USERS_FILE, users)
    return True


def store_message(*, sender: str, recipient: str, payload: Any) -> int:
    ensure_data_files()
    messages = _load_json_array(MESSAGES_FILE)

    next_id = max((m.get("id", 0) for m in messages), default=0) + 1
    envelope = {
        "id": next_id,
        "sender": sender,
        "recipient": recipient,
        "payload": payload,
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "delivered": False,
    }
    messages.append(envelope)
    _save_json_array(MESSAGES_FILE, messages)
    return next_id


def get_undelivered_messages(username: str) -> List[Dict[str, Any]]:
    ensure_data_files()
    messages = _load_json_array(MESSAGES_FILE)

    undelivered = [
        m for m in messages if m.get("recipient") == username and not m.get("delivered")
    ]
    if undelivered:
        delivered_ids = {m["id"] for m in undelivered}
        updated = [
            {**m, "delivered": True} if m.get("id") in delivered_ids else m
            for m in messages
        ]
        _save_json_array(MESSAGES_FILE, updated)

    return undelivered


def get_conversation(user_a: str, user_b: str) -> List[Dict[str, Any]]:
    """
    All messages between two users (both directions), oldest first.
    Read-only: does not change delivered flags.
    """
    ensure_data_files()
    messages = _load_json_array(MESSAGES_FILE)
    pair = {user_a, user_b}
    between = [
        m
        for m in messages
        if {m.get("sender"), m.get("recipient")} == pair
    ]
    between.sort(key=lambda m: m.get("id", 0))
    return between


def get_chat_partners(username: str) -> List[Dict[str, Any]]:
    """
    Distinct users who have exchanged messages with `username`, with last activity time.
    Sorted by most recent first (by createdAt string, ISO-8601 comparable).
    """
    ensure_data_files()
    messages = _load_json_array(MESSAGES_FILE)
    last_by_peer: Dict[str, str] = {}
    for m in messages:
        s = m.get("sender")
        r = m.get("recipient")
        if not isinstance(s, str) or not isinstance(r, str):
            continue
        if s == username:
            peer = r
        elif r == username:
            peer = s
        else:
            continue
        created = m.get("createdAt") or ""
        prev = last_by_peer.get(peer)
        if prev is None or created > prev:
            last_by_peer[peer] = created
    rows = [{"peer": p, "lastMessageAt": t} for p, t in last_by_peer.items()]
    rows.sort(key=lambda row: row["lastMessageAt"], reverse=True)
    return rows

