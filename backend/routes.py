from __future__ import annotations

import secrets
from typing import List, Dict

from fastapi import APIRouter, HTTPException, Query

from models import (
    RegisterRequest,
    RotateSignedPreKeyRequest,
    ReplenishOneTimePreKeysRequest,
    BundleResponse,
    SignedPreKey,
    OneTimePreKey,
    SendRequest,
)
from storage import (
    ensure_data_files,
    upsert_user_keys,
    get_user_bundle,
    reserve_user_bundle_with_one_time_prekey,
    rotate_user_signed_prekey,
    append_one_time_prekeys,
    store_message,
    get_undelivered_messages,
    get_conversation,
    get_chat_partners,
)


router = APIRouter()


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/register")
async def register(req: RegisterRequest) -> dict:
    """
    Store or update a user's public key bundle (identity key + prekeys).
    Only PUBLIC material is stored here; private keys remain on the client.
    """
    ensure_data_files()

    prekey_auth_token = secrets.token_urlsafe(32)
    upsert_user_keys(
        username=req.username,
        identity_key=req.identityKey,
        identity_dh_key=req.identityDhKey,
        signed_prekey_public=req.signedPreKey.publicKey,
        signed_prekey_signature=req.signedPreKey.signature,
        one_time_prekeys=[pk.model_dump() for pk in req.oneTimePrekeys],
        prekey_auth_token=prekey_auth_token,
    )

    return {
        "username": req.username,
        "status": "registered",
        "prekeyAuthToken": prekey_auth_token,
    }


@router.post("/rotate-signed-prekey")
async def rotate_signed_prekey(req: RotateSignedPreKeyRequest) -> dict:
    """
    Replace the currently advertised signed prekey for a user.
    """
    ensure_data_files()
    ok = rotate_user_signed_prekey(
        req.username,
        req.signedPreKey.publicKey,
        req.signedPreKey.signature,
        req.authToken,
    )
    if not ok:
        raise HTTPException(status_code=403, detail="invalid_prekey_auth")
    return {"username": req.username, "status": "signed_prekey_rotated"}


@router.post("/replenish-one-time-prekeys")
async def replenish_one_time_prekeys(req: ReplenishOneTimePreKeysRequest) -> dict:
    """
    Append additional one-time prekeys to the server-side public bundle.
    """
    ensure_data_files()
    ok = append_one_time_prekeys(
        req.username, [pk.model_dump() for pk in req.oneTimePrekeys], req.authToken
    )
    if not ok:
        raise HTTPException(status_code=403, detail="invalid_prekey_auth")
    return {"username": req.username, "status": "one_time_prekeys_replenished"}


@router.get("/bundle/{username}", response_model=BundleResponse)
async def bundle(username: str) -> BundleResponse:
    """
    Fetch a user's public key bundle for X3DH on the client.
    """
    ensure_data_files()
    row = get_user_bundle(username)
    if row is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    one_time_prekeys_raw = row.get("oneTimePrekeys") or []
    one_time_prekeys = [OneTimePreKey(**pk) for pk in one_time_prekeys_raw]

    return BundleResponse(
        username=row["username"],
        identityKey=row["identityKey"],
        identityDhKey=row.get("identityDhKey", ""),
        signedPreKey=SignedPreKey(
            publicKey=row["signedPreKeyPublic"],
            signature=row["signedPreKeySignature"],
        ),
        oneTimePrekeys=one_time_prekeys,
    )


@router.post("/bundle/{username}/reserve", response_model=BundleResponse)
async def reserve_bundle(username: str) -> BundleResponse:
    """
    Fetch public bundle for session init and consume exactly one one-time prekey.
    If none are available, returns bundle with an empty OPK list.
    """
    ensure_data_files()
    row = reserve_user_bundle_with_one_time_prekey(username)
    if row is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    one_time_prekeys_raw = row.get("oneTimePrekeys") or []
    one_time_prekeys = [OneTimePreKey(**pk) for pk in one_time_prekeys_raw]
    return BundleResponse(
        username=row["username"],
        identityKey=row["identityKey"],
        identityDhKey=row.get("identityDhKey", ""),
        signedPreKey=SignedPreKey(
            publicKey=row["signedPreKeyPublic"],
            signature=row["signedPreKeySignature"],
        ),
        oneTimePrekeys=one_time_prekeys,
    )


@router.post("/send")
async def send_message(req: SendRequest) -> dict:
    """
    Queue an encrypted message for delivery.
    The server treats 'message' as opaque; it never decrypts it.
    """
    ensure_data_files()
    msg_id = store_message(
        sender=req.from_user,
        recipient=req.to_user,
        payload=req.message,
    )
    return {"status": "queued", "id": msg_id}


@router.get("/messages")
async def get_messages(username: str = Query(...)) -> Dict[str, List[dict]]:
    """
    Retrieve all undelivered encrypted messages for the given user.
    Marks them as delivered so they are not returned again.
    """
    ensure_data_files()
    raw_messages = get_undelivered_messages(username)

    # Use JSON keys "from" / "to" (not from_user) so the frontend and Pydantic stay aligned.
    messages = [
        {
            "id": m["id"],
            "from": m["sender"],
            "to": m["recipient"],
            "message": m["payload"],
            "createdAt": m["createdAt"],
        }
        for m in raw_messages
    ]
    return {"messages": messages}


@router.get("/chats")
async def list_chats(username: str = Query(..., description="Current user")) -> Dict[str, List[dict]]:
    """
    All users you have at least one stored message with, most recently active first.
    """
    ensure_data_files()
    chats = get_chat_partners(username)
    return {"chats": chats}


@router.get("/conversation")
async def conversation(
    me: str = Query(..., description="Current user"),
    peer: str = Query(..., description="Other party in the chat"),
) -> Dict[str, List[dict]]:
    """
    Full encrypted history between `me` and `peer` (both directions), oldest first.
    Does not mark messages delivered — use for rebuilding the transcript after reload.
    """
    ensure_data_files()
    raw = get_conversation(me, peer)
    messages = [
        {
            "id": m["id"],
            "from": m["sender"],
            "to": m["recipient"],
            "message": m["payload"],
            "createdAt": m["createdAt"],
        }
        for m in raw
    ]
    return {"messages": messages}

