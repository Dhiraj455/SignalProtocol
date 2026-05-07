from __future__ import annotations

from typing import Annotated, List, Any, Dict

from pydantic import BaseModel, ConfigDict, Field


class SignedPreKey(BaseModel):
    publicKey: str
    signature: str


class OneTimePreKey(BaseModel):
    id: int
    publicKey: str


class RegisterRequest(BaseModel):
    username: str
    identityKey: str
    identityDhKey: str
    signedPreKey: SignedPreKey
    oneTimePrekeys: List[OneTimePreKey] = Field(default_factory=list)


class RotateSignedPreKeyRequest(BaseModel):
    username: str
    authToken: str
    signedPreKey: SignedPreKey


class ReplenishOneTimePreKeysRequest(BaseModel):
    username: str
    authToken: str
    oneTimePrekeys: List[OneTimePreKey] = Field(default_factory=list)


class BundleResponse(BaseModel):
    username: str
    identityKey: str
    identityDhKey: str
    signedPreKey: SignedPreKey
    oneTimePrekeys: List[OneTimePreKey]


class EncryptedMessage(BaseModel):
    # Double Ratchet header + ciphertext, JSON-safe
    header: Dict[str, Any]
    ciphertext: str


class SendRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_user: Annotated[str, Field(alias="from")]
    to_user: Annotated[str, Field(alias="to")]
    message: Any  # can be EncryptedMessage or any JSON-serializable structure


class MessageEnvelope(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: int
    from_user: Annotated[str, Field(alias="from")]
    to_user: Annotated[str, Field(alias="to")]
    message: Any
    createdAt: str

