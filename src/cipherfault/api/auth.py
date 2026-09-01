"""API-key authentication."""

from __future__ import annotations

from hashlib import sha256
from secrets import compare_digest

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db.models import ApiKey, Org
from .db.session import get_db


def hash_api_key(api_key: str) -> str:
    return sha256(api_key.encode()).hexdigest()


def current_org(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> Org:
    if not x_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing API key")

    key_hash = hash_api_key(x_api_key)
    api_key = db.scalar(select(ApiKey).where(ApiKey.key_hash == key_hash))
    if api_key and compare_digest(api_key.key_hash, key_hash):
        org = db.get(Org, api_key.org_id)
        if org is not None:
            return org
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key")
