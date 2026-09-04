"""First-run SaaS database bootstrap."""

from __future__ import annotations

from sqlalchemy import select

from .auth import hash_api_key
from .config import settings
from .db.models import ApiKey, Org
from .db.session import SessionLocal, init_db


def init_structured_data() -> dict[str, str]:
    init_db()
    seeded = _seed_dev_api_key(settings.dev_api_key) if settings.dev_api_key else False
    return {"database": "ready", "dev_api_key": "seeded" if seeded else "skipped"}


def _seed_dev_api_key(raw_key: str) -> bool:
    db = SessionLocal()
    try:
        if db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw_key))):
            return False
        org = db.scalar(select(Org).where(Org.name == "Dev Org")) or Org(name="Dev Org")
        db.add(org)
        db.flush()
        db.add(ApiKey(org_id=org.id, name="dev", key_hash=hash_api_key(raw_key), key_prefix=raw_key[:8]))
        db.commit()
        return True
    finally:
        db.close()
