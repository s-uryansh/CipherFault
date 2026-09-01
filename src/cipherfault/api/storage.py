"""Local upload storage for day-one SaaS development."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi import UploadFile

from .config import settings


def save_upload(upload: UploadFile) -> tuple[str, Path]:
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(upload.filename or "binary").name
    path = settings.storage_dir / f"{uuid4()}-{filename}"
    with path.open("wb") as stream:
        while chunk := upload.file.read(1024 * 1024):
            stream.write(chunk)
    return filename, path
