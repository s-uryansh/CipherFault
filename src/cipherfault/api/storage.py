"""Upload storage for local dev and Supabase-backed demos."""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from typing import Iterator
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import UploadFile

from .config import settings


def save_upload(upload: UploadFile) -> tuple[str, Path]:
    if settings.storage_backend == "supabase":
        return _save_supabase_upload(upload)
    if settings.storage_backend != "local":
        raise RuntimeError(f"unsupported storage backend: {settings.storage_backend}")
    return _save_local_upload(upload)


@contextmanager
def scan_input(storage_path: str) -> Iterator[Path]:
    if settings.storage_backend == "local":
        yield Path(storage_path)
        return
    if settings.storage_backend == "supabase":
        with tempfile.NamedTemporaryFile(prefix="cipherfault-", suffix=Path(storage_path).suffix) as temp:
            temp.write(_supabase_request("GET", _object_url(storage_path)))
            temp.flush()
            yield Path(temp.name)
        return
    raise RuntimeError(f"unsupported storage backend: {settings.storage_backend}")


def delete_upload(storage_path: str) -> None:
    if settings.storage_backend == "local":
        Path(storage_path).unlink(missing_ok=True)
        return
    if settings.storage_backend == "supabase":
        body = json.dumps({"prefixes": [storage_path]}).encode()
        _supabase_request("DELETE", _bucket_url(), body=body, content_type="application/json")
        return
    raise RuntimeError(f"unsupported storage backend: {settings.storage_backend}")


def _save_local_upload(upload: UploadFile) -> tuple[str, Path]:
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(upload.filename or "binary").name
    path = settings.storage_dir / f"{uuid4()}-{filename}"
    with path.open("wb") as stream:
        while chunk := upload.file.read(1024 * 1024):
            stream.write(chunk)
    return filename, path


def _save_supabase_upload(upload: UploadFile) -> tuple[str, Path]:
    filename = Path(upload.filename or "binary").name
    key = f"uploads/{uuid4()}-{filename}"
    data = upload.file.read()
    _supabase_request("POST", _object_url(key), body=data, content_type=upload.content_type or "application/octet-stream")
    return filename, Path(key)


def _object_url(storage_path: str) -> str:
    return f"{_storage_url()}/object/{_bucket()}/{quote(storage_path)}"


def _bucket_url() -> str:
    return f"{_storage_url()}/object/{_bucket()}"


def _storage_url() -> str:
    if not settings.supabase_url:
        raise RuntimeError("CIPHERFAULT_SUPABASE_URL is required for Supabase storage")
    return settings.supabase_url.rstrip("/") + "/storage/v1"


def _bucket() -> str:
    if not settings.supabase_bucket:
        raise RuntimeError("CIPHERFAULT_SUPABASE_BUCKET is required for Supabase storage")
    return quote(settings.supabase_bucket)


def _headers(content_type: str | None = None) -> dict[str, str]:
    if not settings.supabase_key:
        raise RuntimeError("CIPHERFAULT_SUPABASE_KEY is required for Supabase storage")
    headers = {"apikey": settings.supabase_key, "Authorization": f"Bearer {settings.supabase_key}"}
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _supabase_request(method: str, url: str, *, body: bytes | None = None, content_type: str | None = None) -> bytes:
    request = Request(url, data=body, method=method, headers=_headers(content_type))
    try:
        with urlopen(request, timeout=60) as response:
            return response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Supabase storage {method} failed: HTTP {exc.code} {detail}") from exc
