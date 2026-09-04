import sys
from io import BytesIO
from types import SimpleNamespace

sys.path.insert(0, "src")

from fastapi import UploadFile

from cipherfault.api import storage


class FakeResponse:
    def __init__(self, body=b""):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.body


def test_supabase_storage_upload_download_and_delete(monkeypatch):
    calls = []
    monkeypatch.setattr(
        storage,
        "settings",
        SimpleNamespace(
            storage_backend="supabase",
            supabase_url="https://ljfowjssdnllcyzpctck.supabase.co",
            supabase_key="test-key",
            supabase_bucket="cipherfault",
        ),
    )

    def fake_urlopen(request, timeout):
        calls.append((request.get_method(), request.full_url, request.data, dict(request.header_items()), timeout))
        return FakeResponse(b"binary-from-storage")

    monkeypatch.setattr(storage, "urlopen", fake_urlopen)

    upload = UploadFile(file=BytesIO(b"\x7fELF\x02\x01" + b"binary"), filename="payment-service.out")
    filename, stored = storage.save_upload(upload, "org-1")

    assert filename == "payment-service.out"
    assert str(stored).startswith("uploads/org-1/")
    assert storage.storage_path_belongs_to_org(str(stored), "org-1")
    assert not storage.storage_path_belongs_to_org(str(stored), "org-2")
    with storage.scan_input(str(stored)) as path:
        assert path.read_bytes() == b"binary-from-storage"
    storage.delete_upload(str(stored))

    methods = [call[0] for call in calls]
    assert methods == ["POST", "GET", "DELETE"]
    assert all("/storage/v1/object/cipherfault/" in call[1] or call[1].endswith("/storage/v1/object/cipherfault") for call in calls)
    assert all(call[3]["Apikey"] == "test-key" for call in calls)


def test_local_storage_rejects_non_elf(monkeypatch, tmp_path):
    monkeypatch.setattr(
        storage,
        "settings",
        SimpleNamespace(
            storage_backend="local",
            storage_dir=tmp_path,
            max_upload_bytes=100,
        ),
    )

    upload = UploadFile(file=BytesIO(b"not-elf"), filename="bad.bin")
    try:
        storage.save_upload(upload, "org-1")
    except ValueError as exc:
        assert "expected a 64-bit little-endian ELF" in str(exc)
    else:
        raise AssertionError("non-ELF upload accepted")

    assert list(tmp_path.rglob("*")) == [tmp_path / "org-1"]


def test_local_storage_rejects_oversized_upload(monkeypatch, tmp_path):
    monkeypatch.setattr(
        storage,
        "settings",
        SimpleNamespace(
            storage_backend="local",
            storage_dir=tmp_path,
            max_upload_bytes=6,
        ),
    )

    upload = UploadFile(file=BytesIO(b"\x7fELF\x02\x01x"), filename="too-big.out")
    try:
        storage.save_upload(upload, "org-1")
    except ValueError as exc:
        assert "upload exceeds" in str(exc)
    else:
        raise AssertionError("oversized upload accepted")
