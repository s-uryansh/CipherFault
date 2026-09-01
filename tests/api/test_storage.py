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
            supabase_bucket="CipherFault",
        ),
    )

    def fake_urlopen(request, timeout):
        calls.append((request.get_method(), request.full_url, request.data, dict(request.header_items()), timeout))
        return FakeResponse(b"binary-from-storage")

    monkeypatch.setattr(storage, "urlopen", fake_urlopen)

    upload = UploadFile(file=BytesIO(b"binary"), filename="payment-service.out")
    filename, stored = storage.save_upload(upload)

    assert filename == "payment-service.out"
    assert str(stored).startswith("uploads/")
    with storage.scan_input(str(stored)) as path:
        assert path.read_bytes() == b"binary-from-storage"
    storage.delete_upload(str(stored))

    methods = [call[0] for call in calls]
    assert methods == ["POST", "GET", "DELETE"]
    assert all("/storage/v1/object/CipherFault/" in call[1] or call[1].endswith("/storage/v1/object/CipherFault") for call in calls)
    assert all(call[3]["Apikey"] == "test-key" for call in calls)
