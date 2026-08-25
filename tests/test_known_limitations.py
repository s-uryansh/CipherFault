import sys

import pytest

sys.path.insert(0, "scripts")

import check_known_limitations


def test_known_limitation_check_requires_built_fixture(monkeypatch, tmp_path):
    monkeypatch.setattr(check_known_limitations, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match="run scripts/build_cve_fixtures.sh"):
        check_known_limitations.main()
