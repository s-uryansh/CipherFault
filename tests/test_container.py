from pathlib import Path


def test_container_pins_ghidra_and_runs_cipherfault():
    dockerfile = Path("Dockerfile").read_text()

    assert "GHIDRA_VERSION=12.1.2" in dockerfile
    assert "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d" in dockerfile
    assert "CIPHERFAULT_INSTALL_TARGET=." in dockerfile
    assert 'ENTRYPOINT ["cipherfault"]' in dockerfile
