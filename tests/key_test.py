import sys, pytest
from pathlib import Path

possible_paths = [
    Path.home() / "Documents/Secure-P2P/src/crypto",
    Path.home() / "Documents/Obsidian-Vaults/cortado/Secure-P2P/src/crypto",
]

for path in possible_paths:
    if path.exists():
        sys.path.append(str(path))
        break

import key_exchange


# TODO Plan tests for key_exchange.py
def test_now():
    assert isinstance(
        key_exchange.generate_ephemeral_key_pair(), key_exchange.ClientKeyPair
    )

