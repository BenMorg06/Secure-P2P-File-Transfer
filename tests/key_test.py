import sys, pytest
from pathlib import Path

sys.path.append(str(Path.home() / "Documents/Secure-P2P-File-Transfer/src/crypto"))
import key_exchange

# TODO Plan tests for key_exchange.py
def test_now():
    assert isinstance(key_exchange.generate_ephemeral_key_pair(), key_exchange.ClientKeyPair)