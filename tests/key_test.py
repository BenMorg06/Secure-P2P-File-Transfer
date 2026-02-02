import sys, pytest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

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

@pytest.fixture
def client_keypair():
    return key_exchange.generate_ephemeral_key_pair()

@pytest.fixture
def receiver_keypair():
    return key_exchange.generate_ephemeral_key_pair()

class TestKeyExchange:

    def test_keypair_generation(self, client_keypair):
        assert isinstance(client_keypair, key_exchange.ClientKeyPair)
        assert isinstance(client_keypair.private_key, x25519.X25519PrivateKey)
        assert isinstance(client_keypair.public_key, x25519.X25519PublicKey)

    def test_shared_secret_computation(self, client_keypair, receiver_keypair):
        shared_secret_1 = key_exchange.compute_shared_secret(
            client_keypair.private_key, receiver_keypair.public_key
        )
        shared_secret_2 = key_exchange.compute_shared_secret(
            receiver_keypair.private_key, client_keypair.public_key
        )
        assert shared_secret_1 == shared_secret_2
        assert len(shared_secret_1) == 32  # X25519 shared secret length

    def test_symmetric_key_derivation(self, client_keypair, receiver_keypair):
        shared_secret = b'fixed_secret_for_testing_32_byte'
        info = b"Test Info"
        symmetric_key = key_exchange.derive_symmetric_key(shared_secret, info)
        assert len(symmetric_key) == 32  # AES-256 key length

    def test_key_derivation_with_different_info(self, client_keypair, receiver_keypair):
        shared_secret = b'fixed_secret_for_testing_32_byte'
        info1 = b"Info One"
        info2 = b"Info Two"
        key1 = key_exchange.derive_symmetric_key(shared_secret, info1)
        key2 = key_exchange.derive_symmetric_key(shared_secret, info2)
        assert key1 != key2

    @pytest.mark.parametrize('client_key, receiver_key',
        [
            (x25519.X25519PrivateKey, "Public Key"),
            ("Private Key", x25519.X25519PublicKey),
            (None, None)
        ]
            
    )
    def test_invalid_secret_computation(self, client_key, receiver_key):
        with pytest.raises(TypeError):
            shared_secret_1 = key_exchange.compute_shared_secret(
                client_key, receiver_key
            )

    # TODO End-to-End computation and derivation test - generate key pairs, comput secret, derive key, compare key
    # TODO Test ephemeral keys are uniqie
    # TODO Test private key secrecy - private_bytes_raw()
    # TODO Test compute secret not all zeros
    # TODO Test Salt as none value
    # TODO Test bad secret cant derive key
    # TODO Ensure keypairs have correct attributes - hasattr(keypair, private)
    # TODO Global State Leakage
    '''
    def test_no_global_state_leakage(client_keypair, receiver_keypair):
    s1 = key_exchange.compute_shared_secret(
        client_keypair.private_key, receiver_keypair.public_key
    )
    s2 = key_exchange.compute_shared_secret(
        client_keypair.private_key, receiver_keypair.public_key
    )
    assert s1 == s2
'''
