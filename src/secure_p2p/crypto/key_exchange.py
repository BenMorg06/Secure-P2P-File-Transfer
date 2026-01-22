import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class ClientKeyPair:
    """
    Docstring for ClientKeyPair
    """
    def __init__(self, private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey):
        self.private_key = private_key
        self.public_key = public_key

    def set_peer_public_key(self, peer_public_key: x25519.X25519PublicKey):
        self.peer_public_key = peer_public_key

# Ephemeral Key Generation using X25519
def generate_ephemeral_key_pair() -> ClientKeyPair:
    """
    Docstring for generate_ephemeral_key_pair
    
    :return: Description
    :rtype: clientKeyPair
    """
    client_private_key = x25519.X25519PrivateKey.generate()
    client_public_key = client_private_key.public_key()
    return ClientKeyPair(client_private_key, client_public_key)

# Compute Shared Secret 
def compute_shared_secret(private_key: x25519.X25519PrivateKey, peer_public_key: x25519.X25519PublicKey) -> bytes:
    """
    Docstring for compute_shared_secret

    :param private_key: Description
    :type private_key: X25519PrivateKey
    :param peer_public_key: Description
    :type peer_public_key: X25519PublicKey
    :param peer_public_key: Description
    :type peer_public_key: X25519PublicKey
    :return: Description
    :rtype: bytes
    """
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

# Derive Symmetric Key using HKDF
def derive_symmetric_key(shared_secret: bytes, info: bytes=b"secure_p2p") -> bytes:
    """
    Docstring for derive_symmetric_key
    
    :param shared_secret: Description
    :type shared_secret: bytes
    :param info: Description
    :type info: bytes
    :return: Description
    :rtype: bytes
    """
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    ).derive(shared_secret)
    return derived_key