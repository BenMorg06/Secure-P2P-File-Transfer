import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# TODO Consider custom error exceptions for encryption/decryption failures
# TODO Replace type checks with isinstance

class EncryptedPayload:
    """
    Container for AEAD-encrypted data.

    Attributes:
        nonce (bytes): Randomly generated nonce used for each individual encryption.
        ciphertext (bytes): The encrypted data, including authentication tag.
    """
    def __init__(self, nonce: bytes, ciphertext: bytes):
        self.nonce: bytes = nonce
        self.ciphertext: bytes = ciphertext

def encrypt(data: bytes, key: bytes, aad: bytes=None) -> EncryptedPayload:
    """
    Encrypt data using AES-GCM with the provided symmetric key.
    
    Args:
        data (bytes): The plaintext data to be encrypted.
        key (bytes): The symmetric key for encryption (must be 32 bytes for AES-256).
        aad (bytes, optional): Additional authenticated data to be included in the authentication tag.
    
    Returns:
        EncryptedPayload: An object containing the nonce and ciphertext.

    Raises:
        ValueError: If the key length is not 32 bytes.
    """
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes in length.")
    if not isinstance(data, bytes): 
        raise TypeError("Plaintext must be bytes")
    if aad and not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # Fresh nonce for each encryption
    ciphertext = aesgcm.encrypt(nonce, data, aad)
    return EncryptedPayload(nonce, ciphertext)

def decrypt(payload: EncryptedPayload, key: bytes, aad: bytes=None) -> bytes:
    """
    Decrypt data using AES-GCM with the provided symmetric key.

    Args:
        payload (EncryptedPayload): The encrypted payload containing nonce and ciphertext.
        key (bytes): The symmetric key for decryption (must be 32 bytes for AES-256).
        aad (bytes, optional): Additional authenticated data that was included during encryption.

    Returns:
        bytes: The decrypted plaintext data.
    
    Raises:
        ValueError: If the decryption fails.
    """
    if not isinstance(payload, EncryptedPayload):
        raise TypeError("Payload must be EncryptedPayload Object")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes in length")
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(payload.nonce, payload.ciphertext, aad)
    except Exception as e:
        raise ValueError("Decryption failed.") from e
    return plaintext