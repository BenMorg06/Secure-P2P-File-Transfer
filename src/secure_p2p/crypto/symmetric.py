import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

data = b"Hello, Secure P2P!"
key = AESGCM.generate_key(bit_length=256)
aad = b"authenticated but unencrypted data"
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, data, aad)
plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

