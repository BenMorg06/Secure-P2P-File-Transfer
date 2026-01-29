import os, sys, pytest
from pathlib import Path

possible_paths = [
    Path.home() / "Documents/Secure-P2P-File-Transfer/src/crypto",
    Path.home()
    / "Documents/Obsidian-Vaults/cortado/Secure-P2P-File-Transfer/src/crypto",
]

for path in possible_paths:
    if path.exists():
        sys.path.append(str(path))
        break

import symmetric

# TODO Change urandom for test reproducibility
# TODO Parametrize tests


class TestEncryption:
    expected_plaintext = b"Hello World! 123"
    lower_plaintext = b"hello"
    upper_plaintext = b"HELLO"
    mix_plaintext = b"Hello"
    bad_plaintext = "Hello"  # Non-Byte format
    empty_plaintext = b''
    long_plaintext = os.urandom(256)
    key = os.urandom(32)
    different_key = os.urandom(32)
    long_key = os.urandom(64)
    short_key = os.urandom(16)
    bad_key = "1111"
    aad = os.urandom(12)
    different_aad = os.urandom(12)
    bad_aad = "info"
    good_ciphertext = symmetric.encrypt(expected_plaintext, key)

    @pytest.mark.parametrize("plaintext", 
    [
        lower_plaintext,
        upper_plaintext,
        mix_plaintext,
        expected_plaintext,
        empty_plaintext, # currently allowed and works???
        long_plaintext
    ])
    def test_encrypt(self, plaintext):
        ciphertext = symmetric.encrypt(plaintext, self.key)
        assert symmetric.decrypt(ciphertext, self.key) == plaintext

    def test_non_byte_plaintext(self):
        with pytest.raises(TypeError):
            ciphertext = symmetric.encrypt(self.bad_plaintext, self.key)

    # TODO Understand why this test passes
    def test_non_payload_ciphertext(self):
        with pytest.raises(TypeError):
            ciphertext = b"Hello World"
            output_plaintext = symmetric.decrypt(ciphertext, self.key)

    def test_expected_with_aad(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key, self.aad)
        output_plaintext = symmetric.decrypt(ciphertext, self.key, self.aad)
        assert output_plaintext == self.expected_plaintext

    def test_with_invalid_aad(self):
        with pytest.raises(TypeError):
            symmetric.encrypt(self.expected_plaintext, self.key, self.bad_aad)

    @pytest.mark.parametrize("key", 
    [
        short_key,
        long_key
    ])
    def test_bad_key_encrypt(self, key):
        with pytest.raises(ValueError):
            symmetric.encrypt(self.expected_plaintext, key)

    @pytest.mark.parametrize("key", 
    [
        short_key,
        long_key,
        different_key
    ])
    def test_bad_key_decrypt(self, key):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.good_ciphertext, key)

    # TODO is it worth combining with parametrize and if statement?
    def test_invalid_key_encrypt(self):
        with pytest.raises(TypeError):
            symmetric.encrypt(self.expected_plaintext, self.bad_key)
    
    def test_invalid_key_decrypt(self):
        with pytest.raises(TypeError):
            symmetric.decrypt(self.good_ciphertext, self.bad_key)

    def test_wrong_aad_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.good_ciphertext, self.key, self.different_aad)

    def test_invalid_aad_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.good_ciphertext, self.key, self.bad_aad)

    # TODO Nonce uniqueness
    def test_nonce_uniqueness(self):
        ciphertexts = [symmetric.encrypt(self.expected_plaintext, self.key) for i in range(100)]
        nonces = [ct.nonce for ct in ciphertexts]
        assert len(nonces) == len(set(nonces))
    # TODO Nonce Length Validation
    def test_nonce_length(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key)
        assert len(ciphertext.nonce) == 12
    # TODO Tampered Nonce
    def test_tampered_nonce(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key)
        tampered_nonce = bytearray(ciphertext.nonce)
        tampered_nonce[0] ^= 0x01
        ciphertext.nonce = bytes(tampered_nonce)

        with pytest.raises(ValueError):
            symmetric.decrypt(ciphertext, self.key)
    # TODO Tampered ciphertext
    def test_tampered_ciphertext(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key)
        tampered = bytearray(ciphertext.ciphertext)
        tampered[0] ^=0x01
        ciphertext.ciphertext = bytes(tampered)
        
        with pytest.raises(ValueError):
            symmetric.decrypt(ciphertext, self.key)

    # TODO AAD empty
    def test_empty_aad(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key, b'')
        plaintext = symmetric.decrypt(ciphertext, self.key, b'')
        assert plaintext == self.expected_plaintext
    # TODO AAD Used for encrypt but missing fo decrypt and vice versa
    def test_missing_aad_on_decrypt(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key, self.aad) # AAD
        with pytest.raises(ValueError):
            symmetric.decrypt(ciphertext, self.key)  # No AAD 

    def test_missing_aad_on_decrypt(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key) # No AAD
        with pytest.raises(ValueError):
            symmetric.decrypt(ciphertext, self.key, self.aad)  # AAD 


    def test_payload_attributes(self):
        assert hasattr(self.good_ciphertext, 'nonce')
        assert hasattr(self.good_ciphertext, 'ciphertext')
        assert isinstance(self.good_ciphertext.nonce, bytes)
        assert isinstance(self.good_ciphertext.ciphertext, bytes)

    def test_invalid_payload_type(self):
        with pytest.raises(TypeError):
            symmetric.decrypt("Not Payload", self.key)

    def test_none_key_encrypt(self):
        with pytest.raises(TypeError):
            symmetric.encrypt(self.expected_plaintext, None)

    def test_none_plaintext(self):
        with pytest.raises(TypeError):
            symmetric.encrypt(None, self.key)

    def test_none_ciphertext(self):
        with pytest.raises(TypeError):
            symmetric.decrypt(None, self.key)
    # TODO Authenticaion tag length