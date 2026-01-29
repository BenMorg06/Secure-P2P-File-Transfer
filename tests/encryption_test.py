import os, sys, pytest
from pathlib import Path

sys.path.append(str(Path.home() / "Documents/Secure-P2P-File-Transfer/src/crypto"))
import symmetric

# TODO Change urandom for test reproducibility
# TODO Parametrize tests

class TestEncryption:
    expected_plaintext = b"Hello World! 123"
    lower_plaintext = b"hello"
    upper_plaintext = b"HELLO"
    mix_plaintext = b"Hello"
    bad_plaintext = "Hello"  # Non-Byte format
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
        expected_plaintext
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

    # TODO Parametrize
    def test_short_key_encrypt(self):
        with pytest.raises(ValueError):
            symmetric.encrypt(self.expected_plaintext, self.short_key)

    def test_long_key_encrypt(self):
        with pytest.raises(ValueError):
            symmetric.encrypt(self.expected_plaintext, self.long_key)

    # TODO Parametrize
    def test_short_key_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.good_ciphertext, self.short_key)

    def test_long_key_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.good_ciphertext, self.long_key)

    def test_bad_key_encrypt(self):
        with pytest.raises(TypeError):
            symmetric.encrypt(self.expected_plaintext, self.bad_key)
    
    def test_bad_key_decrypt(self):
        with pytest.raises(TypeError):
            symmetric.decrypt(self.good_ciphertext, self.bad_key)

    # TODO Tampered ciphertext

    def test_wrong_key_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.good_ciphertext, self.different_key)

    def test_wrong_aad_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.good_ciphertext, self.key, self.different_aad)

    # TODO Nonce related tests

    def test_wrong_aad_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.good_ciphertext, self.key, self.bad_aad)

    # TODO Test Large and Empty plaintexts and ciphertexts