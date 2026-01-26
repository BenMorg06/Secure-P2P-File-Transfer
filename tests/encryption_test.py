import os, sys, pytest
from pathlib import Path

sys.path.append(str(Path.home() / "Documents/Secure-P2P-File-Transfer/src/crypto"))
import symmetric


class TestEncryption:
    expected_plaintext = b"Hello World! 123"
    lower_plaintext = b"hello"
    upper_plaintext = b"HELLO"
    mix_plaintext = b"Hello"
    bad_plaintext = "Hello"  # Non-Byte format
    key = os.urandom(32)
    long_key = os.urandom(64)
    short_key = os.urandom(16)
    aad = os.urandom(12)

    def test_lower(self):
        ciphertext = symmetric.encrypt(self.lower_plaintext, self.key)
        output_plaintext = symmetric.decrypt(ciphertext, self.key)
        assert output_plaintext == self.lower_plaintext

    def test_upper(self):
        ciphertext = symmetric.encrypt(self.upper_plaintext, self.key)
        output_plaintext = symmetric.decrypt(ciphertext, self.key)
        assert output_plaintext == self.upper_plaintext

    def test_mix(self):
        ciphertext = symmetric.encrypt(self.mix_plaintext, self.key)
        output_plaintext = symmetric.decrypt(ciphertext, self.key)
        assert output_plaintext == self.mix_plaintext

    def test_expected(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key)
        output_plaintext = symmetric.decrypt(ciphertext, self.key)
        assert output_plaintext == self.expected_plaintext

    # TODO test incorrect plaintext and ciphertext format
    def test_non_byte_plaintext(self):
        with pytest.raises(ValueError):
            ciphertext = symmetric.encrypt(self.bad_plaintext, self.key)

    def test_non_payload_ciphertext(self):
        with pytest.raises(ValueError):
            ciphertext = b"Hello World"
            output_plaintext = symmetric.decrypt(ciphertext, self.key)

    def test_expected_with_aad(self):
        ciphertext = symmetric.encrypt(self.expected_plaintext, self.key, self.aad)
        output_plaintext = symmetric.decrypt(ciphertext, self.key, self.aad)
        assert output_plaintext == self.expected_plaintext

    # TODO Test incorrect aad format - Needs fix in symmetric
    def test_with_invalid_aad(self):
        pass

    def test_short_key_encrypt(self):
        with pytest.raises(ValueError):
            symmetric.encrypt(self.expected_plaintext, self.short_key)

    def test_short_key_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.expected_plaintext, self.short_key)

    def test_long_key_encrypt(self):
        with pytest.raises(ValueError):
            symmetric.encrypt(self.expected_plaintext, self.long_key)

    def test_long_key_decrypt(self):
        with pytest.raises(ValueError):
            symmetric.decrypt(self.expected_plaintext, self.long_key)

    # TODO Test incorrect key format - needs fix in symmetric

