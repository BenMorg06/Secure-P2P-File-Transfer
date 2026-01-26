import os, sys, pytest
from pathlib import Path
sys.path.append(str(Path.home() / "Documents/Secure-P2P-File-Transfer/src/crypto"))
import symmetric

class TestEncryption:
    expected_plaintext = b"Hello World! 123"
    lower_plaintext = b'hello'
    upper_plaintext = b'HELLO'
    mix_plaintext = b"Hello"
    key = os.urandom(32)
    long_key = os.urandom(64)
    short_key = os.urandom(16)

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

    def test_short_key_encrypt(self):
        with pytest.raises(ValueError):
            symmetric.encrypt(self.expected_plaintext, self.short_key)
        