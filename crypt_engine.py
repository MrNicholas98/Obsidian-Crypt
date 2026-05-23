import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class ObsidianEngine:
    def __init__(self):
        self.backend = default_backend()
        # PBKDF2 parameters for secure key stretching
        self.iterations = 100_000

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Stretches a user text password into a secure 32-byte (256-bit) cryptographic key."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, input_path: str, password: str) -> str:
        """Reads a file, encrypts it using AES-256-GCM, and saves it as an isolated encrypted payload."""
        if not os.path.exists(input_path):
            raise FileNotFoundError("Target file not found.")

        # Read original raw file bytes
        with open(input_path, "rb") as f:
            data = f.read()

        # Generate cryptographic randomness: 16-byte Salt, 12-byte Initialization Vector (IV)
        salt = os.urandom(16)
        iv = os.urandom(12)

        # Derive key from password
        key = self._derive_key(password, salt)

        # Initialize AES-GCM Cipher (Authenticated Encryption preventing tampering)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        ).encryptor()

        # Encrypt data and finalize authentication tag
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag

        # Package file metadata seamlessly: Salt + IV + Tag + Ciphertext
        output_path = input_path + ".crypt"
        with open(output_path, "wb") as f:
            f.write(salt + iv + tag + ciphertext)

        return output_path

    def decrypt_file(self, input_path: str, password: str) -> str:
        """Parses a structured .crypt file, validates structural integrity, and recovers original data."""
        if not input_path.endswith(".crypt"):
            raise ValueError("Invalid file extension. Vault requires a secure '.crypt' target.")

        with open(input_path, "rb") as f:
            payload = f.read()

        # Extract precise byte offsets from structured metadata payload
        salt = payload[0:16]
        iv = payload[16:28]
        tag = payload[28:44]
        ciphertext = payload[44:]

        # Derive verification key using the extracted salt
        key = self._derive_key(password, salt)

        # Initialize decryption cipher
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend
        ).decryptor()

        # Reconstruct unencrypted original file bytes
        original_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Output decrypted file by removing the '.crypt' tag
        output_path = input_path.replace(".crypt", "")
        with open(output_path, "wb") as f:
            f.write(original_data)

        return output_path