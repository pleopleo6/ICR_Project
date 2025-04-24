import secrets
import base64
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# flake8: noqa: E303

def generate_salt(length=32):
    return secrets.token_bytes(length)

def hash_password_argon2id(password: str, salt: bytes, hash_len=32):
    """
    Returns the Argon2id hash of a password given a salt.
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=65536,  # 64 MB
        parallelism=1,
        hash_len=hash_len,
        type=Type.ID
    )

def derive_encryption_key(argon2_hash: bytes, salt: bytes = b"", length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(), 
        length=length,
        salt=salt,
        info=b"encryption key",
        backend=default_backend()
    )
    return hkdf.derive(argon2_hash)

def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_private_key(private_key_bytes: bytes, key: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    nonce = generate_salt(12)
    ciphertext = aead.encrypt(nonce, private_key_bytes, associated_data=None)
    return nonce + ciphertext #TAG include at the end of ciphertext