import secrets
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from Crypto.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import json
import hashlib
from cryptography.hazmat.primitives import hashes

def derive_salt_from_username(username, length=32):
    """
    Derives a salt from a username using SHA3-256.
    """
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(username.encode())
    return digest.finalize()[:length]

def generate_salt(length=32):
    return secrets.token_bytes(length)

def hash_password_argon2id(password: str, salt: bytes, hash_len=32):
    """
    Returns the Argon2id hash of a password given a salt.
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=10,          # 10 iterations
        memory_cost=262144,    # 256 MiB = 262144 KiB
        parallelism=1,
        hash_len=32,           # ou 64 selon besoin
        type=Type.ID
    )

def derive_encryption_key(master_key: bytes, salt: bytes = b"", length: int = 32, info: bytes = b"encryption key") -> bytes:
    """
    Derives a key from the master_key using HKDF with optional salt and info.

    Args:
        master_key (bytes): The input keying material.
        salt (bytes, optional): Salt value (can be empty). Defaults to b"".
        length (int, optional): Length of the derived key. Defaults to 32.
        info (bytes, optional): Contextual information to produce different keys. Defaults to b"encryption key".

    Returns:
        bytes: The derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(master_key)

def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_private_key(private_key_bytes: bytes, key: bytes) -> bytes:
    nonce = generate_salt(24)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_bytes)
    return nonce + ciphertext + tag

def decrypt_private_key(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt private key encrypted with XChaCha20-Poly1305"""
    nonce = encrypted_data[:24]
    ciphertext = encrypted_data[24:-16]  # Last 16 bytes are the tag
    tag = encrypted_data[-16:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def generate_symmetric_key(length: int = 32) -> bytes:
    """
    Generate a cryptographically secure random symmetric key.
    Uses XChaCha20-Poly1305 which requires a 32-byte key.
    """
    return secrets.token_bytes(length)

def encrypt_message_symmetric(message: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt a message using XChaCha20-Poly1305.
    Returns (ciphertext, nonce) tuple.
    """
    nonce = generate_salt(24)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return ciphertext + tag, nonce

def encrypt_key_asymmetric(key: bytes, recipient_public_key_bytes: bytes) -> bytes:
    """
    Encrypt a symmetric key using X25519 key exchange and XChaCha20-Poly1305.
    This implements a secure hybrid encryption scheme.
    """
    # Convert the recipient's public key bytes to X25519PublicKey
    recipient_public_key = x25519.X25519PublicKey.from_public_bytes(recipient_public_key_bytes)
    
    # Generate ephemeral key pair for this encryption
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Perform key exchange
    shared_key = ephemeral_private_key.exchange(recipient_public_key)
    
    # Derive encryption key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=b"",
        info=b"key_encryption",
        backend=default_backend()
    ).derive(shared_key)
    
    # Encrypt the symmetric key
    nonce = generate_salt(24)
    cipher = ChaCha20_Poly1305.new(key=derived_key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    
    # Return ephemeral public key + nonce + ciphertext + tag
    return ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) + nonce + ciphertext + tag

def hash_dict(d: dict) -> bytes:
    """
    Create a deterministic hash of a dictionary.
    Uses SHA3-256 for cryptographic security.
    """
    # Convert dict to canonical JSON string
    json_str = json.dumps(d, sort_keys=True, separators=(',', ':'))
    
    # Hash the JSON string
    hasher = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    hasher.update(json_str.encode())
    return hasher.finalize()

def decrypt_key_asymmetric(encrypted_data, recipient_private_key):
    """
    Decrypts a symmetric key encrypted with X25519 and XChaCha20-Poly1305.
    
    Args:
        encrypted_data (bytes): Symmetric key encrypted
        recipient_private_key (X25519PrivateKey): Recipient's private key
        
    Returns:
        bytes: Decrypted symmetric key
    """
    # First 32 bytes are the ephemeral public key
    ephemeral_pubkey_bytes = encrypted_data[:32]
    nonce = encrypted_data[32:56]  # 24 bytes for nonce
    ciphertext = encrypted_data[56:-16]  # The rest minus 16 bytes for tag
    tag = encrypted_data[-16:]
    
    # Convert to public key object
    ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_pubkey_bytes)
    
    # Perform key exchange
    shared_key = recipient_private_key.exchange(ephemeral_public_key)
    
    # Derive encryption key
    derived_key = HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=b"",
        info=b"key_encryption",
        backend=default_backend()
    ).derive(shared_key)
    
    # Decrypt with XChaCha20-Poly1305
    cipher = ChaCha20_Poly1305.new(key=derived_key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def decrypt_message_symmetric(ciphertext, nonce, key):
    """
    Decrypts a message with XChaCha20-Poly1305.
    
    Args:
        ciphertext (bytes): Encrypted message (including tag)
        nonce (bytes): Nonce used for encryption
        key (bytes): Symmetric key
        
    Returns:
        bytes: Decrypted message
    """
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    message = ciphertext[:-16]  # Last 16 bytes are the tag
    tag = ciphertext[-16:]
    return cipher.decrypt_and_verify(message, tag)

def verify_signature(message_hash: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verifies a message signature with the signer's Ed25519 public key.
    
    Args:
        message_hash (bytes): The hash of the message that was signed
        signature (bytes): The signature to verify
        public_key_bytes (bytes): Signer's Ed25519 public key in raw format
        
    Returns:
        bool: True if the signature is valid, False otherwise
    """
    try:
        # Convert public key bytes to Ed25519PublicKey object
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Verify signature
        public_key.verify(signature, message_hash)
        return True
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False