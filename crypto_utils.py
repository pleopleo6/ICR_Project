import secrets
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import json

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

def decrypt_private_key(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt private key encrypted with ChaCha20-Poly1305"""
    aead = ChaCha20Poly1305(key)
    nonce = encrypted_data[:12]  # First 12 bytes are nonce
    ciphertext = encrypted_data[12:]  # Rest is ciphertext+tag
    return aead.decrypt(nonce, ciphertext, associated_data=None)

def generate_symmetric_key(length: int = 32) -> bytes:
    """
    Generate a cryptographically secure random symmetric key.
    Uses ChaCha20-Poly1305 which requires a 32-byte key.
    """
    return secrets.token_bytes(length)

def encrypt_message_symmetric(message: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt a message using ChaCha20-Poly1305.
    Returns (ciphertext, nonce) tuple.
    """
    aead = ChaCha20Poly1305(key)
    nonce = generate_salt(12)  # ChaCha20-Poly1305 uses 12-byte nonce
    ciphertext = aead.encrypt(nonce, message, associated_data=None)
    return ciphertext, nonce

def encrypt_key_asymmetric(key: bytes, recipient_public_key_bytes: bytes) -> bytes:
    """
    Encrypt a symmetric key using X25519 key exchange and ChaCha20-Poly1305.
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
    aead = ChaCha20Poly1305(derived_key)
    nonce = generate_salt(12)
    ciphertext = aead.encrypt(nonce, key, associated_data=None)
    
    # Return ephemeral public key + nonce + ciphertext
    return ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ) + nonce + ciphertext

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
    Déchiffre une clé symétrique chiffrée avec X25519 et ChaCha20-Poly1305.
    
    Args:
        encrypted_data (bytes): Clé symétrique chiffrée
        recipient_private_key (X25519PrivateKey): Clé privée du destinataire
        
    Returns:
        bytes: Clé symétrique déchiffrée
    """
    # Les 32 premiers octets sont la clé publique éphémère
    ephemeral_pubkey_bytes = encrypted_data[:32]
    nonce = encrypted_data[32:44]  # 12 octets pour le nonce
    ciphertext = encrypted_data[44:]  # Le reste est le texte chiffré
    
    # Convertir en objet clé publique
    ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_pubkey_bytes)
    
    # Effectuer l'échange de clés
    shared_key = recipient_private_key.exchange(ephemeral_public_key)
    
    # Dériver la clé de chiffrement
    derived_key = HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=b"",
        info=b"key_encryption",
        backend=default_backend()
    ).derive(shared_key)
    
    # Déchiffrer avec ChaCha20-Poly1305
    aead = ChaCha20Poly1305(derived_key)
    return aead.decrypt(nonce, ciphertext, associated_data=None)

def decrypt_message_symmetric(ciphertext, nonce, key):
    """
    Déchiffre un message avec ChaCha20-Poly1305.
    
    Args:
        ciphertext (bytes): Message chiffré
        nonce (bytes): Nonce utilisé pour le chiffrement
        key (bytes): Clé symétrique
        
    Returns:
        bytes: Message déchiffré
    """
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, associated_data=None)