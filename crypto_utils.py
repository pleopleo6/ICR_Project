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

def decrypt_private_key(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt private key encrypted with ChaCha20-Poly1305"""
    aead = ChaCha20Poly1305(key)
    nonce = encrypted_data[:12]  # First 12 bytes are nonce
    ciphertext = encrypted_data[12:]  # Rest is ciphertext+tag
    return aead.decrypt(nonce, ciphertext, associated_data=None)

def print_and_compare_keys(username, priv_sign, priv_enc):
    user_dir = Path(f"client_keys/{username}")

    def load_private_key(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def load_public_key(path):
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    print("\n===== 🔍 COMPARAISON DES CLÉS =====")

    # Recharger les clés locales
    stored_priv_sign = load_private_key(user_dir / "sign_key.pem")
    stored_priv_enc = load_private_key(user_dir / "enc_key.pem")
    stored_pub_sign = load_public_key(user_dir / "sign_pub.pem")
    stored_pub_enc = load_public_key(user_dir / "enc_pub.pem")

    # Afficher et comparer les clés
    def b64_raw(pub):
        return base64.b64encode(pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode()

    print("\n📤 Clé publique SIGN")
    print(" - Déchiffrée :", b64_raw(priv_sign.public_key()))
    print(" - Stockée    :", b64_raw(stored_priv_sign.public_key()))
    print(" - Pub stockée:", b64_raw(stored_pub_sign))
    assert priv_sign.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == stored_pub_sign.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ), "❌ Signature pubkey mismatch"
    print(" ✅ Clés SIGN identiques")

    print("\n📤 Clé publique ENC")
    print(" - Déchiffrée :", b64_raw(priv_enc.public_key()))
    print(" - Stockée    :", b64_raw(stored_priv_enc.public_key()))
    print(" - Pub stockée:", b64_raw(stored_pub_enc))
    assert priv_enc.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == stored_pub_enc.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ), "❌ Encryption pubkey mismatch"
    print(" ✅ Clés ENC identiques")

    print("\n✅ Toutes les clés sont identiques et cohérentes !")