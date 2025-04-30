import socket
import ssl
import json
import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from crypto_utils import (
    generate_salt,
    derive_encryption_key,
    hash_password_argon2id,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    encrypt_private_key,
    decrypt_private_key
)
import base64
import json
from crypto_utils import generate_salt, hash_password_argon2id

def save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc):
    user_dir = Path(f"client_keys/{username}")
    user_dir.mkdir(parents=True, exist_ok=True)

    with open(user_dir / "sign_key.pem", "wb") as f:
        f.write(priv_sign.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(user_dir / "enc_key.pem", "wb") as f:
        f.write(priv_enc.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(user_dir / "sign_pub.pem", "wb") as f:
        f.write(pub_sign.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open(user_dir / "enc_pub.pem", "wb") as f:
        f.write(pub_enc.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def get_keys_from_password(username, password, response_json):
    # response_json → dictionnary
    if isinstance(response_json, str):  
        response_json = json.loads(response_json)

    if response_json.get("status") != "success":
        return f"Server error: {response_json.get('message')}"

    user_data = response_json["user"].get(username)
    if not user_data:
        return "No user data found in server response"

    # Step 1: Base64 decode salts
    salt_argon2 = base64.b64decode(user_data["salt_argon2"])
    salt_hkdf = base64.b64decode(user_data["salt_hkdf"])

    # Step 2: Regenerate derived key from password
    hashed = hash_password_argon2id(password, salt_argon2)
    derived_key = derive_encryption_key(hashed, salt_hkdf, length=32)

    # Step 3: Decrypt private keys
    encrypted_sign_key = base64.b64decode(user_data["Encrypted_sign_key"])
    encrypted_enc_key = base64.b64decode(user_data["Encrypted_enc_key"])

    try:
        # Decrypt signing key
        priv_sign_bytes = decrypt_private_key(encrypted_sign_key, derived_key)
        priv_sign = Ed25519PrivateKey.from_private_bytes(priv_sign_bytes)
        
        # Decrypt encryption key
        priv_enc_bytes = decrypt_private_key(encrypted_enc_key, derived_key)
        priv_enc = X25519PrivateKey.from_private_bytes(priv_enc_bytes)

        # Get public keys from private
        pub_sign = priv_sign.public_key()
        pub_enc = priv_enc.public_key()

        # Save locally
        save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc)

        return "Keys successfully retrieved and stored locally."

    except Exception as e:
        return f"Decryption failed: {str(e)}"

def create_user(username=None, password=None):
    if username is None:
        username = input("Enter username: ")
    if password is None:
        password = input("Enter password: ")

    # 1. Generate 2 salt for password and HKDF
    salt_argon2 = generate_salt(32)
    salt_hkdf = generate_salt(32)

    # 2. Hash with Argon2id
    hashed = hash_password_argon2id(password, salt_argon2)

    # 3. HKDF (SHA3-256)
    derived_key = derive_encryption_key(hashed, salt=salt_hkdf, length=32)

    # 4. Generate keys
    priv_sign, pub_sign = generate_ed25519_keypair()
    priv_enc, pub_enc = generate_x25519_keypair()

    # Serialize public keys
    pubkey_sign = base64.b64encode(pub_sign.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    pubkey_enc = base64.b64encode(pub_enc.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    # Serialize and encrypt private keys
    privkey_sign_bytes = priv_sign.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    privkey_enc_bytes = priv_enc.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted_sign_key = base64.b64encode(encrypt_private_key(privkey_sign_bytes, derived_key)).decode()
    encrypted_enc_key = base64.b64encode(encrypt_private_key(privkey_enc_bytes, derived_key)).decode()

    # Save keys locally 
    save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc)

    # Prepare data
    user_data = {
        "action": "create_user",
        "username": username,
        "salt_argon2": base64.b64encode(salt_argon2).decode(),
        "salt_hkdf": base64.b64encode(salt_hkdf).decode(),
        "PubKey_sign": pubkey_sign,
        "PubKey_enc": pubkey_enc,
        "Encrypted_sign_key": encrypted_sign_key,
        "Encrypted_enc_key": encrypted_enc_key
    }
    return json.dumps(user_data)


def reset_password():
    # TODO: Implement logic
    return json.dumps({"action": "reset_password", "message": "Not yet implemented"})


def send_message():
    msg = input("Enter message to send: ")
    return json.dumps({"action": "send_message", "message": msg})

