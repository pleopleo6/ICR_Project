import socket
import ssl
import json
import base64
import os
from cryptography.hazmat.primitives import serialization
from crypto_utils import (
    generate_salt,
    derive_encryption_key,
    hash_password_argon2id,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    encrypt_private_key
)
# flake8: noqa: E303

import base64
import json
from crypto_utils import generate_salt, hash_password_argon2id

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


def retrieve_keys():
    # TODO: Implement logic
    return json.dumps({"action": "retrieve_keys", "message": "Not yet implemented"})


def send_message():
    msg = input("Enter message to send: ")
    return json.dumps({"action": "send_message", "message": msg})

