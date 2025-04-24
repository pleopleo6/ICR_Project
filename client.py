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

def create_user():
    username = input("Enter username: ")
    password = input("Enter password: ")

    # 1. Generate 2 salt for password and HKDF
    salt_argon2 = generate_salt(32)
    salt_hkdf = generate_salt(32)

    # 2. Hash with Argon2id
    hashed = hash_password_argon2id(password, salt_argon2)

     # 3. HKDF (SHA3-256) with argon2 hash
    derived_key = derive_encryption_key(hashed, salt=salt_hkdf, length=32)

    # 4. Keys generation
    priv_sign, pub_sign = generate_ed25519_keypair()
    priv_enc, pub_enc = generate_x25519_keypair()

    # Serialization public keys
    pubkey_sign = base64.b64encode(pub_sign.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    pubkey_enc = base64.b64encode(pub_enc.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    # Serialization private keys
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

    # 5. ChaCha20-Poly1305 encryption for private keys
    encrypted_sign_key = base64.b64encode(encrypt_private_key(privkey_sign_bytes, derived_key)).decode()
    encrypted_enc_key = base64.b64encode(encrypt_private_key(privkey_enc_bytes, derived_key)).decode()

    # 6. Prepare data
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


def run_client():
    host = 'localhost'
    port = 8443
    server_cert = 'server.crt'

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=server_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False

    print("Choose an option:")
    print("1. Create User")
    print("2. Reset Password")
    print("3. Retrieve Keys")
    print("4. Send Message")
    choice = input("Enter your choice (1-4): ").strip()

    if choice == "1":
        payload = create_user()
    elif choice == "2":
        payload = reset_password()
    elif choice == "3":
        payload = retrieve_keys()
    elif choice == "4":
        payload = send_message()
    else:
        print("Invalid choice.")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.connect((host, port))
                print("Connected to server")
                print(f"Using TLS version: {ssock.version()}")

                ssock.sendall(payload.encode())
                response = ssock.recv(4096)
                print(f"Received from server: {response.decode()}")
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    run_client()