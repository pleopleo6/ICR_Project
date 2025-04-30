import json
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import base64

DB_FILE = "database.json"

def load_database():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def get_user_all_data(username):
    db = load_database()
    if username in db:
        return {"status": "success", "user": {username: db[username]}}
    else:
        return {"status": "error", "message": "User not found"}


def get_user_public_info(username):
    db = load_database()
    if username in db:
        user = db[username]
        return {
            "status": "success",
            "username": username,
            "PubKey_sign": user.get("PubKey_sign"),
            "PubKey_enc": user.get("PubKey_enc")
        }
    else:
        return {"status": "error", "message": "User not found"}

def create_user(username, salt_argon2, salt_hkdf, pubkey_sign, pubkey_enc, encrypted_sign_key, encrypted_enc_key):
    # Load existing database or initialize a new one
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            try:
                db = json.load(f)
            except json.JSONDecodeError:
                db = {}
    else:
        db = {}

    # Check if the user already exists
    if username in db:
        return {"status": "error", "message": "Username already exists"}

    # Add the new user with both salts
    db[username] = {
        "salt_argon2": salt_argon2,
        "salt_hkdf": salt_hkdf,
        "PubKey_sign": pubkey_sign,
        "PubKey_enc": pubkey_enc,
        "Encrypted_sign_key": encrypted_sign_key,
        "Encrypted_enc_key": encrypted_enc_key
    }

    # Write back to the file
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=4)

    return {"status": "success", "message": f"User {username} created successfully"}



###### Crypto functions : 

def verify_signature(username, message: str, signature_b64: str):
    db = load_database()
    if username not in db:
        return False, "User not found"
    
    pubkey_b64 = db[username].get("PubKey_sign")
    if not pubkey_b64:
        return False, "Public key not found"

    try:
        pubkey_bytes = base64.b64decode(pubkey_b64)
        signature_bytes = base64.b64decode(signature_b64)
        pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        pubkey.verify(signature_bytes, message.encode())
        return True, "Signature valid"
    except (InvalidSignature, ValueError) as e:
        return False, f"Invalid signature: {e}"