import json
import os

DB_FILE = "database.json"
# flake8: noqa: E303

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