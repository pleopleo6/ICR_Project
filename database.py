import json
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import base64
import uuid

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
        return db[username]  # Return the user data directly
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


def reset_password(username, salt_argon2, salt_hkdf, Encrypted_sign_key, Encrypted_enc_key):
    try:
        db = load_database()

        if username not in db:
            return False

        # Only update the fields related to password reset
        db[username]["salt_argon2"] = salt_argon2
        db[username]["salt_hkdf"] = salt_hkdf
        db[username]["Encrypted_sign_key"] = Encrypted_sign_key
        db[username]["Encrypted_enc_key"] = Encrypted_enc_key

        with open("database.json", "w") as f:
            json.dump(db, f, indent=4)

        return True

    except Exception as e:
        print(f"Error updating database: {e}")
        return False

def get_all_users():
    try:
        with open("database.json", "r") as f:
            db = json.load(f)

        user_list = list(db.keys())
        return {"status": "success", "users": user_list}

    except FileNotFoundError:
        return {"status": "error", "message": "Database not found."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

###### Crypto functions : 

def verify_signature(username, message, signature_b64):
    """
    Verify a signature.
    
    Args:
        username (str): The username of the signer
        message: The message or hash to verify (can be string or bytes)
        signature_b64 (str): Base64 encoded signature
        
    Returns:
        tuple: (is_valid, message)
    """
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
        
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode()
            
        pubkey.verify(signature_bytes, message)
        return True, "Signature valid"
    except (InvalidSignature, ValueError) as e:
        return False, f"Invalid signature: {e}"

def store_message(message_data):
    """
    Store a message in messages.json file
    
    Args:
        message_data (dict): The message data to store
        
    Returns:
        bool: True if stored successfully, False otherwise
    """
    messages_file = "messages.json"
    
    try:
        # Load existing messages or create new structure
        if os.path.exists(messages_file):
            with open(messages_file, 'r') as f:
                try:
                    messages = json.load(f)
                except json.JSONDecodeError:
                    messages = {"messages": []}
        else:
            messages = {"messages": []}
        
        # Add timestamp if not present
        if "timestamp" not in message_data:
            from datetime import datetime
            message_data["timestamp"] = datetime.now().isoformat()
        
        # Add a message ID if not present
        if "message_id" not in message_data:
            message_data["message_id"] = str(uuid.uuid4())
            
        # Make a safety check to avoid duplicate messages
        # We consider a message is duplicate if sender, recipient and timestamp are the same
        is_duplicate = False
        for existing_msg in messages["messages"]:
            if (existing_msg.get("from") == message_data.get("from") and
                existing_msg.get("to") == message_data.get("to") and
                existing_msg.get("timestamp") == message_data.get("timestamp")):
                is_duplicate = True
                break
                
        if not is_duplicate:
            # Add the message to the list
            messages["messages"].append(message_data)
            
            # Write back to file
            with open(messages_file, 'w') as f:
                json.dump(messages, f, indent=4)
                
            print(f"Message stored with ID: {message_data.get('message_id')}")
            return True
        else:
            print("Duplicate message detected, not storing")
            return False
    
    except Exception as e:
        print(f"Error storing message: {e}")
        return False
    