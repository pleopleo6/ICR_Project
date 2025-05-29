import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import base64
import json
from crypto_utils import (
    generate_salt,
    derive_encryption_key,
    hash_password_argon2id,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    encrypt_private_key,
    decrypt_private_key,
    generate_symmetric_key,
    encrypt_message_symmetric,
    encrypt_key_asymmetric,
    hash_dict,
    derive_salt_from_username
)
from vdf_crypto import (
    solve_time_lock_puzzle,
    decrypt_with_challenge_key,
)
import os
from datetime import datetime
import uuid

# Ensure client_keys directory exists
Path("client_keys").mkdir(exist_ok=True)

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc):    
    ret = False
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
    
    ret = True
    return ret  

def get_keys_from_password(username, password, response_json):
    # response_json → dictionary
    if isinstance(response_json, str):
        response_json = json.loads(response_json)

    if response_json.get("status") == "error":
        return f"Server error: {response_json.get('message')}"

    # Check that expected fields are present
    required_fields = ["auth_key", "Encrypted_sign_key", "Encrypted_enc_key", "PubKey_sign", "PubKey_enc"]
    if not all(key in response_json for key in required_fields):
        print(f"Server response: {response_json}")
        return "Required fields missing in server response"

    try:
        # Recreate master_key from username as during creation
        salt_argon2 = derive_salt_from_username(username)
        master_key = hash_password_argon2id(password, salt_argon2)

        # Derive auth_key and data_key locally
        computed_auth_key = derive_encryption_key(master_key, info=b"auth_key")
        data_key = derive_encryption_key(master_key, info=b"data_key")

        # Verify that auth_key matches the one stored on the server
        received_auth_key_b64 = response_json["auth_key"]
        computed_auth_key_b64 = base64.b64encode(computed_auth_key).decode()

        if received_auth_key_b64 != computed_auth_key_b64:
            print("Auth key does not match!")
            return "Incorrect password"

        # Decrypt private keys
        encrypted_sign_key = base64.b64decode(response_json["Encrypted_sign_key"])
        encrypted_enc_key = base64.b64decode(response_json["Encrypted_enc_key"])

        try:
            # Decrypt signature key
            priv_sign_bytes = decrypt_private_key(encrypted_sign_key, data_key)
            priv_sign = Ed25519PrivateKey.from_private_bytes(priv_sign_bytes)

            # Decrypt encryption key
            priv_enc_bytes = decrypt_private_key(encrypted_enc_key, data_key)
            priv_enc = X25519PrivateKey.from_private_bytes(priv_enc_bytes)

            # Extract public keys
            pub_sign = priv_sign.public_key()
            pub_enc = priv_enc.public_key()

            # Verify public keys
            server_pub_sign = base64.b64decode(response_json["PubKey_sign"])
            server_pub_enc = base64.b64decode(response_json["PubKey_enc"])

            derived_pub_sign = pub_sign.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            derived_pub_enc = pub_enc.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            if derived_pub_sign != server_pub_sign or derived_pub_enc != server_pub_enc:
                print("Public keys derived from password don't match server keys!")
                return "Wrong password"

            # Local save
            ret = save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc)
            return ret

        except Exception as e:
            print(f"Error decrypting keys: {str(e)}")
            return "Incorrect password or decryption error"

    except KeyError as e:
        print(f"Missing key in server response: {e}")
        return f"Server error: Missing data {e}"

def create_user(username=None, password=None):
    if username is None:
        username = input("Enter username: ")
    if password is None:
        password = input("Enter password: ")

    # Convert password to bytes (master key)
    # Generate a salt for Argon2id
    salt_argon2 = derive_salt_from_username(username)

    # Hash the password using Argon2id to produce the master key
    master_key = hash_password_argon2id(password, salt_argon2)

    # Derive two keys using different "info" labels, no salt
    auth_key = derive_encryption_key(master_key, salt=None, length=32, info=b'auth_key')
    data_key = derive_encryption_key(master_key, salt=None, length=32, info=b'data_key')

    # Generate key pairs
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

    # Serialize private keys (Raw)
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

    # Encrypt private keys with data_key
    encrypted_sign_key = base64.b64encode(encrypt_private_key(privkey_sign_bytes, data_key)).decode()
    encrypted_enc_key = base64.b64encode(encrypt_private_key(privkey_enc_bytes, data_key)).decode()

    # Save keys locally
    save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc)

    # Prepare payload to send to server
    user_data = {
        "action": "create_user",
        "username": username,
        "auth_key": base64.b64encode(auth_key).decode(),
        "PubKey_sign": pubkey_sign,
        "PubKey_enc": pubkey_enc,
        "Encrypted_sign_key": encrypted_sign_key,
        "Encrypted_enc_key": encrypted_enc_key
    }

    return json.dumps(user_data)

def reset_password(new_password, username):
    user_dir = Path(f"client_keys/{username}")
    priv_sign = load_private_key(user_dir / "sign_key.pem")
    priv_enc  = load_private_key(user_dir / "enc_key.pem")

    # 1. Recalculate derived keys from new password
    salt_argon2 = derive_salt_from_username(username)
    master_key = hash_password_argon2id(new_password, salt_argon2)

    auth_key = derive_encryption_key(master_key, info=b"auth_key")
    data_key = derive_encryption_key(master_key, info=b"data_key")

    # 2. Extract and re-encrypt existing private keys
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

    encrypted_sign_key = base64.b64encode(encrypt_private_key(privkey_sign_bytes, data_key)).decode()
    encrypted_enc_key = base64.b64encode(encrypt_private_key(privkey_enc_bytes, data_key)).decode()

    # 3. Reuse existing public keys
    pub_sign = priv_sign.public_key()
    pub_enc = priv_enc.public_key()

    pubkey_sign = base64.b64encode(pub_sign.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    pubkey_enc = base64.b64encode(pub_enc.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    # 4. Prepare message to send
    unsigned_payload = {
        "action": "reset_password",
        "username": username,
        "auth_key": base64.b64encode(auth_key).decode(),
        "PubKey_sign": pubkey_sign,
        "PubKey_enc": pubkey_enc,
        "Encrypted_sign_key": encrypted_sign_key,
        "Encrypted_enc_key": encrypted_enc_key
    }

    # 5. Sign message with existing signature key
    message = json.dumps(unsigned_payload, sort_keys=True).encode()
    signature = priv_sign.sign(message)
    signature_b64 = base64.b64encode(signature).decode()

    # 6. Add signature to payload
    final_payload = dict(unsigned_payload)
    final_payload["signature"] = signature_b64

    return json.dumps(final_payload)

def send_message_payload(sender, recipient, content, message_type, unlock_date, Pubkey_recipient, file_metadata=None):
    # 1. Generate a symmetric key (ChaCha20)
    k_msg = generate_symmetric_key()

    # 2. Encrypt message with this key only if we have content
    if content is not None:
        # For regular content, encrypt it
        if isinstance(content, str):
            content_bytes = content.encode()
        else:
            content_bytes = content
            
        ciphertext, nonce = encrypt_message_symmetric(content_bytes, k_msg)
    else:
        # No content to encrypt
        ciphertext = None
        nonce = None

    # 3. Encrypt key with recipient's public key
    pubkey_recipient_bytes = base64.b64decode(Pubkey_recipient)
    encrypted_k_msg = encrypt_key_asymmetric(k_msg, pubkey_recipient_bytes)

    # Calculate time until unlocking to adapt VDF
    has_vdf_puzzle = False
    vdf_challenge = None
    
    # Non-used code (VDF created on server side)
    if unlock_date:
        try:
            # Convert date format to datetime object
            day, month, year, hour, minute, second = unlock_date.split(":")
            unlock_datetime = datetime(int(year), int(month), int(day), 
                                     int(hour), int(minute), int(second))
            now = datetime.now()
            
            # Verify if unlocking date is in the future
            if unlock_datetime > now:
                # Calculate remaining time in seconds
                time_diff = (unlock_datetime - now).total_seconds()
                
                # If delay is less than 5 minutes, no VDF
                if time_diff > 300:  # More than 5 minutes
                    # Generate a challenge key
                    challenge_key = generate_symmetric_key()
                    
                    # Determine puzzle difficulty
                    # The further the date, the longer the puzzle to solve
                    # But we limit the time to 5 minutes maximum to not block the browser
                    vdf_seconds = min(time_diff / 120, 300)  # ~0.8% of total time, max 5 min
                    
                    print(f"Generating adapted VDF puzzle: {vdf_seconds:.2f} seconds for a delay of {time_diff:.2f} seconds")
                    
                    # Create time-lock puzzle
                    from vdf_crypto import generate_time_lock_puzzle, encrypt_with_challenge_key, store_original_encrypted_k_msg
                    N, T, C = generate_time_lock_puzzle(challenge_key, vdf_seconds)
                    
                    # Double encryption: encrypt already encrypted key with challenge key
                    double_encrypted = encrypt_with_challenge_key(encrypted_k_msg, challenge_key)
                    
                    # Store original in memory/file for possible recovery
                    message_id = str(uuid.uuid4())
                    store_original_encrypted_k_msg(message_id, encrypted_k_msg)
                    
                    # Replace original encrypted key with double-encrypted version
                    encrypted_k_msg = double_encrypted
                    
                    # Define VDF challenge
                    has_vdf_puzzle = True
                    vdf_challenge = {
                        "N": N,
                        "T": T,
                        "C": C,
                        "unlock_delay_seconds": time_diff
                    }
                    
                    print(f"Generated VDF puzzle: N={N}, T={T}, C={C}")
        except Exception as e:
            print(f"Error generating VDF based on date: {e}")
            # Continue without VDF in case of error

    # 4. Build message D (unsigned)
    D = {
        "encrypted_k_msg": base64.b64encode(encrypted_k_msg).decode(),
        "unlock_date": unlock_date,
        "is_binary": not isinstance(content, str) if content is not None else True  # Mark if it's a binary file
    }
    
    # Add ciphertext and nonce only if we have content
    if content is not None:
        D["ciphertext"] = base64.b64encode(ciphertext).decode()
        if nonce is not None:  # Only add nonce if we actually encrypted the content
            D["nonce"] = base64.b64encode(nonce).decode()
    
    # Add file metadata if it's a file
    if file_metadata and message_type != "text":
        D["file_metadata"] = file_metadata
        
    # Add VDF challenge if present
    if has_vdf_puzzle:
        D["vdf_challenge"] = vdf_challenge

    # 5. Hash D for signature
    hashed_D = hash_dict(D)  # → bytes

    # 6. Load sender's signature private key
    sender_dir = Path(f"client_keys/{sender}")
    priv_sign = load_private_key(sender_dir / "sign_key.pem")
    if not isinstance(priv_sign, Ed25519PrivateKey):
        raise ValueError("Sender private key must be Ed25519")

    # 7. Sign hash of D
    signature = priv_sign.sign(hashed_D)
    signature_b64 = base64.b64encode(signature).decode()

    # 8. Create final message
    msg = {
        "message_id": str(uuid.uuid4()) if not has_vdf_puzzle else message_id,
        "from": sender,
        "to": recipient,
        "type": message_type,
        "payload": D,
        "signature": signature_b64
    }

    # Debug prints for large files
    if file_metadata and "local_file_path" in file_metadata:
        print("\n=== DEBUG: Large File Message ===")
        print(f"Message ID: {msg['message_id']}")
        print(f"From: {msg['from']}")
        print(f"To: {msg['to']}")
        print(f"Type: {msg['type']}")
        print("Payload:")
        print(f"  - encrypted_k_msg: {msg['payload']['encrypted_k_msg'][:50]}...")
        print(f"  - unlock_date: {msg['payload']['unlock_date']}")
        print(f"  - is_binary: {msg['payload']['is_binary']}")
        print("File Metadata:")
        for key, value in msg['payload']['file_metadata'].items():
            print(f"  - {key}: {value}")
        print(f"Signature: {msg['signature'][:50]}...")
        print("===============================\n")

    # Return the raw message instead of JSON encoding it
    return {"action": "send_message", "message": msg}

def decrypt_message(message, recipient_private_key, sender_pubkey_sign=None):
    """
    Decrypt a received message and verify signature if sender's public key is provided.
    
    Args:
        message (dict): The message to decrypt
        recipient_private_key (X25519PrivateKey): The recipient's private key
        sender_pubkey_sign (bytes, optional): The sender's signature public key (format Raw)
    
    Returns:
        dict: Contains decrypted content and signature verification status
    """
    try:
        # Extract data from payload
        payload = message.get("payload", {})
        message_id = message.get("message_id")
        sender = message.get("from", "unknown")
        
        if not payload:
            return {"content": "Error: empty payload", "signature_verified": False}
            
        encrypted_k_msg_b64 = payload.get("encrypted_k_msg")
        nonce_b64 = payload.get("nonce")
        ciphertext_b64 = payload.get("ciphertext")
        vdf_challenge = payload.get("vdf_challenge")
        is_binary = payload.get("is_binary", False)  # Default to consider as text
        
        # Check if this is a large file
        file_metadata = payload.get("file_metadata", {})
        local_file_path = file_metadata.get("local_file_path")
        
        # Extract signature
        signature_b64 = message.get("signature")
        
        # For large files, we don't need ciphertext and nonce
        if local_file_path:
            if not encrypted_k_msg_b64:
                return {"content": "Error: missing encrypted key for large file", "signature_verified": False}
        else:
            # For normal messages, we need all components
            if not all([encrypted_k_msg_b64, nonce_b64, ciphertext_b64]):
                return {"content": "Error: incomplete message", "signature_verified": False}
            
        # Convert from base64 to bytes
        encrypted_k_msg = base64.b64decode(encrypted_k_msg_b64)
        
        # For normal messages, convert other components
        if not local_file_path:
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
        
        # Verify signature if public key is provided
        signature_verified = False
        if sender_pubkey_sign and signature_b64:
            try:
                # Hash the payload for signature verification
                payload_hash = hash_dict(payload)
                signature = base64.b64decode(signature_b64)
                sender_pubkey = Ed25519PublicKey.from_public_bytes(sender_pubkey_sign)
                sender_pubkey.verify(signature, payload_hash)
                signature_verified = True
            except Exception as e:
                print(f"Signature verification failed: {e}")
        
        # Solve VDF challenge if present
        if vdf_challenge:
            print("Message protected by a time-lock puzzle. Decryption in progress...")
            
            # First verify if message is still locked by date
            unlock_date_str = payload.get("unlock_date")
            unlock_date_passed = False
            
            if unlock_date_str:
                try:
                    day, month, year, hour, minute, second = unlock_date_str.split(":")
                    unlock_datetime = datetime(int(year), int(month), int(day), 
                                            int(hour), int(minute), int(second))
                    now = datetime.now()
                    unlock_date_passed = now >= unlock_datetime
                except Exception as e:
                    print(f"Error verifying date: {e}")
            
            # If date has passed, server should give us the key
            # Client must not access server files directly
            if unlock_date_passed or not unlock_date_str:
                return {"content": "Message locked: ask server for key", "signature_verified": signature_verified}
            
            # If date hasn't passed, we need to solve the puzzle
            N = vdf_challenge.get("N")
            T = vdf_challenge.get("T")
            C = vdf_challenge.get("C")
            
            if all([N, T, C]):
                # Solve puzzle to get challenge key
                print(f"Solving VDF puzzle with {T} iterations...")
                challenge_key = solve_time_lock_puzzle(N, T, C)
                # Decrypt symmetric key with challenge key
                encrypted_k_msg = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)
            else:
                return {"content": "Error: incomplete puzzle parameters", "signature_verified": signature_verified}
        
        # Decrypt symmetric key with recipient's private key
        from crypto_utils import decrypt_key_asymmetric
        k_msg = decrypt_key_asymmetric(encrypted_k_msg, recipient_private_key)
        
        # If this is a large file, return the local file path instead of decrypting content
        if local_file_path:
            print(f"Large file detected, returning local path: {local_file_path}")
            return {
                "content": local_file_path,
                "signature_verified": signature_verified,
                "is_large_file": True,
                "file_metadata": file_metadata
            }
        
        # For normal messages, decrypt the content
        from crypto_utils import decrypt_message_symmetric
        decrypted_content = decrypt_message_symmetric(ciphertext, nonce, k_msg)
        
        # For text messages, decode to string
        if not is_binary:
            try:
                decrypted_content = decrypted_content.decode('utf-8')
            except UnicodeDecodeError:
                print("Warning: Could not decode content as UTF-8, returning as bytes")
        
        return {
            "content": decrypted_content,
            "signature_verified": signature_verified,
            "is_large_file": False
        }
        
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return {"content": f"Error decrypting: {str(e)}", "signature_verified": False}

def download_messages(username, server_response=None):
    """
    Download all messages for a user and store them in a local directory.
    
    Args:
        username (str): User name
        server_response (str, optional): Server response containing messages. If None, messages will be requested from server.
        
    Returns:
        dict: Information about downloaded messages
    """
    # Create destination directory if it doesn't exist
    download_dir = Path(f"client_messages_download/{username}")
    download_dir.mkdir(parents=True, exist_ok=True)
    
    # If no server response is provided, request messages from server
    if server_response is None:
        # Create request
        request = {
            "action": "get_messages",
            "username": username
        }
        
        # Send request to server (to be implemented in main application)
        # server_response = send_request_to_server(json.dumps(request))
        return {
            "status": "error",
            "message": "No server response provided. This function must be called from the main application."
        }
    
    # Process server response
    if isinstance(server_response, str):
        server_response = json.loads(server_response)
        
    if server_response.get("status") != "success" or "messages" not in server_response:
        return {
            "status": "error",
            "message": f"Server error: {server_response.get('message', 'Invalid response')}"
        }
        
    messages = server_response["messages"]
    if not messages:
        return {
            "status": "info",
            "message": "No messages to download"
        }
    
    # Load decryption private key
    try:
        user_dir = Path(f"client_keys/{username}")
        priv_enc = load_private_key(user_dir / "enc_key.pem")
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error loading private key: {e}"
        }
    
    # Decrypt and save each message
    downloaded_messages = []
    locked_messages = []
    errors = []
    
    for msg in messages:
        try:
            message_id = msg.get("message_id", "unknown")
            sender = msg.get("from", "unknown")
            timestamp = msg.get("timestamp", "")
            
            # Create unique filename for message
            timestamp_str = timestamp.replace(" ", "_").replace(":", "-") if timestamp else ""
            filename = f"{message_id}_{sender}_{timestamp_str}.json"
            
            # Save raw message
            with open(download_dir / filename, "w", encoding="utf-8") as f:
                json.dump(msg, f, indent=4)
                
            # Verify if message can be decrypted
            payload = msg.get("payload", {})
            unlock_date_str = payload.get("unlock_date")
            vdf_challenge = payload.get("vdf_challenge")
            
            is_locked = False
            
            # Verify if message is locked by date
            if unlock_date_str:
                try:
                    day, month, year, hour, minute, second = unlock_date_str.split(":")
                    unlock_datetime = datetime(int(year), int(month), int(day), 
                                            int(hour), int(minute), int(second))
                    now = datetime.now()
                    is_locked = now < unlock_datetime
                except Exception as e:
                    print(f"Error parsing date: {e}")
            
            # If message is not locked by date, try to decrypt it
            if not is_locked:
                try:
                    content = decrypt_message(msg, priv_enc)
                    
                    if isinstance(content, str):
                        # Save decrypted content for text messages
                        content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.txt"
                        with open(download_dir / content_filename, "w", encoding="utf-8") as f:
                            f.write(content)
                    else:
                        # Save binary content
                        content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.bin"
                        with open(download_dir / content_filename, "wb") as f:
                            f.write(content)
                    
                    downloaded_messages.append({
                        "id": message_id,
                        "sender": sender,
                        "timestamp": timestamp,
                        "filename": content_filename,
                        "is_decrypted": True
                    })
                except Exception as e:
                    if vdf_challenge:
                        # If decryption fails and there's a VDF challenge, it's probably because of the VDF
                        locked_messages.append({
                            "id": message_id,
                            "sender": sender,
                            "timestamp": timestamp,
                            "vdf_challenge": True
                        })
                    else:
                        errors.append({
                            "id": message_id,
                            "error": str(e)
                        })
            else:
                # Message locked by date
                locked_messages.append({
                    "id": message_id,
                    "sender": sender,
                    "timestamp": timestamp,
                    "unlock_date": unlock_date_str,
                    "date_locked": True
                })
            
        except Exception as e:
            errors.append({
                "id": msg.get("message_id", "unknown"),
                "error": str(e)
            })
    
    return {
        "status": "success",
        "downloaded": len(downloaded_messages),
        "locked": len(locked_messages),
        "errors": len(errors),
        "download_dir": str(download_dir),
        "messages": downloaded_messages,
        "locked_messages": locked_messages,
        "error_details": errors
    }

def solve_vdf_for_message(username, message_id, server_response=None):
    """
    Solve VDF manually for a specific message.
    
    Args:
        username (str): User name
        message_id (str): Message ID
        server_response (str, optional): Server response containing the message. If None, the message will be requested.
        
    Returns:
        dict: Operation result
    """
    try:
        if server_response is None:
            return {
                "status": "error",
                "message": "No server response provided. This function must be called from the main application."
            }
        
        if isinstance(server_response, str):
            server_response = json.loads(server_response)
            
        # Extract message from server data
        message = server_response.get("message", {})
        if not message:
            return {
                "status": "error",
                "message": "Message not found in server response"
            }
            
        # Verify if message has a VDF challenge
        payload = message.get("payload", {})
        vdf_challenge = payload.get("vdf_challenge")
        
        if not vdf_challenge:
            return {
                "status": "error",
                "message": "This message has no VDF challenge"
            }
            
        # Extract VDF parameters
        N = vdf_challenge.get("N")
        T = vdf_challenge.get("T")
        C = vdf_challenge.get("C")
        unlock_delay_seconds = vdf_challenge.get("unlock_delay_seconds")
        
        if not all([N, T, C]):
            return {
                "status": "error",
                "message": "VDF parameters incomplete"
            }
            
        print(f"Local VDF solving in progress for message {message_id}...")
        print(f"This operation may take time ({T} iterations)")
        
        if unlock_delay_seconds:
            print(f"This message is designed to be unlocked after about {unlock_delay_seconds} seconds")
        
        # Solve puzzle - return key in bytes
        challenge_key = solve_time_lock_puzzle(N, T, C)
        print(f"Challenge key solved (size: {len(challenge_key)} bytes)")
        
        # Extract and decrypt encrypted_k_msg
        encrypted_k_msg_b64 = payload.get("encrypted_k_msg")
        if not encrypted_k_msg_b64:
            return {
                "status": "error",
                "message": "encrypted_k_msg parameter missing"
            }
            
        encrypted_k_msg = base64.b64decode(encrypted_k_msg_b64)
        
        # Decrypt first layer (VDF) to get asymmetric encrypted key
        asymmetric_encrypted_key = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)
        print(f"First layer decrypted with challenge key (size: {len(asymmetric_encrypted_key)} bytes)")
        
        # Create a copy of message for modifications
        updated_message = json.loads(json.dumps(message))
        updated_payload = updated_message.get("payload", {})
        
        # Store asymmetric encrypted key (after VDF solved)
        updated_payload["encrypted_k_msg"] = base64.b64encode(asymmetric_encrypted_key).decode()
        
        # Remove VDF challenge now that it's solved
        if "vdf_challenge" in updated_payload:
            del updated_payload["vdf_challenge"]
            
        # Update message
        updated_message["payload"] = updated_payload
        
        # Save in local file
        user_dir = Path(f"client_messages_download/{username}")
        user_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        timestamp = message.get("timestamp", "")
        sender = message.get("from", "unknown")
        timestamp_str = timestamp.replace(" ", "_").replace(":", "-") if timestamp else ""
        filename = f"{message_id}_{sender}_{timestamp_str}_solved.json"
        
        with open(user_dir / filename, "w", encoding="utf-8") as f:
            json.dump(updated_message, f, indent=4)
        
        try:
            # Load decryption private key
            user_dir_keys = Path(f"client_keys/{username}")
            with open(user_dir_keys / "enc_key.pem", "rb") as f:
                priv_enc = serialization.load_pem_private_key(f.read(), password=None)
                
            # Decrypt message with recipient's private key
            content = decrypt_message(updated_message, priv_enc)
            
            # Save decrypted content
            if isinstance(content, str):
                content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.txt"
                with open(user_dir / content_filename, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.bin"
                with open(user_dir / content_filename, "wb") as f:
                    f.write(content)
                    
            return {
                "status": "success",
                "message": "VDF solved locally and message decrypted",
                "saved_file": str(user_dir / filename),
                "content_file": str(user_dir / content_filename),
                "updated_message": updated_message,
                "solved": True
            }
            
        except Exception as e:
            print(f"Error decrypting after solving: {e}")
            return {
                "status": "success",
                "message": "VDF solved locally but decryption error after solving: " + str(e),
                "saved_file": str(user_dir / filename),
                "updated_message": updated_message,
                "solved": True
            }
    
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error solving VDF: {str(e)}"
        }

def solve_vdf_for_message_locally(username, message, force_solve=False):
    """
    Solve VDF locally for a message without contacting the server.
    
    Args:
        username (str): User name
        message (dict): The complete message with its data
        force_solve (bool): If True, force VDF solving even if date has passed
        
    Returns:
        dict: Operation result
    """
    try:
        message_id = message.get("message_id")
        if not message_id:
            return {
                "status": "error",
                "message": "Message ID missing"
            }
            
        # Verify if message has a VDF challenge
        payload = message.get("payload", {})
        vdf_challenge = payload.get("vdf_challenge")
        
        if not vdf_challenge:
            return {
                "status": "error",
                "message": "This message has no VDF challenge"
            }
            
        # First verify if message is still locked by date
        unlock_date_str = payload.get("unlock_date")
        if unlock_date_str and not force_solve:
            try:
                day, month, year, hour, minute, second = unlock_date_str.split(":")
                unlock_datetime = datetime(int(year), int(month), int(day), 
                                        int(hour), int(minute), int(second))
                now = datetime.now()
                if now < unlock_datetime:
                    return {
                        "status": "error",
                        "message": f"Message still locked until {unlock_datetime.strftime('%d/%m/%Y %H:%M:%S')}"
                    }
            except Exception as e:
                print(f"Error verifying date: {e}")
            
        # Extract VDF parameters
        N = vdf_challenge.get("N")
        T = vdf_challenge.get("T")
        C = vdf_challenge.get("C")
        
        if not all([N, T, C]):
            return {
                "status": "error",
                "message": "VDF parameters incomplete"
            }
            
        print(f"Local VDF solving in progress for message {message_id}...")
        print(f"This operation may take time ({T} iterations)")
        
        # Solve puzzle - return key in bytes
        challenge_key = solve_time_lock_puzzle(N, T, C)
        print(f"Challenge key solved (size: {len(challenge_key)} bytes)")
        
        # Extract and decrypt encrypted_k_msg
        encrypted_k_msg_b64 = payload.get("encrypted_k_msg")
        if not encrypted_k_msg_b64:
            return {
                "status": "error",
                "message": "encrypted_k_msg parameter missing"
            }
            
        encrypted_k_msg = base64.b64decode(encrypted_k_msg_b64)
        
        # Decrypt first layer (VDF) to get asymmetric encrypted key
        asymmetric_encrypted_key = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)
        print(f"First layer decrypted with challenge key (size: {len(asymmetric_encrypted_key)} bytes)")
        
        # Create a copy of message for modifications
        updated_message = json.loads(json.dumps(message))
        updated_payload = updated_message.get("payload", {})
        
        # Store asymmetric encrypted key (after VDF solved)
        updated_payload["encrypted_k_msg"] = base64.b64encode(asymmetric_encrypted_key).decode()
        
        # Remove VDF challenge now that it's solved
        if "vdf_challenge" in updated_payload:
            del updated_payload["vdf_challenge"]
            
        # Update message
        updated_message["payload"] = updated_payload
        
        # Save in local file
        user_dir = Path(f"client_messages_download/{username}")
        user_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        timestamp = message.get("timestamp", "")
        sender = message.get("from", "unknown")
        timestamp_str = timestamp.replace(" ", "_").replace(":", "-") if timestamp else ""
        filename = f"{message_id}_{sender}_{timestamp_str}_solved.json"
        
        with open(user_dir / filename, "w", encoding="utf-8") as f:
            json.dump(updated_message, f, indent=4)
        
        try:
            # Load decryption private key
            user_dir_keys = Path(f"client_keys/{username}")
            with open(user_dir_keys / "enc_key.pem", "rb") as f:
                priv_enc = serialization.load_pem_private_key(f.read(), password=None)
                
            # Decrypt message with recipient's private key
            content = decrypt_message(updated_message, priv_enc)
            
            # Save decrypted content
            if isinstance(content, str):
                content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.txt"
                with open(user_dir / content_filename, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.bin"
                with open(user_dir / content_filename, "wb") as f:
                    f.write(content)
                    
            return {
                "status": "success",
                "message": "VDF solved",
                "decrypted_content": content if isinstance(content, str) else "[Decrypted file]",
                "saved_file": str(user_dir / filename),
                "content_file": str(user_dir / content_filename),
                "updated_message": updated_message
            }
            
        except Exception as e:
            print(f"Error decrypting after solving: {e}")
            return {
                "status": "error",
                "message": f"Error decrypting: {str(e)}"
            }
    
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error solving VDF: {str(e)}"
        }