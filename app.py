from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, Response, stream_with_context
from io import BytesIO
import json
from client import create_user, reset_password, get_keys_from_password, send_message_payload, decrypt_message
import socket
import ssl
from datetime import timedelta, datetime
from functools import wraps
import os
from pathlib import Path
import uuid
import base64
import time
from crypto_utils import derive_encryption_key, hash_password_argon2id, derive_salt_from_username, generate_symmetric_key, encrypt_message_symmetric
from vdf_crypto import generate_challenge_key, encrypt_with_challenge_key, generate_time_lock_puzzle, solve_time_lock_puzzle, decrypt_with_challenge_key
import threading
from cryptography.hazmat.primitives import serialization
import hashlib
import tempfile

app = Flask(__name__)
# Note: In a production environment, it would be better to:
# 1. Separate configuration into a config.py file
# 2. Use environment variables for secrets
# 3. Implement more robust session management with Redis or a database
# 4. Add additional security middlewares
# This is a POC with basic security (web design level)
app.secret_key = 'votre_cle_secrete'  # Replace with a real secret key in production

# Basic session configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF attack protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Session expires after 15 minutes

# In production, enable these options:
# app.config['SESSION_COOKIE_SECURE'] = True  # Force HTTPS for cookies

# Dictionnaire pour stocker la progression des VDF
vdf_progress = {}
vdf_results = {}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', error="Your session has expired. Please login again."))
        return f(*args, **kwargs)
    return decorated_function

def send_payload(payload, chunk_size=8192, max_retries=3):
    host = 'localhost'
    port = 8443
    server_cert = 'server.crt'

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=server_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False

    # Convert payload to bytes if it's a string
    if isinstance(payload, str):
        payload_bytes = payload.encode()
    else:
        payload_bytes = payload
        
    payload_len = len(payload_bytes)
    print(f"\n=== DEBUG: Sending Payload ===")
    print(f"Payload size: {payload_len} bytes")
    print(f"Connecting to {host}:{port}...")
    
    retries = 0
    while retries < max_retries:
        try:
            print("Creating socket connection...")
            with socket.create_connection((host, port), timeout=300) as sock:  # 5-minute timeout
                print("Socket connected, wrapping with TLS...")
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    print("TLS connection established")
                    
                    # For large payloads, send in chunks
                    total_sent = 0
                    
                    # Dynamically adjust chunk size based on payload size
                    if payload_len > 1_000_000_000:  # > 1 GB
                        actual_chunk_size = 1048576  # 1 MB chunks
                    elif payload_len > 100_000_000:  # > 100 MB
                        actual_chunk_size = 524288   # 512 KB chunks
                    elif payload_len > 10_000_000:   # > 10 MB
                        actual_chunk_size = 262144   # 256 KB chunks
                    else:
                        actual_chunk_size = chunk_size  # Default (8 KB)
                    
                    print(f"Using chunk size: {actual_chunk_size} bytes")
                    
                    # Start sending data in chunks
                    start_time = time.time()
                    last_progress_time = start_time
                    
                    for i in range(0, payload_len, actual_chunk_size):
                        chunk = payload_bytes[i:i+actual_chunk_size]
                        bytes_sent = ssock.send(chunk)
                        total_sent += bytes_sent
                        
                        # Print progress every 5 seconds for large payloads
                        current_time = time.time()
                        if payload_len > 1_000_000 and (current_time - last_progress_time) >= 5:
                            percent_complete = (total_sent / payload_len) * 100
                            elapsed = current_time - start_time
                            speed = total_sent / elapsed if elapsed > 0 else 0
                            speed_unit = "B/s"
                            
                            if speed > 1024*1024:
                                speed /= (1024*1024)
                                speed_unit = "MB/s"
                            elif speed > 1024:
                                speed /= 1024
                                speed_unit = "KB/s"
                                
                            print(f"Upload progress: {percent_complete:.1f}% ({total_sent}/{payload_len} bytes) - {speed:.2f} {speed_unit}")
                            last_progress_time = current_time
                        
                        # Add a small delay for very large chunks to avoid network congestion
                        if actual_chunk_size > chunk_size:
                            time.sleep(0.001)
                    
                    print(f"Upload completed: {total_sent}/{payload_len} bytes sent")
                    
                    # Receive the response in chunks
                    print("Waiting for server response...")
                    buffer = b""
                    while True:
                        try:
                            chunk = ssock.recv(chunk_size)
                            if not chunk:
                                break
                            buffer += chunk
                            
                            # Try to see if we have a complete JSON
                            try:
                                json.loads(buffer.decode())
                                # If we're here, the JSON is complete
                                break
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                # Continue reading if there's more data
                                continue
                        except socket.timeout:
                            print("Socket timeout while receiving data")
                            if buffer:  # If we received partial data, try to use it
                                break
                            else:
                                raise
                    
                    print("Server response received")
                    return buffer.decode()
        except (socket.timeout, ConnectionResetError) as e:
            retries += 1
            if retries >= max_retries:
                print(f"Error: Connection failed after {max_retries} attempts - {str(e)}")
                return f"Error: Connection failed after {max_retries} attempts - {str(e)}"
            print(f"Connection issue ({str(e)}), retrying ({retries}/{max_retries})...")
            time.sleep(2)  # Wait before retrying
        except Exception as e:
            print(f"Error: {e}")
            return f"Error: {e}"
            
    print("Maximum retries exceeded")
    return "Error: Maximum retries exceeded."

@app.route("/", methods=["GET"])
@login_required
def index():
    return render_template("dashboard.html", username=session['username'])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate input
        if not username or not password:
            return render_template("login.html", error="Username and password are required")

        salt_argon2 = derive_salt_from_username(username)
        master_key = hash_password_argon2id(password, salt_argon2)
        auth_key = derive_encryption_key(master_key, info=b"auth_key")
        auth_key_b64 = base64.b64encode(auth_key).decode()

        payload = json.dumps({
            "action": "get_user_all_data",
            "username": username,
            "auth_key": auth_key_b64
        })

        rep = send_payload(payload)
        
        # Vérifier si l'utilisateur existe
        try:
            rep_json = json.loads(rep)
            if "status" in rep_json and rep_json["status"] == "error":
                return render_template("login.html", error=f"Server error: {rep_json.get('message', 'Unknown error')}")
        except json.JSONDecodeError:
            return render_template("login.html", error="Invalid server response format")

        try:
            response = get_keys_from_password(username, password, rep)            
            # Print details for debugging
            print(f"get_keys_from_password response: {response}")

            # Properly check if response is True or a success string
            if response is True:  # If keys were successfully retrieved
                session['username'] = username
                return redirect(url_for('index'))
            elif isinstance(response, str):
                # Handle specific error messages
                if response == "Mot de passe incorrect" or response == "Mot de passe incorrect ou erreur de déchiffrement":
                    return render_template("login.html", error="Mot de passe incorrect")
                else:
                    return render_template("login.html", error=response)
            else:
                return render_template("login.html", error="Invalid username or password")
        except Exception as e:
            print(f"Login error: {str(e)}")
            return render_template("login.html", error=f"Error: {str(e)}")

    error = request.args.get('error')
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/create_user", methods=["GET", "POST"])
def create_user_page():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            return render_template("create_user.html", error="Please fill in all fields")
        
        payload = create_user(username, password)
        response = send_payload(payload)
        
        if "Error" in response:
            return render_template("create_user.html", error=response)
        else:
            return render_template("create_user.html", success="Account created successfully! You can now login.")
            
    return render_template("create_user.html")

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        username = session['username']

        # Derive auth_key from old password
        salt_argon2 = derive_salt_from_username(username)
        master_key = hash_password_argon2id(old_password, salt_argon2)
        auth_key = derive_encryption_key(master_key, info=b"auth_key")
        auth_key_b64 = base64.b64encode(auth_key).decode()

        # Request user data with auth_key verification
        payload = json.dumps({
            "action": "get_user_all_data",
            "username": username,
            "auth_key": auth_key_b64
        })
        rep = send_payload(payload)

        is_key_retreived = True
        try:
            is_key_retreived = get_keys_from_password(username, old_password, rep)
        except FileNotFoundError:
            return render_template("change_password.html", error="Unable to reconstruct your private keys. Incorrect password.")

        if is_key_retreived:
            payload = reset_password(new_password, username)
            response = send_payload(payload)
            return render_template("change_password.html", success="Password updated successfully")
        
        return render_template("change_password.html", error="Failed to update password")

    return render_template("change_password.html")

@app.route("/send_message", methods=["GET", "POST"])
@login_required
def send_message():
    if request.method == "POST":
        recipient = request.form.get("recipient")
        message_type = request.form.get("message_type")
        unlock_date = request.form.get("unlock_date")
        
        # Convert the datetime-local input to our format
        try:
            unlock_datetime = datetime.fromisoformat(unlock_date.replace('Z', '+00:00'))
            unlock_date = unlock_datetime.strftime("%d:%m:%Y:%H:%M:%S")
        except ValueError:
            return render_template("send_message.html", error="Invalid date format", now=datetime.now().strftime("%Y-%m-%dT%H:%M"))
        
        if message_type == "text":
            message = request.form.get("message")
            if not message:
                return render_template("send_message.html", error="Please enter a message")
            content = message  # Texte simple, sera encodé dans send_message_payload
            file_info = None
        else:  # file
            file = request.files.get("file")
            if not file:
                return render_template("send_message.html", error="Please select a file")
            
            # Get file information but don't read content yet
            filename = file.filename
            file_extension = os.path.splitext(filename)[1] if filename else ""
            file_size = 0
            
            # Create a temporary file to store the uploaded file
            temp_file_path = os.path.join("temp_uploads", f"{str(uuid.uuid4())}{file_extension}")
            os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
            
            # Stream the file to disk instead of loading it entirely into memory
            try:
                file.save(temp_file_path)
                file_size = os.path.getsize(temp_file_path)
                if file_size == 0:
                    os.remove(temp_file_path)
                    return render_template("send_message.html", error="File is empty")
                
                # Store file info instead of content
                file_info = {
                    "path": temp_file_path,
                    "original_name": filename,
                    "extension": file_extension,
                    "size": file_size
                }
                content = None  # Will be processed in chunks later
            except Exception as e:
                return render_template("send_message.html", error=f"Error processing file: {str(e)}")
        
        payload = json.dumps({"action": "get_user_pub_key", "username": recipient})
        rep = send_payload(payload)
        
        print(f"Server response for recipient: {rep}")

        try:
            rep_json = json.loads(rep)
            if "status" in rep_json and rep_json["status"] == "error":
                if file_info and os.path.exists(file_info["path"]):
                    os.remove(file_info["path"])  # Clean up temp file
                return render_template("send_message.html", error=f"Error getting recipient data: {rep_json.get('message', 'Unknown error')}")
            
            # The structure of the server response should match what we expect
            if "PubKey_enc" not in rep_json:
                print(f"Missing PubKey_enc in server response: {rep_json}")
                if file_info and os.path.exists(file_info["path"]):
                    os.remove(file_info["path"])  # Clean up temp file
                return render_template("send_message.html", error="Recipient's public key not found. User might not exist.")
                
            Pubkey_enc_recipient = rep_json["PubKey_enc"]
        except json.JSONDecodeError:
            if file_info and os.path.exists(file_info["path"]):
                os.remove(file_info["path"])  # Clean up temp file
            return render_template("send_message.html", error="Invalid response from server")
            
        sender = session['username']
        
        try:
            # For text messages, use the regular flow
            if message_type == "text":
                payload2 = send_message_payload(sender, recipient, content, message_type, unlock_date, Pubkey_enc_recipient)
            else:
                # For file messages, include file metadata in the message
                if not file_info:
                    return render_template("send_message.html", error="File information not available")
                
                # Add file metadata to be included in the message
                file_metadata = {
                    "filename": file_info["original_name"],
                    "extension": file_info["extension"],
                    "size": file_info["size"]
                }
                
                # Process the file in chunks to avoid memory issues
                LARGE_FILE_THRESHOLD = 20 * 1024 * 1024  # 20MB threshold for "large files"
                
                if file_info["size"] > LARGE_FILE_THRESHOLD:
                    print(f"Processing large file: {file_info['size']} bytes")
                    
                    # Generate a message ID for this file
                    message_id = str(uuid.uuid4())
                    
                    # Store the encrypted file locally
                    encrypted_file_path = store_encrypted_file(file_info["path"], message_id, file_metadata)
                    
                    # Add the local file path to metadata
                    file_metadata['local_file_path'] = encrypted_file_path
                    file_metadata['message_id'] = message_id
                    
                    # Create a minimal payload for large files
                    # Instead of sending the encrypted content, we'll just send the path
                    payload2 = send_message_payload(
                        sender, 
                        recipient, 
                        None,  # No content to encrypt
                        message_type, 
                        unlock_date, 
                        Pubkey_enc_recipient,
                        file_metadata  # Include file metadata with local path
                    )
                    
                    # Store the original file path for cleanup
                    if 'large_files' not in session:
                        session['large_files'] = {}
                    
                    session['large_files'][message_id] = {
                        'path': file_info["path"],
                        'filename': file_info["original_name"],
                        'mime_type': 'application/octet-stream',
                        'delete_after': True  # Delete after processing
                    }
                else:
                    # For smaller files, read the entire content
                    with open(file_info["path"], 'rb') as f:
                        file_content = f.read()
                    
                    # We can delete the temp file now that we have the content
                    if os.path.exists(file_info["path"]):
                        try:
                            os.remove(file_info["path"])
                        except Exception as e:
                            print(f"Warning: Could not delete temp file: {e}")
                    
                    # Send the message with the file content
                    payload2 = send_message_payload(
                        sender,
                        recipient,
                        file_content,
                        message_type,
                        unlock_date,
                        Pubkey_enc_recipient,
                        file_metadata
                    )
            
            # After reading the file, send the message
            payload_json = json.dumps(payload2)
            print(f"Message payload size: {len(payload_json)} bytes")
            print(payload_json)
            response = send_payload(payload_json)
            print(f"Server response: {response}")
            
            try:
                response_json = json.loads(response)
                if response_json.get("status") == "success":
                    return render_template("send_message.html", success="Message sent successfully")
                else:
                    return render_template("send_message.html", error=response_json.get("message", "Failed to send message"))
            except json.JSONDecodeError:
                return render_template("send_message.html", error="Failed to send message")
        except Exception as e:
            # Clean up temp file in case of error
            if file_info and os.path.exists(file_info["path"]):
                os.remove(file_info["path"])
            return render_template("send_message.html", error=f"Error processing message: {str(e)}")
    
    return render_template("send_message.html", now=datetime.now().strftime("%Y-%m-%dT%H:%M"))

@app.route("/retrieve_messages", methods=["GET"])
@login_required
def retrieve_messages():
    username = session['username']
    
    # Récupérer la liste des messages
    try:
        # 1. Télécharger d'abord les messages depuis le serveur
        request_data = {
            "action": "get_messages",
            "username": username
        }
        
        server_response = send_payload(json.dumps(request_data))
        server_data = json.loads(server_response)
        
        if server_data.get("status") != "success" or "messages" not in server_data:
            # En cas d'erreur avec le serveur, essayer de lire les messages locaux
            print(f"Erreur serveur: {server_data.get('message', 'Erreur inconnue')}")
            
            # Charger les messages du fichier local
            messages_file = "messages.json"
            if not os.path.exists(messages_file):
                return render_template("retrieve_messages.html", error="Aucun message disponible")
                
            with open(messages_file, 'r') as f:
                messages_data = json.load(f)
                
            # Filtrer les messages pour le destinataire actuel
            user_messages = []
            for msg in messages_data.get("messages", []):
                if msg.get("to") == username:
                    user_messages.append(msg)
        else:
            # Utiliser les messages retournés par le serveur
            user_messages = server_data["messages"]
            
            # Stocker les messages dans un dossier local pour les avoir disponibles hors-ligne
            from client import download_messages
            download_result = download_messages(username, server_response)
            if download_result.get("status") == "success":
                print(f"Messages téléchargés avec succès: {download_result.get('downloaded')} déchiffrés, {download_result.get('locked')} verrouillés")
            else:
                print(f"Erreur lors du téléchargement des messages: {download_result.get('message')}")
                
        if not user_messages:
            return render_template("retrieve_messages.html", info="Vous n'avez pas de messages")
            
        # Charger la clé privée de chiffrement pour déchiffrer
        user_dir = Path(f"client_keys/{username}")
        try:
            from cryptography.hazmat.primitives import serialization
            with open(user_dir / "enc_key.pem", "rb") as f:
                priv_enc = serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            return render_template("retrieve_messages.html", error=f"Erreur de chargement de clé: {e}")
        
        # Récupérer les clés publiques des expéditeurs pour vérifier les signatures
        senders = set(msg.get("from") for msg in user_messages if "from" in msg)
        sender_pubkeys = {}
        
        for sender in senders:
            try:
                print(sender)
                # Requête au serveur pour obtenir la clé publique de signature du sender
                pubkey_request = json.dumps({
                    "action": "get_user_pub_key",
                    "username": sender
                })
                
                pubkey_response = send_payload(pubkey_request)
                pubkey_data = json.loads(pubkey_response)
                
                if pubkey_data.get("status") == "success" and "PubKey_sign" in pubkey_data:
                    # Stocker la clé publique de signature en bytes
                    sender_pubkeys[sender] = base64.b64decode(pubkey_data["PubKey_sign"])
                    print(f"Clé publique de signature récupérée pour {sender}")
                else:
                    print(f"Impossible de récupérer la clé publique de {sender}: {pubkey_data.get('message', 'Erreur inconnue')}")
            except Exception as e:
                print(f"Erreur lors de la récupération de la clé publique de {sender}: {e}")
        
        # Déchiffrer les messages
        decoded_messages = []
        for msg in user_messages:
            sender = msg.get("from", "Inconnu")
            timestamp = msg.get("timestamp", "Date inconnue")
            
            # Vérifier si le message est encore verrouillé par date
            unlock_date_str = msg.get("payload", {}).get("unlock_date")
            is_locked = False
            unlock_date_display = "Non spécifié"
            time_remaining = None
            
            if unlock_date_str:
                try:
                    # Format du unlock_date: "14:05:2023:13:02:00" (jour:mois:année:heure:minute:seconde)
                    day, month, year, hour, minute, second = unlock_date_str.split(":")
                    unlock_datetime = datetime(int(year), int(month), int(day), 
                                              int(hour), int(minute), int(second))
                    now = datetime.now()
                    is_locked = now < unlock_datetime
                    unlock_date_display = unlock_datetime.strftime("%d/%m/%Y %H:%M:%S")
                    
                    # Calcul du temps restant
                    if is_locked:
                        time_diff = unlock_datetime - now
                        days = time_diff.days
                        hours, remainder = divmod(time_diff.seconds, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        
                        if days > 0:
                            time_remaining = f"{days} jours, {hours} heures, {minutes} minutes"
                        elif hours > 0:
                            time_remaining = f"{hours} heures, {minutes} minutes, {seconds} secondes"
                        else:
                            time_remaining = f"{minutes} minutes, {seconds} secondes"
                except Exception as e:
                    print(f"Erreur de parsing de date: {e}")
                    
            # Extraire les informations du puzzle VDF si présentes
            vdf_info = None
            payload = msg.get("payload", {})
            if "vdf_challenge" in payload:
                vdf_data = payload["vdf_challenge"]
                vdf_info = {
                    "iterations": vdf_data.get("T", 0),
                    "has_challenge": True,
                    "N": vdf_data.get("N"),
                    "T": vdf_data.get("T"),
                    "C": vdf_data.get("C")
                }
                # Estimer le temps de résolution (approximatif)
                if vdf_info["iterations"] > 0:
                    estimated_seconds = min(vdf_info["iterations"] * 0.00001, 300)  # Estimation grossière
                    if estimated_seconds < 60:
                        vdf_info["estimated_time"] = f"environ {estimated_seconds:.1f} secondes"
                    else:
                        vdf_info["estimated_time"] = f"environ {estimated_seconds/60:.1f} minutes"
            
            # Déchiffrer seulement si le message n'est pas verrouillé par date
            if not is_locked:
                try:
                    # Récupérer la clé publique du sender pour vérification de signature
                    sender_pubkey = sender_pubkeys.get(sender)
                    
                    # Déchiffrer le message et vérifier la signature
                    result = decrypt_message(msg, priv_enc, sender_pubkey)
                    content = result["content"]
                    signature_verified = result["signature_verified"]
                    
                    # Déterminer si c'est un fichier binaire et comment l'afficher
                    message_type = msg.get("type", "text")
                    is_binary = msg.get("payload", {}).get("is_binary", False)
                    
                    if is_binary or message_type != "text":
                        # Pour les fichiers binaires, indiquer qu'il s'agit d'un fichier à télécharger
                        # On stockera le contenu binaire sur le disque au lieu de la session
                        content_display = f"[Fichier {message_type}]"
                        
                        # Générer un ID unique pour ce fichier
                        file_id = f"file_{msg.get('message_id', str(uuid.uuid4()))}"
                        actual_id = msg.get('message_id', str(uuid.uuid4()))
                        
                        # Détecter le type de fichier
                        content_type = "application/octet-stream"  # Type MIME par défaut
                        
                        # Vérifier les signatures de fichiers courants
                        if isinstance(content, bytes):
                            if content.startswith(b'\xFF\xD8\xFF'):  # JPEG
                                content_type = "image/jpeg"
                            elif content.startswith(b'\x89PNG\r\n\x1A\n') or content[0:8] == b'\x89PNG\r\n\x1A\n':  # PNG
                                content_type = "image/png"
                            elif content.startswith(b'GIF87a') or content.startswith(b'GIF89a'):  # GIF
                                content_type = "image/gif"
                            elif content.startswith(b'%PDF'):  # PDF
                                content_type = "application/pdf"
                            elif len(content) > 50:
                                # Pour les debug, afficher les premiers octets
                                print(f"Premiers octets du fichier: {content[:50]}")
                        
                        # Également détecter à partir de l'extension du nom de fichier
                        file_metadata = msg.get("payload", {}).get("file_metadata", {})
                        if file_metadata and 'filename' in file_metadata:
                            filename = file_metadata['filename'].lower()
                            if filename.endswith('.jpg') or filename.endswith('.jpeg'):
                                content_type = "image/jpeg"
                            elif filename.endswith('.png'):
                                content_type = "image/png"
                            elif filename.endswith('.gif'):
                                content_type = "image/gif"
                            elif filename.endswith('.pdf'):
                                content_type = "application/pdf"
                        
                        # Stocker les métadonnées du fichier
                        metadata = {
                            'mime_type': content_type,
                            'message_id': actual_id
                        }
                        
                        # Ajouter les métadonnées du fichier si disponibles
                        if file_metadata:
                            metadata.update(file_metadata)
                            
                            # Mettre à jour l'affichage pour inclure le nom du fichier
                            if 'filename' in file_metadata:
                                content_display = f"[Fichier: {file_metadata['filename']}]"
                        
                        # Stocker le fichier sur le disque
                        file_hash = store_file_content(content, actual_id, metadata)
                        
                        # Stocker la référence dans la session
                        if 'file_refs' not in session:
                            session['file_refs'] = {}
                        session['file_refs'][actual_id] = file_hash
                        
                        content = content_display
                    
                except Exception as e:
                    content = f"Erreur de déchiffrement: {e}"
                    signature_verified = False
                    if "vdf_challenge" in payload:
                        content += "\n\nCe message nécessite la résolution du puzzle VDF pour être déchiffré."
            else:
                # Message verrouillé par date
                content = f"Message locked until {unlock_date_display}"
                signature_verified = False
                if time_remaining:
                    content += f"\nTime remaining: {time_remaining}"
            
            decoded_messages.append({
                "id": msg.get("message_id", "ID unknown"),
                "sender": sender,
                "timestamp": timestamp,
                "content": content,
                "is_locked": is_locked,
                "unlock_date": unlock_date_display,
                "time_remaining": time_remaining,
                "vdf_info": vdf_info,
                "signature_verified": signature_verified,
                "raw_data": json.dumps(msg)  # Stocker les données brutes du message pour la résolution locale du VDF
            })
            
        # Trier par date (plus récent en premier)
        decoded_messages.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return render_template("retrieve_messages.html", messages=decoded_messages)
        
    except Exception as e:
        return render_template("retrieve_messages.html", error=f"Erreur de récupération: {str(e)}")

@app.route("/download_file/<file_id>", methods=["GET"])
@login_required
def download_file(file_id):
    """
    Download a file from the file_storage directory.
    """
    try:
        # Remove 'file_' prefix if present
        if file_id.startswith('file_'):
            file_id = file_id[5:]
            
        # Try to find the file with any extension
        file_storage_dir = Path("file_storage")
        for file_path in file_storage_dir.glob(f"{file_id}.*"):
            if file_path.exists():
                print(f"Downloading file: {file_path}")
                return send_file(
                    str(file_path),
                    as_attachment=True,
                    download_name=file_path.name
                )
        
        print(f"File not found for ID: {file_id}")
        flash("File not found", "error")
        return redirect(url_for('retrieve_messages'))
        
    except Exception as e:
        print(f"Error downloading file: {e}")
        return str(e), 500

@app.route("/download_messages_route")
@login_required
def download_messages_route():
    username = session['username']
    
    # Créer une requête au serveur pour obtenir les messages
    request_data = {
        "action": "get_messages",
        "username": username
    }
    
    # Envoyer la requête au serveur
    try:
        server_response = send_payload(json.dumps(request_data))
        
        # Appeler la fonction qui télécharge et déchiffre les messages
        from client import download_messages
        result = download_messages(username, server_response)
        
        if result.get("status") == "success":
            flash(f"Téléchargement terminé: {result.get('downloaded')} messages déchiffrés, {result.get('locked')} messages verrouillés", "success")
            return redirect(url_for("retrieve_messages"))
        else:
            flash(f"Erreur: {result.get('message')}", "error")
            return redirect(url_for("retrieve_messages"))
            
    except Exception as e:
        flash(f"Erreur lors du téléchargement des messages: {str(e)}", "error")
        return redirect(url_for("retrieve_messages"))

@app.route("/view_local_messages", methods=["GET"])
@login_required
def view_local_messages():
    username = session['username']
    messages = []
    
    try:
        # Load user's private key
        with open(f"client_keys/{username}/enc_key.pem", "rb") as f:
            priv_enc = serialization.load_pem_private_key(f.read(), password=None)
        
        # Get all message files
        user_dir = Path(f"client_messages_download/{username}")
        if not user_dir.exists():
            return render_template("retrieve_messages.html", messages=[])
            
        message_files = list(user_dir.glob("*.json"))
        
        for msg_file in message_files:
            try:
                with open(msg_file, "r", encoding="utf-8") as f:
                    msg = json.load(f)
                    
                # Extract message details
                message_id = msg.get("message_id", "unknown")
                sender = msg.get("from", "unknown")
                timestamp = msg.get("timestamp", "")
                message_type = msg.get("type", "text")
                
                # Get payload and check for VDF challenge
                payload = msg.get("payload", {})
                content = None
                
                if "vdf_challenge" in payload and not is_locked:  # On résout le VDF seulement si pas verrouillé par date
                    vdf_data = payload["vdf_challenge"]
                    N = vdf_data.get("N")
                    T = vdf_data.get("T")
                    C = vdf_data.get("C")
                    
                    if all([N, T, C]):
                        try:
                            print(f"Résolution du VDF pour le message {msg.get('message_id')}...")
                            # Résoudre le puzzle VDF
                            from vdf_crypto import solve_time_lock_puzzle, decrypt_with_challenge_key
                            
                            # Calculer une estimation du temps
                            estimated_seconds = min(T * 0.00001, 300)  # Estimation grossière
                            if estimated_seconds < 60:
                                time_estimate = f"{estimated_seconds:.1f} secondes"
                            else:
                                time_estimate = f"{estimated_seconds/60:.1f} minutes"
                                
                            vdf_info = {
                                "iterations": T,
                                "has_challenge": True,
                                "N": N,
                                "T": T,
                                "C": C,
                                "is_solved": False,
                                "status": f"Résolution en cours... (temps estimé: {time_estimate})"
                            }
                            
                            # Résoudre le VDF
                            challenge_key = solve_time_lock_puzzle(N, T, C)
                            
                            # Déchiffrer la clé symétrique avec la clé challenge
                            encrypted_k_msg = base64.b64decode(payload["encrypted_k_msg"])
                            decrypted_k_msg = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)
                            
                            # Mettre à jour le message
                            msg_copy = msg.copy()
                            msg_copy["payload"]["encrypted_k_msg"] = base64.b64encode(decrypted_k_msg).decode()
                            
                            # Supprimer le challenge VDF puisqu'il est résolu
                            del msg_copy["payload"]["vdf_challenge"]
                            
                            # Déchiffrer le message avec la clé déchiffrée
                            content = decrypt_message(msg_copy, priv_enc)
                            
                            # Sauvegarder le message résolu
                            message_id = msg.get("message_id", "unknown")
                            timestamp_str = timestamp.replace(" ", "_").replace(":", "-") if timestamp else ""
                            filename = f"{message_id}_{sender}_{timestamp_str}_solved.json"
                            
                            with open(user_dir / filename, "w", encoding="utf-8") as f:
                                json.dump(msg_copy, f, indent=4)
                                
                            vdf_info["is_solved"] = True
                            vdf_info["status"] = "VDF résolu avec succès"
                            
                        except Exception as e:
                            print(f"Erreur lors de la résolution du VDF: {e}")
                            vdf_info["status"] = f"Erreur: {str(e)}"
                            content = None
                    else:
                        vdf_info = {
                            "has_challenge": True,
                            "status": "Paramètres VDF incomplets"
                        }
                else:
                    vdf_info = {"has_challenge": False}
                
                # Check if this is a large file
                file_metadata = payload.get("file_metadata", {})
                local_file_path = file_metadata.get("local_file_path")
                
                if local_file_path:
                    # This is a large file, use the local path
                    content = {
                        "type": "large_file",
                        "path": local_file_path,
                        "metadata": file_metadata
                    }
                elif content is None:
                    # Try to decrypt the message
                    try:
                        content = decrypt_message(msg, priv_enc)
                    except Exception as e:
                        print(f"Erreur lors du déchiffrement: {e}")
                        content = f"Erreur de déchiffrement: {str(e)}"
                
                messages.append({
                    "id": message_id,
                    "sender": sender,
                    "timestamp": timestamp,
                    "type": message_type,
                    "content": content,
                    "vdf_info": vdf_info
                })
                
            except Exception as e:
                print(f"Erreur lors du traitement du message {msg_file}: {e}")
                continue
        
        # Sort messages by timestamp
        messages.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return render_template("retrieve_messages.html", messages=messages)
        
    except Exception as e:
        print(f"Erreur lors de la récupération des messages: {e}")
        return render_template("retrieve_messages.html", error=f"Erreur de récupération: {str(e)}")

@app.route("/solve_vdf_local", methods=["POST"])
@login_required
def solve_vdf_local():
    data = request.get_json()
    message_id = data.get("message_id")
    username = session['username']

    # Charger le message brut depuis les messages locaux
    try:
        messages_file = f"client_messages_download/{username}/{message_id}_*.json"
        from glob import glob
        message_files = glob(messages_file)
        if not message_files:
            return jsonify({"status": "error", "message": "Message non trouvé localement"})
        
        with open(message_files[0], "r", encoding="utf-8") as f:
            msg = json.load(f)

        vdf_challenge = msg.get("payload", {}).get("vdf_challenge", {})
        N = vdf_challenge.get("N")
        T = vdf_challenge.get("T")
        C = vdf_challenge.get("C")

        if not all([N, T, C]):
            return jsonify({"status": "error", "message": "Paramètres VDF manquants"})

        # Résoudre le puzzle VDF
        from vdf_crypto import solve_time_lock_puzzle, decrypt_with_challenge_key
        challenge_key = solve_time_lock_puzzle(N, T, C)

        # Déchiffrer la clé symétrique
        encrypted_k_msg_b64 = msg.get("payload", {}).get("encrypted_k_msg")
        if not encrypted_k_msg_b64:
            return jsonify({"status": "error", "message": "Clé chiffrée manquante"})

        encrypted_k_msg = base64.b64decode(encrypted_k_msg_b64)
        decrypted_k_msg = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)

        # Mettre à jour le message sans VDF challenge
        msg["payload"]["encrypted_k_msg"] = base64.b64encode(decrypted_k_msg).decode()
        msg["payload"].pop("vdf_challenge", None)

        # Charger la clé privée pour déchiffrer le message final
        with open(f"client_keys/{username}/enc_key.pem", "rb") as f:
            priv_enc = serialization.load_pem_private_key(f.read(), password=None)

        # Récupérer la clé publique du sender pour vérifier la signature si possible
        sender = msg.get("from", "unknown")
        sender_pubkey = None
        try:
            pubkey_request = json.dumps({
                "action": "get_user_pub_key",
                "username": sender
            })
            
            pubkey_response = send_payload(pubkey_request)
            pubkey_data = json.loads(pubkey_response)
            
            if pubkey_data.get("status") == "success" and "PubKey_sign" in pubkey_data:
                sender_pubkey = base64.b64decode(pubkey_data["PubKey_sign"])
        except Exception as e:
            print(f"Erreur lors de la récupération de la clé publique de {sender}: {e}")

        # Déchiffrer avec le nouveau format qui retourne un dictionnaire
        result = decrypt_message(msg, priv_enc, sender_pubkey)
        decrypted_content = result["content"]
        signature_verified = result["signature_verified"]
        
        # Pour les fichiers, stocker dans la session pour téléchargement
        file_result = {"status": "success", "signature_verified": signature_verified}
        
        if isinstance(decrypted_content, bytes) or msg.get("type") != "text":
            # C'est un fichier, préparer pour téléchargement
            file_id = f"file_{message_id}"
            actual_id = message_id
            
            # Stocker le contenu sur le disque au lieu de la session
            if isinstance(decrypted_content, bytes):
                # Détecter le type de fichier
                content_type = "application/octet-stream"  # Type MIME par défaut
                
                # Vérifier les signatures de fichiers courants
                if decrypted_content.startswith(b'\xFF\xD8\xFF'):  # JPEG
                    content_type = "image/jpeg"
                elif decrypted_content.startswith(b'\x89PNG\r\n\x1A\n') or decrypted_content[0:8] == b'\x89PNG\r\n\x1A\n':  # PNG
                    content_type = "image/png"
                elif decrypted_content.startswith(b'GIF87a') or decrypted_content.startswith(b'GIF89a'):  # GIF
                    content_type = "image/gif"
                elif decrypted_content.startswith(b'%PDF'):  # PDF
                    content_type = "application/pdf"
                elif len(decrypted_content) > 50:
                    # Pour les debug, afficher les premiers octets
                    print(f"Premiers octets du fichier: {decrypted_content[:50]}")
                
                # Récupérer les métadonnées du fichier
                file_metadata = msg.get("payload", {}).get("file_metadata", {})
                
                # Également détecter à partir de l'extension du nom de fichier
                if file_metadata and 'filename' in file_metadata:
                    filename = file_metadata['filename'].lower()
                    if filename.endswith('.jpg') or filename.endswith('.jpeg'):
                        content_type = "image/jpeg"
                    elif filename.endswith('.png'):
                        content_type = "image/png"
                    elif filename.endswith('.gif'):
                        content_type = "image/gif"
                    elif filename.endswith('.pdf'):
                        content_type = "application/pdf"
                
                # Stocker les métadonnées du fichier
                metadata = {
                    'mime_type': content_type,
                    'message_id': actual_id
                }
                
                # Ajouter les métadonnées du fichier si disponibles
                if file_metadata:
                    metadata.update(file_metadata)
                
                # Stocker le fichier sur le disque
                file_hash = store_file_content(decrypted_content, actual_id, metadata)
                
                # Stocker la référence dans la session
                if 'file_refs' not in session:
                    session['file_refs'] = {}
                session['file_refs'][actual_id] = file_hash
                
                # Préparer le résultat
                file_display_name = file_metadata.get('filename', f"file_{message_id}")
                
                # Extension basée sur le type MIME
                extension = ""
                if content_type == "image/jpeg":
                    extension = ".jpg"
                elif content_type == "image/png":
                    extension = ".png"
                elif content_type == "image/gif":
                    extension = ".gif"
                elif content_type == "application/pdf":
                    extension = ".pdf"
                    
                # Ajouter l'extension au nom si pas déjà présente
                if extension and not file_display_name.lower().endswith(extension.lower()):
                    file_display_name += extension
                    
                file_result["is_file"] = True
                file_result["file_id"] = file_id
                file_result["file_name"] = file_display_name
                file_result["decrypted_content"] = f"[Fichier: {file_display_name}]"
            else:
                file_result["decrypted_content"] = decrypted_content
        else:
            file_result["decrypted_content"] = decrypted_content

        # Déterminer le répertoire de téléchargement
        download_dir = Path(f"client_messages_download/{username}")
        download_dir.mkdir(parents=True, exist_ok=True)

        # Sauvegarder la version déchiffrée du message pour utilisation ultérieure
        solved_path = download_dir / f"{message_id}_solved.json"
        with open(solved_path, "w", encoding="utf-8") as f:
            json.dump(msg, f, indent=4)

        return jsonify(file_result)

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/vdf_progress/<message_id>")
@login_required
def vdf_progress_stream(message_id):
    def generate():
        while True:
            # Vérifier la progression
            progress = vdf_progress.get(message_id, 0)
            
            # Si terminé, envoyer le résultat final
            if progress >= 1:
                result = vdf_results.get(message_id, {})
                if result.get("status") == "success":
                    data = {
                        "progress": 1,
                        "decrypted_content": result["content"]
                    }
                else:
                    data = {
                        "progress": 1,
                        "error": result.get("error", "Erreur inconnue")
                    }
                yield f"data: {json.dumps(data)}\n\n"
                break
            
            # Sinon, envoyer la progression
            yield f"data: {json.dumps({'progress': progress})}\n\n"
            time.sleep(0.5)  # Attendre 500ms avant la prochaine mise à jour
    
    return Response(generate(), mimetype="text/event-stream")

@app.route("/stream_large_file/<file_id>")
@login_required
def stream_large_file(file_id):
    """
    Stream a large file from disk
    """
    # Check if we have a reference for this file ID
    if file_id.startswith('file_'):
        actual_id = file_id[5:]  # Remove 'file_' prefix
    else:
        actual_id = file_id
    
    # Get the file hash either from the large_files record or the file_refs
    file_hash = None
    
    # First check the large_files record (old method)
    if 'large_files' in session and actual_id in session['large_files']:
        large_file_info = session['large_files'][actual_id]
        stream_id = large_file_info.get('stream_id')
        if stream_id:
            # This is a stream ID referring to a file on disk
            file_path = large_file_info.get('path')
            if file_path and os.path.exists(file_path):
                # Use direct streaming from the path
                mime_type = large_file_info.get('mime_type', 'application/octet-stream')
                filename = large_file_info.get('filename', f"large_file_{actual_id}")
                
                # Define a generator function to stream the file in chunks
                def generate():
                    chunk_size = 4096  # 4KB chunks
                    with open(file_path, 'rb') as f:
                        while True:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            yield chunk
                
                # Create a response that streams the file
                response = Response(
                    stream_with_context(generate()),
                    mimetype=mime_type,
                    headers={
                        'Content-Disposition': f'attachment; filename="{filename}"',
                        'Content-Length': str(os.path.getsize(file_path))
                    }
                )
                
                return response
    
    # If file wasn't found using the old method, check file_refs (new method)
    if 'file_refs' in session and actual_id in session['file_refs']:
        file_hash = session['file_refs'][actual_id]
    else:
        # Try using the ID directly as a hash (for backward compatibility)
        file_hash = hashlib.sha256(actual_id.encode()).hexdigest()
    
    # Get file content and metadata
    file_content = get_file_content(file_hash)
    if not file_content:
        flash("Large file not found or expired", "error")
        return redirect(url_for('retrieve_messages'))
    
    metadata = get_file_metadata(file_hash)
    
    # Determine content type
    content_type = metadata.get('mime_type', 'application/octet-stream')
    
    # Determine filename
    if metadata.get('filename'):
        filename = metadata['filename']
    else:
        # Generate a filename with appropriate extension
        filename = f"large_file_{actual_id}"
        if metadata.get('extension'):
            if not filename.endswith(metadata['extension']):
                filename += metadata['extension']
    
    # For files under a certain size threshold, just send directly
    file_size = len(file_content)
    if file_size < 10 * 1024 * 1024:  # 10MB
        return send_file(
            BytesIO(file_content),
            mimetype=content_type,
            as_attachment=True,
            download_name=filename
        )
    
    # For truly large files, write to a temporary file and stream
    try:
        # Create temporary file
        temp_dir = Path("temp_files")
        temp_dir.mkdir(exist_ok=True)
        temp_path = temp_dir / f"temp_{file_hash}"
        
        # Write content to temp file
        with open(temp_path, 'wb') as f:
            f.write(file_content)
        
        # Define a generator function to stream the file in chunks
        def generate():
            chunk_size = 4096  # 4KB chunks
            with open(temp_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
            
            # Delete the temp file after streaming
            try:
                os.remove(temp_path)
            except:
                pass
        
        # Create a response that streams the file
        response = Response(
            stream_with_context(generate()),
            mimetype=content_type,
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(file_size)
            }
        )
        
        return response
        
    except Exception as e:
        flash(f"Error streaming file: {str(e)}", "error")
        return redirect(url_for('retrieve_messages'))

@app.route("/download_large_file/<file_id>")
@login_required
def download_large_file(file_id):
    """Route to handle large file downloads by redirecting to the streaming route"""
    if 'large_files' not in session or file_id not in session['large_files']:
        flash("Large file reference not found", "error")
        return redirect(url_for('retrieve_messages'))
    
    file_info = session['large_files'][file_id]
    stream_id = file_info.get('stream_id')
    
    if not stream_id:
        flash("Stream ID not found for this file", "error")
        return redirect(url_for('retrieve_messages'))
    
    # Redirect to the streaming route
    return redirect(url_for('stream_large_file', file_id=stream_id))

# Add this function to manage file storage
def store_file_content(content, file_id=None, metadata=None):
    """Store file content on disk rather than in session"""
    file_storage_dir = Path("file_storage")
    file_storage_dir.mkdir(exist_ok=True)
    
    # Generate a file ID if none provided
    if not file_id:
        file_id = str(uuid.uuid4())
    
    # Hash the file ID to create a safe filename
    file_hash = hashlib.sha256(file_id.encode()).hexdigest()
    file_path = file_storage_dir / file_hash
    
    # Write the content to disk
    with open(file_path, 'wb') as f:
        if isinstance(content, str):
            f.write(content.encode('utf-8'))
        else:
            f.write(content)
    
    # Store metadata in a separate JSON file if provided
    if metadata:
        metadata_path = file_storage_dir / f"{file_hash}.meta"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
    
    return file_hash

def get_file_content(file_hash):
    """Retrieve file content from disk"""
    file_storage_dir = Path("file_storage")
    file_path = file_storage_dir / file_hash
    
    if not file_path.exists():
        return None
    
    with open(file_path, 'rb') as f:
        return f.read()

def get_file_metadata(file_hash):
    """Retrieve file metadata from disk"""
    file_storage_dir = Path("file_storage")
    metadata_path = file_storage_dir / f"{file_hash}.meta"
    
    if not metadata_path.exists():
        return {}
    
    with open(metadata_path, 'r') as f:
        return json.load(f)

def delete_stored_file(file_hash):
    """Delete a stored file and its metadata"""
    file_storage_dir = Path("file_storage")
    file_path = file_storage_dir / file_hash
    metadata_path = file_storage_dir / f"{file_hash}.meta"
    
    if file_path.exists():
        os.remove(file_path)
    
    if metadata_path.exists():
        os.remove(metadata_path)

# Add this function to handle file cleanup
def cleanup_temp_files(max_age_days=1):
    """Remove temporary files older than max_age_days"""
    temp_dirs = ["temp_files", "file_storage"]
    current_time = time.time()
    max_age_seconds = max_age_days * 24 * 60 * 60
    
    for temp_dir in temp_dirs:
        if not os.path.exists(temp_dir):
            continue
            
        for filename in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, filename)
            # Skip directories
            if os.path.isdir(file_path):
                continue
                
            # Check file age
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > max_age_seconds:
                try:
                    os.remove(file_path)
                    print(f"Removed old temporary file: {file_path}")
                except Exception as e:
                    print(f"Failed to remove {file_path}: {e}")

# Run cleanup on application startup - modern approach for Flask 2.x+
with app.app_context():
    # Ensure directories exist
    os.makedirs("temp_files", exist_ok=True)
    os.makedirs("file_storage", exist_ok=True)
    
    # Clean up old files
    cleanup_temp_files()

# Schedule periodic cleanup
@app.before_request
def before_request():
    # Run cleanup once per day (approximately)
    # We use a simple file-based timestamp check
    last_cleanup_file = "last_cleanup.txt"
    current_time = time.time()
    run_cleanup = False
    
    if not os.path.exists(last_cleanup_file):
        run_cleanup = True
    else:
        try:
            with open(last_cleanup_file, 'r') as f:
                last_cleanup_time = float(f.read().strip())
                # Run cleanup if more than 24 hours have passed
                if current_time - last_cleanup_time > 24 * 60 * 60:
                    run_cleanup = True
        except:
            run_cleanup = True
    
    if run_cleanup:
        # Run cleanup
        cleanup_temp_files()
        # Update timestamp
        with open(last_cleanup_file, 'w') as f:
            f.write(str(current_time))

def store_encrypted_file(file_path, message_id, file_metadata):
    """
    Store an encrypted file locally in the messages_files directory.
    
    Args:
        file_path (str): Path to the file to encrypt and store
        message_id (str): Unique identifier for the message
        file_metadata (dict): Metadata about the file
        
    Returns:
        str: Path to the stored encrypted file
    """
    # Create messages_files directory if it doesn't exist
    messages_files_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'messages_files')
    os.makedirs(messages_files_dir, exist_ok=True)
    
    # Generate path for the encrypted file
    encrypted_file_path = os.path.join(messages_files_dir, f"{message_id}.enc")
    
    # Read the file content
    with open(file_path, 'rb') as f:
        file_content = f.read()
    
    # Generate a symmetric key for this file
    k_msg = generate_symmetric_key()
    
    # Encrypt the file content using ChaCha20-Poly1305
    ciphertext, nonce = encrypt_message_symmetric(file_content, k_msg)
    
    # Store the encrypted content with nonce
    with open(encrypted_file_path, 'wb') as f:
        f.write(nonce + ciphertext)  # Store nonce + ciphertext
    
    # Store the key in the metadata for later decryption
    file_metadata['encryption_key'] = base64.b64encode(k_msg).decode()
    
    return encrypted_file_path

if __name__ == "__main__":
    app.run(debug=True, port=5050)