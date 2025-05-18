from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, Response
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
from crypto_utils import derive_encryption_key, hash_password_argon2id, derive_salt_from_username
from vdf_crypto import generate_challenge_key, encrypt_with_challenge_key, generate_time_lock_puzzle, solve_time_lock_puzzle, decrypt_with_challenge_key
import threading
import queue

app = Flask(__name__)
# Note: Dans un environnement de production, il serait préférable de :
# 1. Séparer la configuration dans un fichier config.py
# 2. Utiliser des variables d'environnement pour les secrets
# 3. Implémenter une gestion de session plus robuste avec Redis ou une base de données
# 4. Ajouter des middlewares de sécurité supplémentaires
# Ceci est un POC avec une sécurité basique (niveau web design)
app.secret_key = 'votre_cle_secrete'  # À remplacer par une vraie clé secrète en production

# Configuration de base pour la session
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Empêche l'accès aux cookies via JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protection contre les attaques CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Session expire après 15 minutes

# En production, activer ces options :
# app.config['SESSION_COOKIE_SECURE'] = True  # Force l'utilisation de HTTPS pour les cookies

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

def send_payload(payload):
    host = 'localhost'
    port = 8443
    server_cert = 'server.crt'

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=server_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Envoyer les données en chunks si nécessaire pour les fichiers volumineux
                payload_bytes = payload.encode()
                payload_len = len(payload_bytes)
                
                # Afficher la taille des données envoyées
                print(f"Sending payload of size: {payload_len} bytes")
                
                # Si petit, envoyer en une seule fois
                if payload_len < 8192:
                    ssock.sendall(payload_bytes)
                else:
                    # Pour les grands payloads, envoyer par morceaux
                    chunk_size = 8192
                    for i in range(0, payload_len, chunk_size):
                        chunk = payload_bytes[i:i+chunk_size]
                        ssock.send(chunk)
                        # Petite pause pour éviter la surcharge
                        time.sleep(0.001)
                
                # Recevoir la réponse par morceaux
                buffer = b""
                while True:
                    chunk = ssock.recv(8192)
                    if not chunk:
                        break
                    buffer += chunk
                    
                    # Essayer de voir si nous avons un JSON complet
                    try:
                        json.loads(buffer.decode())
                        # Si nous sommes ici, le JSON est complet
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # Continuer à lire s'il y a plus de données
                        continue
                
                return buffer.decode()
    except Exception as e:
        return f"Error: {e}"

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
            if response is True:  # Si les clés ont été récupérées avec succès
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
        else:  # file
            file = request.files.get("file")
            if not file:
                return render_template("send_message.html", error="Please select a file")
            
            # Lire le contenu binaire du fichier directement
            content = file.read()  # Contenu binaire, pas besoin de décoder
            if not content:
                return render_template("send_message.html", error="File is empty")
        
        payload = json.dumps({"action": "get_user_all_data", "username": recipient})
        rep = send_payload(payload)
        
        print(f"Server response for recipient: {rep}")

        try:
            rep_json = json.loads(rep)
            if "status" in rep_json and rep_json["status"] == "error":
                return render_template("send_message.html", error=f"Error getting recipient data: {rep_json.get('message', 'Unknown error')}")
            
            # The structure of the server response should match what we expect
            if "PubKey_enc" not in rep_json:
                print(f"Missing PubKey_enc in server response: {rep_json}")
                return render_template("send_message.html", error="Recipient's public key not found. User might not exist.")
                
            Pubkey_enc_recipient = rep_json["PubKey_enc"]
        except json.JSONDecodeError:
            return render_template("send_message.html", error="Invalid response from server")
            
        sender = session['username']

        payload2 = send_message_payload(sender, recipient, content, message_type, unlock_date, Pubkey_enc_recipient)
        print(f"Message payload size: {len(payload2)} bytes")

        response = send_payload(payload2)
        print(response)
        try:
            response_json = json.loads(response)
            if response_json.get("status") == "success":
                return render_template("send_message.html", success="Message sent successfully")
            else:
                return render_template("send_message.html", error=response_json.get("message", "Failed to send message"))
        except json.JSONDecodeError:
            return render_template("send_message.html", error="Failed to send message")
    
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
                    content = decrypt_message(msg, priv_enc)
                    
                    # Déterminer si c'est un fichier binaire et comment l'afficher
                    message_type = msg.get("type", "text")
                    is_binary = msg.get("payload", {}).get("is_binary", False)
                    
                    if is_binary or message_type != "text":
                        # Pour les fichiers binaires, indiquer qu'il s'agit d'un fichier à télécharger
                        # On stockera le contenu binaire dans une session pour téléchargement ultérieur
                        content_display = f"[Fichier {message_type}]"
                        
                        # Générer un ID unique pour ce fichier
                        file_id = f"file_{msg.get('message_id', str(uuid.uuid4()))}"
                        
                        # Stocker le contenu binaire dans la session pour téléchargement ultérieur
                        if 'files' not in session:
                            session['files'] = {}
                        
                        # Pour la session, on doit encoder en base64
                        if isinstance(content, bytes):
                            session['files'][file_id] = base64.b64encode(content).decode('utf-8')
                            content_type = "application/octet-stream"  # Type MIME par défaut
                            
                            # Essayer de détecter le type de fichier
                            if content.startswith(b'\xFF\xD8\xFF'):  # Signature JPEG
                                content_type = "image/jpeg"
                            elif content.startswith(b'\x89PNG\r\n\x1A\n'):  # Signature PNG
                                content_type = "image/png"
                            elif content.startswith(b'GIF87a') or content.startswith(b'GIF89a'):  # Signature GIF
                                content_type = "image/gif"
                            elif content.startswith(b'%PDF'):  # Signature PDF
                                content_type = "application/pdf"
                                
                            session['files_types'] = session.get('files_types', {})
                            session['files_types'][file_id] = content_type
                            
                            content = content_display
                    
                except Exception as e:
                    content = f"Erreur de déchiffrement: {e}"
                    if "vdf_challenge" in payload:
                        content += "\n\nCe message nécessite la résolution du puzzle VDF pour être déchiffré."
            else:
                # Message verrouillé par date
                content = f"Message verrouillé jusqu'au {unlock_date_display}"
                if time_remaining:
                    content += f"\nTemps restant: {time_remaining}"
                    
                # Indiquer si le message a également un puzzle VDF
                if "vdf_challenge" in payload:
                    content += "\n\nCe message contient également un puzzle VDF à résoudre."
            
            decoded_messages.append({
                "id": msg.get("message_id", "ID inconnu"),
                "sender": sender,
                "timestamp": timestamp,
                "content": content,
                "is_locked": is_locked,
                "unlock_date": unlock_date_display,
                "time_remaining": time_remaining,
                "vdf_info": vdf_info,
                "raw_data": json.dumps(msg)  # Stocker les données brutes du message pour la résolution locale du VDF
            })
            
        # Trier par date (plus récent en premier)
        decoded_messages.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return render_template("retrieve_messages.html", messages=decoded_messages)
        
    except Exception as e:
        return render_template("retrieve_messages.html", error=f"Erreur de récupération: {str(e)}")

@app.route("/download_file/<file_id>")
@login_required
def download_file(file_id):
    # Vérifier que le fichier existe dans la session
    if 'files' not in session or file_id not in session['files']:
        flash("Fichier non disponible ou expiré", "error")
        return redirect(url_for('retrieve_messages'))
    
    try:
        # Récupérer et décoder le contenu
        file_content_b64 = session['files'][file_id]
        file_content = base64.b64decode(file_content_b64)
        
        # Récupérer le type MIME
        content_type = session.get('files_types', {}).get(file_id, 'application/octet-stream')
        
        # Créer un nom de fichier si nécessaire
        filename = f"secured_file_{file_id.split('_')[-1]}"
        
        # Extension basée sur le type MIME
        if content_type == 'image/jpeg':
            filename += '.jpg'
        elif content_type == 'image/png':
            filename += '.png'
        elif content_type == 'image/gif':
            filename += '.gif'
        elif content_type == 'application/pdf':
            filename += '.pdf'
        
        # Créer une réponse avec le fichier
        return send_file(
            BytesIO(file_content),
            mimetype=content_type,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        flash(f"Erreur lors du téléchargement: {str(e)}", "error")
        return redirect(url_for('retrieve_messages'))

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
    
    try:
        # Charger les messages depuis le dossier local
        user_dir = Path(f"client_messages_download/{username}")
        if not user_dir.exists():
            return render_template("retrieve_messages.html", info="Aucun message téléchargé disponible")
        
        # Lire tous les fichiers JSON dans le dossier (messages bruts)
        message_files = list(user_dir.glob("*.json"))
        if not message_files:
            return render_template("retrieve_messages.html", info="Aucun message téléchargé disponible")
        
        # Charger les messages
        user_messages = []
        for file_path in message_files:
            if "_solved" in file_path.name or "_decrypted" in file_path.name:  # Ignorer les fichiers déjà traités
                continue
                
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    msg = json.load(f)
                    if msg.get("to") == username:  # Vérifier que c'est bien destiné à cet utilisateur
                        user_messages.append(msg)
                except json.JSONDecodeError:
                    print(f"Erreur de lecture du fichier {file_path}")
                    continue
        
        if not user_messages:
            return render_template("retrieve_messages.html", info="Aucun message disponible pour votre compte")
            
        # Charger la clé privée de déchiffrement pour déchiffrer
        user_dir = Path(f"client_keys/{username}")
        try:
            from cryptography.hazmat.primitives import serialization
            with open(user_dir / "enc_key.pem", "rb") as f:
                priv_enc = serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            return render_template("retrieve_messages.html", error=f"Erreur de chargement de clé: {e}")
        
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
                    day, month, year, hour, minute, second = unlock_date_str.split(":")
                    unlock_datetime = datetime(int(year), int(month), int(day), 
                                              int(hour), int(minute), int(second))
                    now = datetime.now()
                    is_locked = now < unlock_datetime
                    unlock_date_display = unlock_datetime.strftime("%d/%m/%Y %H:%M:%S")
                    
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
                        
                        # Mettre à jour le message avec la clé déchiffrée
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
                            
                            # Si c'est un fichier binaire
                            if isinstance(content, bytes):
                                message_type = msg.get("type", "file")
                                content = f"[Fichier {message_type}]"
                                
                                # Stocker le contenu binaire dans la session pour téléchargement ultérieur
                                file_id = f"file_{msg.get('message_id', str(uuid.uuid4()))}"
                                if 'files' not in session:
                                    session['files'] = {}
                                session['files'][file_id] = base64.b64encode(content).decode('utf-8')
                                
                            # Mettre à jour le statut VDF
                            vdf_info["is_solved"] = True
                            vdf_info["status"] = "VDF résolu avec succès !"
                            
                    except Exception as e:
                        print(f"Erreur lors de la résolution du VDF: {e}")
                        content = f"Erreur lors de la résolution du VDF: {str(e)}"
                        vdf_info = {
                            "iterations": T,
                            "has_challenge": True,
                            "N": N,
                            "T": T,
                            "C": C,
                            "is_solved": False,
                            "status": f"Erreur lors de la résolution: {str(e)}"
                        }
                else:
                    vdf_info = {
                        "iterations": T if T else "inconnu",
                        "has_challenge": True,
                        "status": "Paramètres VDF incomplets"
                    }
            
            # Si pas de VDF ou si le VDF n'a pas été résolu, essayer de déchiffrer normalement
            if content is None and not is_locked:
                try:
                    content = decrypt_message(msg, priv_enc)
                    if isinstance(content, bytes):
                        message_type = msg.get("type", "text")
                        content = f"[Fichier {message_type}]"
                        
                        file_id = f"file_{msg.get('message_id', str(uuid.uuid4()))}"
                        if 'files' not in session:
                            session['files'] = {}
                        session['files'][file_id] = base64.b64encode(content).decode('utf-8')
                except Exception as e:
                    content = f"Erreur de déchiffrement: {e}"
            elif is_locked:
                content = f"Message verrouillé jusqu'au {unlock_date_display}"
                if time_remaining:
                    content += f"\nTemps restant: {time_remaining}"
            
            decoded_messages.append({
                "id": msg.get("message_id", "ID inconnu"),
                "sender": sender,
                "timestamp": timestamp,
                "content": content,
                "is_locked": is_locked,
                "unlock_date": unlock_date_display,
                "time_remaining": time_remaining,
                "vdf_info": vdf_info
            })
            
        # Trier par date (plus récent en premier)
        decoded_messages.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return render_template("retrieve_messages.html", messages=decoded_messages, offline_mode=True)
        
    except Exception as e:
        return render_template("retrieve_messages.html", error=f"Erreur de récupération: {str(e)}")

@app.route("/create_test_vdf_message")
@login_required
def create_test_vdf_message():
    """Crée un message VDF de test pour voir l'interface de résolution"""
    username = session['username']
    
    try:
        # Assurer que le dossier existe
        user_dir = Path(f"client_messages_download/{username}")
        user_dir.mkdir(parents=True, exist_ok=True)
        
        # Générer une clé de défi pour le test
        from vdf_crypto import generate_challenge_key, encrypt_with_challenge_key, generate_time_lock_puzzle
        
        # Créer une clé fictive comme si c'était k_msg chiffré
        fake_encrypted_k_msg = b"encrypted_key_message_example_1234567890abcdefghijklmnopqrstuvwxyz"
        
        # Générer une clé de défi comme le ferait le serveur
        challenge_key = generate_challenge_key()
        print(f"DEBUG Test - Clé de défi générée: {challenge_key.hex()[:16]}...")
        
        # Créer une date de déverrouillage dans le futur (10 minutes à partir de maintenant)
        unlock_datetime = datetime.now() + timedelta(minutes=10)
        unlock_date = unlock_datetime.strftime("%d:%m:%Y:%H:%M:%S")
        
        # Calculer la difficulté du VDF basée sur le temps de déverrouillage (comme dans send_message_payload)
        time_diff = 600  # 10 minutes en secondes
        vdf_seconds = min(time_diff / 120, 300)  # ~0.8% du temps total, max 5 min
        
        # Créer un time-lock puzzle pour la clé de défi
        N, T, C = generate_time_lock_puzzle(challenge_key, vdf_seconds)
        print(f"DEBUG Test - Puzzle généré: N={N}, T={T}, C={C}, temps prévu: {vdf_seconds} secondes")
        
        # Chiffrer la clé fictive avec la clé de défi
        double_encrypted = encrypt_with_challenge_key(fake_encrypted_k_msg, challenge_key)
        print(f"DEBUG Test - Taille du fake_encrypted_k_msg doublement chiffré: {len(double_encrypted)} octets")
        
        # Stocker la clé originale pour la récupérer plus tard
        from vdf_crypto import store_original_encrypted_k_msg
        message_id = f"test_vdf_{uuid.uuid4()}"
        store_original_encrypted_k_msg(message_id, fake_encrypted_k_msg)
        
        # Créer un message de test qui ressemble exactement à un vrai message
        test_message = {
            "message_id": message_id,
            "from": "system@testvdf",
            "to": username,
            "type": "text",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "payload": {
                "ciphertext": base64.b64encode(b"Message de test VDF - Le contenu sera visible apres resolution du VDF et quand la date de deverrouillage sera atteinte").decode('utf-8'),
                "nonce": base64.b64encode(b"nonce123456789").decode('utf-8'),
                "encrypted_k_msg": base64.b64encode(double_encrypted).decode('utf-8'),
                "vdf_challenge": {
                    "N": N,
                    "T": T,
                    "C": C,
                    "unlock_delay_seconds": time_diff
                },
                "unlock_date": unlock_date
            }
        }
        
        # Sauvegarder le message de test
        timestamp = test_message["timestamp"]
        sender = test_message["from"]
        timestamp_str = timestamp.replace(" ", "_").replace(":", "-")
        filename = f"{message_id}_{sender}_{timestamp_str}.json"
        
        with open(user_dir / filename, "w", encoding="utf-8") as f:
            json.dump(test_message, f, indent=4)
            
        flash(f"Message VDF de test créé avec succès - Déverrouillable à partir de {unlock_datetime.strftime('%H:%M:%S')}. Consultez vos messages locaux pour le voir.", "success")
        return redirect(url_for('view_local_messages'))
        
    except Exception as e:
        flash(f"Erreur lors de la création du message VDF de test: {e}", "error")
        return redirect(url_for('index'))

def solve_vdf_with_progress(message_id, N, T, C, raw_data, username):
    """Résout le VDF en mettant à jour la progression"""
    try:
        # Initialiser la progression
        vdf_progress[message_id] = 0
        msg = json.loads(raw_data)
        
        # Résoudre le VDF avec mise à jour de la progression
        def progress_callback(current_iteration):
            vdf_progress[message_id] = current_iteration / T
        
        # Résoudre le puzzle VDF
        challenge_key = solve_time_lock_puzzle(N, T, C, progress_callback)
        
        # Déchiffrer la clé symétrique avec la clé challenge
        encrypted_k_msg = base64.b64decode(msg["payload"]["encrypted_k_msg"])
        decrypted_k_msg = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)
        
        # Mettre à jour le message avec la clé déchiffrée
        msg_copy = msg.copy()
        msg_copy["payload"]["encrypted_k_msg"] = base64.b64encode(decrypted_k_msg).decode()
        del msg_copy["payload"]["vdf_challenge"]
        
        # Charger la clé privée de déchiffrement
        user_dir = Path(f"client_keys/{username}")
        with open(user_dir / "enc_key.pem", "rb") as f:
            from cryptography.hazmat.primitives import serialization
            priv_enc = serialization.load_pem_private_key(f.read(), password=None)
        
        # Déchiffrer le message
        content = decrypt_message(msg_copy, priv_enc)
        
        # Sauvegarder le message résolu
        user_dir = Path(f"client_messages_download/{username}")
        user_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = msg.get("timestamp", "")
        sender = msg.get("from", "unknown")
        timestamp_str = timestamp.replace(" ", "_").replace(":", "-") if timestamp else ""
        filename = f"{message_id}_{sender}_{timestamp_str}_solved.json"
        
        with open(user_dir / filename, "w", encoding="utf-8") as f:
            json.dump(msg_copy, f, indent=4)
        
        # Stocker le résultat
        if isinstance(content, bytes):
            message_type = msg.get("type", "file")
            content_display = f"[Fichier {message_type}]"
            
            # Stocker le contenu binaire dans la session
            file_id = f"file_{message_id}"
            if 'files' not in session:
                session['files'] = {}
            session['files'][file_id] = base64.b64encode(content).decode('utf-8')
            
            vdf_results[message_id] = {
                "status": "success",
                "content": content_display
            }
        else:
            vdf_results[message_id] = {
                "status": "success",
                "content": content
            }
            
    except Exception as e:
        print(f"Erreur lors de la résolution du VDF: {e}")
        vdf_results[message_id] = {
            "status": "error",
            "error": str(e)
        }
    finally:
        # Marquer comme terminé
        vdf_progress[message_id] = 1

from flask import jsonify

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
        from cryptography.hazmat.primitives import serialization
        with open(f"client_keys/{username}/enc_key.pem", "rb") as f:
            priv_enc = serialization.load_pem_private_key(f.read(), password=None)

        from client import decrypt_message
        decrypted_content = decrypt_message(msg, priv_enc)

        return jsonify({
            "status": "success",
            "decrypted_content": decrypted_content
        })

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

if __name__ == "__main__":
    app.run(debug=True, port=5050)