from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
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

        payload = json.dumps({"action": "get_user_all_data", "username": username})
        rep = send_payload(payload)
        
        print(f"Server response: {rep}")

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

        payload = json.dumps({"action": "get_user_all_data", "username": username})
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
        # Charger les messages du fichier
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
                    from datetime import datetime
                    # Format du unlock_date: "14:05:2023:13:02:00" (jour:mois:année:heure:minute:seconde)
                    day, month, year, hour, minute, second = unlock_date_str.split(":")
                    unlock_datetime = datetime(int(year), int(month), int(day), 
                                              int(hour), int(minute), int(second))
                    now = datetime.now()
                    is_locked = now < unlock_datetime
                    unlock_date_display = unlock_datetime.strftime("%d/%m/%Y %H:%M:%S")
                    
                    # Calcul du temps restant
                    if is_locked:
                        from datetime import timedelta
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
                    "has_challenge": True
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
                        # Note: pour les gros fichiers, il serait préférable de les stocker temporairement sur disque
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
            else:
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

if __name__ == "__main__":
    app.run(debug=True, port=5050)