from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
from client import create_user, reset_password, get_keys_from_password, send_message_payload
import socket
import ssl
from datetime import timedelta, datetime
from functools import wraps

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
                ssock.sendall(payload.encode())
                return ssock.recv(4096).decode()
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

        payload = json.dumps({"action": "get_user_all_data", "username": username})
        rep = send_payload(payload)

        # Vérifier si l'utilisateur existe
        try:
            rep_json = json.loads(rep)
            if "status" in rep_json and rep_json["status"] == "error":
                return render_template("login.html", error="Invalid username or password")
        except json.JSONDecodeError:
            return render_template("login.html", error="Invalid username or password")

        try:
            response = get_keys_from_password(username, password, rep)
            if response:  # Si les clés ont été récupérées avec succès
                session['username'] = username
                return redirect(url_for('index'))
            else:
                return render_template("login.html", error="Invalid username or password")
        except Exception as e:
            return render_template("login.html", error="Invalid username or password")

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
            content = message
        else:  # file
            file = request.files.get("file")
            if not file:
                return render_template("send_message.html", error="Please select a file")
            content = file.read().decode('utf-8', errors='ignore')
        
        payload = json.dumps({"action": "get_user_all_data", "username": recipient})
        rep = send_payload(payload)

        try:
            rep_json = json.loads(rep)
            if "status" in rep_json and rep_json["status"] == "error":
                return render_template("send_message.html", error=f"Error getting recipient data: {rep_json.get('message', 'Unknown error')}")
            
            if "PubKey_enc" not in rep_json:
                return render_template("send_message.html", error="Recipient's public key not found. User might not exist.")
                
            Pubkey_enc_recipient = rep_json["PubKey_enc"]
        except json.JSONDecodeError:
            return render_template("send_message.html", error="Invalid response from server")
            
        sender = session['username']

        print("yo")
        payload2 = send_message_payload(sender, recipient, content, message_type, unlock_date, Pubkey_enc_recipient)
        print(payload2)

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
    # TODO: Implémenter la récupération des messages
    return render_template("retrieve_messages.html")

if __name__ == "__main__":
    app.run(debug=True, port=5050)