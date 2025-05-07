from flask import Flask, render_template, request, redirect, url_for, session
import json
from client import create_user, reset_password, get_keys_from_password
import socket
import ssl

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete'  # Nécessaire pour les sessions

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
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("dashboard.html", username=session['username'])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        payload = json.dumps({"action": "get_user_all_data", "username": username})
        rep = send_payload(payload)

        try:
            response = get_keys_from_password(username, password, rep)
            if response:  # Si les clés ont été récupérées avec succès
                session['username'] = username
                return redirect(url_for('index'))
            else:
                return render_template("login.html", error="Invalid username or password")
        except Exception as e:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
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
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == "POST":
        recipient = request.form.get("recipient")
        message = request.form.get("message")
        # TODO: Implémenter l'envoi de message
        return render_template("send_message.html", success="Message sent successfully")
    
    return render_template("send_message.html")

@app.route("/retrieve_messages", methods=["GET"])
def retrieve_messages():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # TODO: Implémenter la récupération des messages
    return render_template("retrieve_messages.html")

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

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password_page():
    if request.method == "POST":
        username = request.form.get("username")
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")

        payload = json.dumps({"action": "get_user_all_data", "username": username})
        rep = send_payload(payload)
        response = "Cannot retreive your private keys, your old password is not accurate"

        is_key_retreived = True
        try:
            is_key_retreived = get_keys_from_password(username, old_password, rep)
        except FileNotFoundError:
            return render_template("response.html", response="Unable to reconstruct your private keys. Incorrect password. Password update failed.")

        if is_key_retreived:
            payload = reset_password(new_password, username)
            response = send_payload(payload)
        
        return render_template("response.html", response=response)

    return render_template("reset_password.html")

@app.route("/retrieve_keys", methods=["GET", "POST"])
def retrieve_keys_page():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        payload = json.dumps({"action": "get_user_all_data", "username": username})
        rep = send_payload(payload)

        try:
            response = get_keys_from_password(username, password, rep)
            if response:  # Si les clés ont été récupérées avec succès
                return redirect(url_for('index'))
            else:
                return render_template("response.html", response="Invalid username or password")
        except Exception as e:
            return render_template("response.html", response="Invalid username or password")

    return render_template("retrieve_keys.html")

if __name__ == "__main__":
    app.run(debug=True, port=5050)