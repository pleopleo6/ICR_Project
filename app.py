from flask import Flask, render_template, request, redirect, url_for
import json
from client import create_user, reset_password, get_keys_from_password
import socket
import ssl

app = Flask(__name__)

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
    return render_template("index.html")

@app.route("/create_user", methods=["GET", "POST"])
def create_user_page():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        payload = create_user(username, password)
        response = send_payload(payload)
        return render_template("response.html", response=response)
    return render_template("create_user.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password_page():
    if request.method == "POST":
        new_password = request.form.get("new_password")

        payload = reset_password(new_password)

        response = send_payload(payload)
        return render_template("response.html", response=response)

    return render_template("reset_password.html")

@app.route("/retrieve_keys", methods=["GET", "POST"])
def retrieve_keys_page():
    if request.method == "POST":
        username =  request.form.get("username")
        password = request.form.get("password")

        payload = json.dumps({"action": "get_user_all_data", "username": username})
        rep = send_payload(payload)

        response = get_keys_from_password(username, password, rep)
        
        return render_template("response.html", response=response)

    return render_template("retrieve_keys.html")

if __name__ == "__main__":
    app.run(debug=True, port=5050)