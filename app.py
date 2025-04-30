from flask import Flask, render_template, request, redirect, url_for
import json
from client import create_user, reset_password, retrieve_keys

app = Flask(__name__)

def send_payload(payload):
    import socket
    import ssl

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

if __name__ == "__main__":
    app.run(debug=True, port=5050)