import socket
import ssl
import json
from database import (
    create_user,
    get_user_all_data,
    verify_signature
)

def handle_client_request(data):
    try:
        request = json.loads(data.decode())
        action = request.get("action")

        if action == "create_user":
            result = create_user(
                username=request["username"],
                salt_argon2=request["salt_argon2"],
                salt_hkdf=request["salt_hkdf"],
                pubkey_sign=request["PubKey_sign"],
                pubkey_enc=request["PubKey_enc"],
                encrypted_sign_key=request["Encrypted_sign_key"],
                encrypted_enc_key=request["Encrypted_enc_key"]
            )
        elif action == "reset_password":
            # TODO: Implement password reset logic
            result = {"status": "error", "message": request}
        elif action == "retrieve_keys":
            result = {"status": "error", "message": "Key retrieval not implemented yet."}
        elif action == "send_message":
            # TODO: Implement secure messaging
            result = {"status": "success", "echo": request.get("message", "")}
        elif action == "get_user_all_data":
            username = request.get("username")
            if not username:
                result = {"status": "error", "message": "Missing 'username' in request."}
            else:
                result = get_user_all_data(username)
        else:
            result = {"status": "error", "message": "Invalid action."}
    except json.JSONDecodeError:
        result = {"status": "error", "message": "Invalid JSON format."}
    except KeyError as e:
        result = {"status": "error", "message": f"Missing field: {e}"}
    except Exception as e:
        result = {"status": "error", "message": f"Server error: {str(e)}"}

    return json.dumps(result).encode()


def run_server():
    host = 'localhost'
    port = 8443
    server_cert = 'server.crt'
    server_key = 'server.key'

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"Server listening on {host}:{port}")

        with context.wrap_socket(sock, server_side=True) as ssock:
            print("Waiting for client connections...")

            while True:
                try:
                    conn, addr = ssock.accept()
                    print(f"\nConnected to client: {addr}")

                    with conn:
                        while True:
                            data = conn.recv(4096)
                            if not data:
                                break
                            print(f"Received raw data: {data}")
                            response = handle_client_request(data)
                            conn.sendall(response)

                    print("Connection closed")

                except ssl.SSLError as e:
                    print(f"SSL Error: {e}")
                except Exception as e:
                    print(f"Server error: {e}")

if __name__ == "__main__":
    run_server()