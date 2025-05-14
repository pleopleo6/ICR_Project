import socket
import ssl
import json
import os
import base64
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from database import (
    create_user,
    get_user_all_data,
    verify_signature,
    reset_password,
    get_all_users, # for get the list of user of the app
    store_message
)
from vdf_crypto import (
    generate_challenge_key,
    encrypt_with_challenge_key,
    generate_time_lock_puzzle,
    store_challenge_keys
)

def hash_dict(d):
    """
    Create a deterministic hash of a dictionary.
    Uses SHA3-256 for cryptographic security.
    """
    # Convert dict to canonical JSON string
    json_str = json.dumps(d, sort_keys=True, separators=(',', ':'))
    
    # Hash the JSON string
    hasher = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    hasher.update(json_str.encode())
    return hasher.finalize()

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
            try:
                username = request["username"]
                signature_b64 = request["signature"]

                # Préparer le message original (sans signature) pour vérification
                unsigned_payload = dict(request)
                unsigned_payload.pop("signature")

                canonical_message = json.dumps(unsigned_payload, sort_keys=True)

                # Vérifier la signature avec la clé publique stockée
                is_valid, msg = verify_signature(username, canonical_message, signature_b64)
                if not is_valid:
                    result = {"status": "error", "message": f"Signature verification failed: {msg}"}
                else:
                    print("Signature verified correctly")
                    # Appliquer les changements (nouvelles données)
                    ok = reset_password(
                        username=username,
                        salt_argon2=request["salt_argon2"],
                        salt_hkdf=request["salt_hkdf"],
                        Encrypted_sign_key=request["Encrypted_sign_key"],
                        Encrypted_enc_key=request["Encrypted_enc_key"]
                    )
                    result = {"status": "success" if ok else "error", "message": "Password reset" if ok else "Failed to update user"}
            except Exception as e:
                result = {"status": "error", "message": f"Exception: {str(e)}"}
        elif action == "send_message":
            try:
                # Extraire les données du message
                message = request.get("message", {})
                sender = message.get("from")
                payload = message.get("payload", {})
                signature_b64 = message.get("signature")
                
                if not all([sender, payload, signature_b64]):
                    result = {"status": "error", "message": "Message is missing required fields"}
                    return json.dumps(result).encode()
                
                # Hacher le payload pour vérification
                payload_hash = hash_dict(payload)
                
                # Vérifier la signature directement avec le hash binaire
                is_valid, msg = verify_signature(sender, payload_hash, signature_b64)
                
                if not is_valid:
                    print(f"Signature verification failed: {msg}")
                    result = {"status": "error", "message": f"Signature verification failed: {msg}"}
                else:
                    print("Signature verified correctly")
                    
                    # Générer un ID de message s'il n'existe pas
                    message_id = message.get("message_id", str(uuid.uuid4()))
                    message["message_id"] = message_id
                    
                    # 1. Générer une clé de défi
                    challenge_key = generate_challenge_key()
                    
                    # 2. Déterminer le temps de puzzle en fonction de la date d'unlock
                    unlock_time = 10  # valeur par défaut en secondes
                    
                    # Récupérer la date d'unlock du message si présente
                    if "unlock_date" in payload:
                        unlock_date_str = payload["unlock_date"]
                        try:
                            from datetime import datetime
                            
                            # Format du unlock_date: "14:05:2023:13:02:00" (jour:mois:année:heure:minute:seconde)
                            day, month, year, hour, minute, second = unlock_date_str.split(":")
                            unlock_datetime = datetime(int(year), int(month), int(day), 
                                                    int(hour), int(minute), int(second))
                            
                            # Calculer la différence entre maintenant et la date d'unlock
                            now = datetime.now()
                            
                            # Si la date est dans le futur, ajuster le temps du puzzle
                            if unlock_datetime > now:
                                # Calculer la différence en secondes
                                time_diff = (unlock_datetime - now).total_seconds()
                                
                                # Utiliser directement cette différence comme temps de puzzle
                                # Le temps nécessaire pour résoudre le puzzle devrait idéalement être 
                                # égal au temps d'attente jusqu'à la date de déverrouillage
                                
                                # Limiter le temps maximum pour éviter les puzzles trop complexes
                                MAX_PUZZLE_TIME = 300  # 5 minutes maximum
                                
                                if time_diff <= MAX_PUZZLE_TIME:
                                    # Pour les courtes périodes, utiliser directement la différence
                                    unlock_time = time_diff
                                else:
                                    # Pour les périodes plus longues, limiter et mettre à l'échelle
                                    unlock_time = MAX_PUZZLE_TIME
                                    
                                print(f"Date de déverrouillage: {unlock_datetime}, temps actuel: {now}")
                                print(f"Différence temporelle: {time_diff:.2f} secondes, temps de puzzle fixé à: {unlock_time:.2f}s")
                        except Exception as e:
                            print(f"Erreur lors du parsing de la date d'unlock: {e}")
                    
                    # 3. Créer un time-lock puzzle pour la clé
                    N, T, C = generate_time_lock_puzzle(challenge_key, unlock_time)
                    
                    # 4. Stocker la clé de défi pour un accès rapide
                    store_challenge_keys(message_id, challenge_key)
                    
                    # 4. Chiffrer le encrypted_k_msg avec la clé de défi
                    if "encrypted_k_msg" in payload:
                        encrypted_k_msg_bytes = base64.b64decode(payload["encrypted_k_msg"])
                        double_encrypted = encrypt_with_challenge_key(encrypted_k_msg_bytes, challenge_key)
                        payload["encrypted_k_msg"] = base64.b64encode(double_encrypted).decode()
                        
                        # Ajouter les paramètres du puzzle au message
                        payload["vdf_challenge"] = {
                            "N": N,
                            "T": T,
                            "C": C
                        }
                        
                        # Mettre à jour le payload dans le message
                        message["payload"] = payload
                    
                    # Stocker le message dans messages.json
                    stored = store_message(message)
                    if stored:
                        result = {"status": "success", "message": "Message received and stored with time-lock puzzle"}
                    else:
                        result = {"status": "error", "message": "Message received but failed to store"}
            except Exception as e:
                print(f"Error processing message: {e}")
                result = {"status": "error", "message": f"Error processing message: {str(e)}"}
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
                        # Utiliser un buffer pour gérer les grandes quantités de données
                        buffer = b""
                        
                        while True:
                            # Recevoir des données par morceaux
                            chunk = conn.recv(8192)  # Augmenter la taille du buffer pour de meilleures performances
                            if not chunk:
                                break
                                
                            buffer += chunk
                            
                            # Vérifier si nous avons reçu un message JSON complet
                            try:
                                # Essayer de décoder - cela lèvera une exception si le JSON est incomplet
                                json.loads(buffer.decode())
                                # Si nous arrivons ici, le JSON est complet
                                break
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                # Continue à recevoir des données si le JSON est incomplet
                                continue
                        
                        if buffer:
                            print(f"Received data of size: {len(buffer)} bytes")
                            response = handle_client_request(buffer)
                            conn.sendall(response)

                    print("Connection closed")

                except ssl.SSLError as e:
                    print(f"SSL Error: {e}")
                except Exception as e:
                    print(f"Server error: {e}")

if __name__ == "__main__":
    run_server()