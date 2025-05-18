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
    store_message,
    verify_auth_key
)
from vdf_crypto import (
    generate_challenge_key,
    encrypt_with_challenge_key,
    generate_time_lock_puzzle,
    store_original_encrypted_k_msg,
    get_original_encrypted_k_msg
)
from datetime import datetime

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
                auth_key=request["auth_key"],
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
                    # Appliquer les nouvelles données comme un "update" d'utilisateur
                    ok = create_user(  # On réécrit les données avec la nouvelle auth_key et les clés
                        username=request["username"],
                        auth_key=request["auth_key"],
                        pubkey_sign=request["PubKey_sign"],
                        pubkey_enc=request["PubKey_enc"],
                        encrypted_sign_key=request["Encrypted_sign_key"],
                        encrypted_enc_key=request["Encrypted_enc_key"]
                    )
                    status = "success" if ok else "error"
                    result = {"status": status, "message": "Password reset" if ok else "Failed to update user"}
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
                    
                    print(f"DEBUG - Traitement du message {message_id} de {sender}")
                    
                    # 1. Générer une clé de défi aléatoire (32 octets)
                    challenge_key = generate_challenge_key()
                    print(f"DEBUG - Clé de défi générée: {challenge_key.hex()[:16]}...")

                    # 2. Déterminer le temps de puzzle en fonction de la date d'unlock
                    unlock_time = 10  # valeur par défaut en secondes
                    
                    if "unlock_date" in payload:
                        unlock_date_str = payload["unlock_date"]
                        try:
                            day, month, year, hour, minute, second = unlock_date_str.split(":")
                            unlock_datetime = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
                            now = datetime.now()
                            
                            print(f"DEBUG - Date de déverrouillage: {unlock_datetime}, temps actuel: {now}")
                            
                            if unlock_datetime > now:
                                time_diff = (unlock_datetime - now).total_seconds()
                                MAX_PUZZLE_TIME = 300  # 5 minutes maximum
                                unlock_time = min(time_diff / 120, MAX_PUZZLE_TIME)

                                if "vdf_challenge" in payload and "unlock_delay_seconds" in payload["vdf_challenge"]:
                                    client_unlock_time = float(payload["vdf_challenge"]["unlock_delay_seconds"])
                                    print(f"DEBUG - Temps de déverrouillage VDF spécifié par le client: {client_unlock_time:.2f}s")
                                    unlock_time = min(client_unlock_time / 120, MAX_PUZZLE_TIME)

                                print(f"DEBUG - Différence temporelle: {time_diff:.2f} secondes, temps de puzzle fixé à: {unlock_time:.2f}s (environ {100*unlock_time/time_diff:.2f}% du temps d'attente)")
                        except Exception as e:
                            print(f"Erreur lors du parsing de la date d'unlock: {e}")
                    
                    # 3. Créer un time-lock puzzle pour la même clé de défi
                    N, T, C = generate_time_lock_puzzle(challenge_key, unlock_time)
                    print(f"DEBUG - Puzzle généré: N={N}, T={T}, C={C}")
                    
                    # 4. Chiffrer le encrypted_k_msg avec la même clé de défi
                    if "encrypted_k_msg" in payload:
                        encrypted_k_msg_bytes = base64.b64decode(payload["encrypted_k_msg"])
                        print(f"DEBUG - Taille du encrypted_k_msg original: {len(encrypted_k_msg_bytes)} octets")
                        
                        # Stocker encrypted_k_msg original pour récupération après déverrouillage par date
                        store_original_encrypted_k_msg(message_id, encrypted_k_msg_bytes)
                        
                        # Double chiffrage avec la même clé que celle du VDF
                        double_encrypted = encrypt_with_challenge_key(encrypted_k_msg_bytes, challenge_key)
                        print(f"DEBUG - Taille du encrypted_k_msg après doublement chiffré: {len(double_encrypted)} octets")
                        
                        payload["encrypted_k_msg"] = base64.b64encode(double_encrypted).decode()
                        
                        # Ajouter les paramètres du puzzle au message
                        payload["vdf_challenge"] = {
                            "N": N,
                            "T": T,
                            "C": C
                        }
                        
                        # Mettre à jour le payload dans le message
                        message["payload"] = payload
                        
                        print(f"DEBUG - Message {message_id} préparé avec succès, prêt à être stocké")
                    
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
            auth_key_client = request.get("auth_key")

            if not username or not auth_key_client:
                result = {"status": "error", "message": "Missing 'username' or 'auth_key' in request."}
            elif not verify_auth_key(username, auth_key_client):
                result = {"status": "error", "message": "Invalid authentication key."}
            else:
                result = get_user_all_data(username)
        elif action == "get_messages":
            username = request.get("username")
            if not username:
                result = {"status": "error", "message": "Missing 'username' in request."}
            else:
                # Charger les messages du fichier
                messages_file = "messages.json"
                if not os.path.exists(messages_file):
                    result = {"status": "error", "message": "No messages available"}
                else:
                    try:
                        with open(messages_file, 'r') as f:
                            messages_data = json.load(f)
                            
                        # Filtrer les messages pour le destinataire demandé
                        user_messages = []
                        for msg in messages_data.get("messages", []):
                            if msg.get("to") == username:
                                # Créer une copie du message pour ne pas modifier l'original
                                msg_copy = json.loads(json.dumps(msg))
                                
                                # Vérifier si la date d'unlock est passée
                                unlock_date_str = msg_copy.get("payload", {}).get("unlock_date")
                                if unlock_date_str:
                                    try:
                                        # Format du unlock_date: "14:05:2023:13:02:00"
                                        day, month, year, hour, minute, second = unlock_date_str.split(":")
                                        unlock_datetime = datetime(int(year), int(month), int(day), 
                                                                int(hour), int(minute), int(second))
                                        now = datetime.now()
                                        
                                        # Si la date est passée, remplacer la clé chiffrée par l'originale
                                        if now >= unlock_datetime and "message_id" in msg_copy:
                                            message_id = msg_copy["message_id"]
                                            original_key = get_original_encrypted_k_msg(message_id)
                                            
                                            if original_key:
                                                # Remplacer la clé chiffrée dans le message
                                                msg_copy["payload"]["encrypted_k_msg"] = base64.b64encode(original_key).decode()
                                                # Supprimer les informations de défi VDF
                                                if "vdf_challenge" in msg_copy["payload"]:
                                                    del msg_copy["payload"]["vdf_challenge"]
                                    except Exception as e:
                                        print(f"Erreur lors du traitement de la date d'unlock: {e}")
                                
                                user_messages.append(msg_copy)
                        
                        result = {"status": "success", "messages": user_messages}
                    except Exception as e:
                        result = {"status": "error", "message": f"Error retrieving messages: {str(e)}"}
        elif action == "get_original_key":
            # Endpoint pour récupérer la clé originale d'un message
            message_id = request.get("message_id")
            username = request.get("username")
            
            if not message_id or not username:
                result = {"status": "error", "message": "Missing message_id or username"}
            else:
                # Vérifier que l'utilisateur est bien le destinataire du message
                messages_file = "messages.json"
                is_recipient = False
                
                if os.path.exists(messages_file):
                    try:
                        with open(messages_file, 'r') as f:
                            messages_data = json.load(f)
                            
                        for msg in messages_data.get("messages", []):
                            if msg.get("message_id") == message_id and msg.get("to") == username:
                                is_recipient = True
                                
                                # Vérifier si la date d'unlock est passée
                                unlock_date_str = msg.get("payload", {}).get("unlock_date")
                                date_passed = False
                                
                                if unlock_date_str:
                                    try:
                                        day, month, year, hour, minute, second = unlock_date_str.split(":")
                                        unlock_datetime = datetime(int(year), int(month), int(day), 
                                                               int(hour), int(minute), int(second))
                                        now = datetime.now()
                                        date_passed = now >= unlock_datetime
                                    except:
                                        # En cas d'erreur, considérer la date comme non passée
                                        date_passed = False
                                
                                # Si la date est passée ou s'il n'y a pas de date, donner la clé originale
                                if date_passed or not unlock_date_str:
                                    original_key = get_original_encrypted_k_msg(message_id)
                                    if original_key:
                                        result = {
                                            "status": "success", 
                                            "original_key": base64.b64encode(original_key).decode()
                                        }
                                    else:
                                        result = {"status": "error", "message": "Original key not found"}
                                else:
                                    # Message toujours verrouillé par date
                                    result = {
                                        "status": "error", 
                                        "message": "Message is still locked by date",
                                        "unlock_date": unlock_date_str
                                    }
                                break
                    except Exception as e:
                        result = {"status": "error", "message": f"Error checking message: {str(e)}"}
                
                if not is_recipient:
                    result = {"status": "error", "message": "Not authorized or message not found"}
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