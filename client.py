import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import base64
import json
from crypto_utils import (
    generate_salt,
    derive_encryption_key,
    hash_password_argon2id,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    encrypt_private_key,
    decrypt_private_key,
    generate_symmetric_key,
    encrypt_message_symmetric,
    encrypt_key_asymmetric,
    hash_dict
)
from vdf_crypto import (
    solve_time_lock_puzzle,
    decrypt_with_challenge_key,
    get_original_encrypted_k_msg
)
import os
from datetime import datetime
import uuid

# Ensure client_keys directory exists
Path("client_keys").mkdir(exist_ok=True)

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc):    
    ret = False
    user_dir = Path(f"client_keys/{username}")
    user_dir.mkdir(parents=True, exist_ok=True)

    with open(user_dir / "sign_key.pem", "wb") as f:
        f.write(priv_sign.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(user_dir / "enc_key.pem", "wb") as f:
        f.write(priv_enc.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(user_dir / "sign_pub.pem", "wb") as f:
        f.write(pub_sign.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open(user_dir / "enc_pub.pem", "wb") as f:
        f.write(pub_enc.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    ret = True
    return ret  

def get_keys_from_password(username, password, response_json):
    # response_json → dictionnary
    if isinstance(response_json, str):  
        response_json = json.loads(response_json)

    if response_json.get("status") == "error":
        return f"Server error: {response_json.get('message')}"

    # The server returns the user data directly, not nested under a "user" key
    # Check if the expected fields are in the response
    required_fields = ["salt_argon2", "salt_hkdf", "Encrypted_sign_key", "Encrypted_enc_key", "PubKey_sign", "PubKey_enc"]
    if not all(key in response_json for key in required_fields):
        print(f"Server response: {response_json}")
        return "Required fields missing in server response"

    try:
        # Step 1: Base64 decode salts
        salt_argon2 = base64.b64decode(response_json["salt_argon2"])
        salt_hkdf = base64.b64decode(response_json["salt_hkdf"])

        # Step 2: Regenerate derived key from password
        hashed = hash_password_argon2id(password, salt_argon2)
        derived_key = derive_encryption_key(hashed, salt_hkdf, length=32)

        # Step 3: Decrypt private keys
        encrypted_sign_key = base64.b64decode(response_json["Encrypted_sign_key"])
        encrypted_enc_key = base64.b64decode(response_json["Encrypted_enc_key"])

        try:
            # Decrypt signing key
            priv_sign_bytes = decrypt_private_key(encrypted_sign_key, derived_key)
            priv_sign = Ed25519PrivateKey.from_private_bytes(priv_sign_bytes)
            
            # Decrypt encryption key
            priv_enc_bytes = decrypt_private_key(encrypted_enc_key, derived_key)
            priv_enc = X25519PrivateKey.from_private_bytes(priv_enc_bytes)

            # Get public keys from private
            pub_sign = priv_sign.public_key()
            pub_enc = priv_enc.public_key()
            
            # Verify that derived public keys match those stored on server
            # This confirms the password is correct
            server_pub_sign = base64.b64decode(response_json["PubKey_sign"])
            server_pub_enc = base64.b64decode(response_json["PubKey_enc"])
            
            # Convert our public keys to raw format for comparison
            derived_pub_sign = pub_sign.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            derived_pub_enc = pub_enc.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Verify keys match
            if derived_pub_sign != server_pub_sign or derived_pub_enc != server_pub_enc:
                print("Public keys derived from password don't match server keys!")
                print(f"Server sign key: {base64.b64encode(server_pub_sign).decode()}")
                print(f"Derived sign key: {base64.b64encode(derived_pub_sign).decode()}")
                return "Mot de passe incorrect"

            # Save locally
            ret = save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc)

            # Only return True if keys were successfully saved
            return ret

        except Exception as e:
            print(f"Error decrypting keys: {str(e)}")
            return "Mot de passe incorrect ou erreur de déchiffrement"
    
    except KeyError as e:
        print(f"Missing key in server response: {e}")
        return f"Server error: Missing data {e}"

def create_user(username=None, password=None):
    if username is None:
        username = input("Enter username: ")
    if password is None:
        password = input("Enter password: ")

    # 1. Generate 2 salt for password and HKDF
    salt_argon2 = generate_salt(32)
    salt_hkdf = generate_salt(32)

    # 2. Hash with Argon2id
    hashed = hash_password_argon2id(password, salt_argon2)

    # 3. HKDF (SHA3-256)
    derived_key = derive_encryption_key(hashed, salt=salt_hkdf, length=32)

    # 4. Generate keys
    priv_sign, pub_sign = generate_ed25519_keypair()
    priv_enc, pub_enc = generate_x25519_keypair()

    # Serialize public keys
    pubkey_sign = base64.b64encode(pub_sign.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    pubkey_enc = base64.b64encode(pub_enc.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    # Serialize and encrypt private keys
    privkey_sign_bytes = priv_sign.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    privkey_enc_bytes = priv_enc.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted_sign_key = base64.b64encode(encrypt_private_key(privkey_sign_bytes, derived_key)).decode()
    encrypted_enc_key = base64.b64encode(encrypt_private_key(privkey_enc_bytes, derived_key)).decode()

    # Save keys locally 
    save_keys(username, priv_sign, pub_sign, priv_enc, pub_enc)

    # Prepare data
    user_data = {
        "action": "create_user",
        "username": username,
        "salt_argon2": base64.b64encode(salt_argon2).decode(),
        "salt_hkdf": base64.b64encode(salt_hkdf).decode(),
        "PubKey_sign": pubkey_sign,
        "PubKey_enc": pubkey_enc,
        "Encrypted_sign_key": encrypted_sign_key,
        "Encrypted_enc_key": encrypted_enc_key
    }
    return json.dumps(user_data)


def reset_password(new_password, username):
    user_dir = Path(f"client_keys/{username}")
    priv_sign = load_private_key(user_dir / "sign_key.pem")
    priv_enc  = load_private_key(user_dir / "enc_key.pem")

    # 1. Nouveau sel et dérivation de clé avec le nouveau mot de passe
    salt_argon2 = generate_salt(32)
    salt_hkdf = generate_salt(32)

    hashed = hash_password_argon2id(new_password, salt_argon2)
    derived_key = derive_encryption_key(hashed, salt_hkdf, length=32)

    # 2. Extraire et rechiffrer les clés privées existantes
    privkey_sign_bytes = priv_sign.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    privkey_enc_bytes = priv_enc.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted_sign_key = base64.b64encode(encrypt_private_key(privkey_sign_bytes, derived_key)).decode()
    encrypted_enc_key = base64.b64encode(encrypt_private_key(privkey_enc_bytes, derived_key)).decode()

    # 3. Créer le message à signer (sans les clés publiques)
    unsigned_payload = {
        "action": "reset_password",
        "username": username,
        "salt_argon2": base64.b64encode(salt_argon2).decode(),
        "salt_hkdf": base64.b64encode(salt_hkdf).decode(),
        "Encrypted_sign_key": encrypted_sign_key,
        "Encrypted_enc_key": encrypted_enc_key
    }

    # 4. Signer le message avec l'ancienne clé de signature
    message = json.dumps(unsigned_payload, sort_keys=True).encode()
    signature = priv_sign.sign(message)
    signature_b64 = base64.b64encode(signature).decode()

    # 5. Ajouter la signature
    final_payload = dict(unsigned_payload)
    final_payload["signature"] = signature_b64

    return json.dumps(final_payload)

def send_message_payload(sender, recipient, content, message_type, unlock_date, Pubkey_recipient):
    # 1. Générer une clé symétrique (ChaCha20)
    k_msg = generate_symmetric_key()

    # 2. Chiffrer le message avec cette clé
    # Encoder seulement si le contenu est déjà une chaîne (texte) et pas des bytes
    if isinstance(content, str):
        content_bytes = content.encode()
    else:
        content_bytes = content
        
    ciphertext, nonce = encrypt_message_symmetric(content_bytes, k_msg)

    # 3. Chiffrer la clé avec la clé publique du destinataire
    pubkey_recipient_bytes = base64.b64decode(Pubkey_recipient)
    encrypted_k_msg = encrypt_key_asymmetric(k_msg, pubkey_recipient_bytes)

    # Calculer le temps jusqu'au déverrouillage pour adapter le VDF
    has_vdf_puzzle = False
    vdf_challenge = None
    
    if unlock_date:
        try:
            # Convertir le format de date en objet datetime
            day, month, year, hour, minute, second = unlock_date.split(":")
            unlock_datetime = datetime(int(year), int(month), int(day), 
                                     int(hour), int(minute), int(second))
            now = datetime.now()
            
            # Vérifier si la date de déverrouillage est dans le futur
            if unlock_datetime > now:
                # Calculer le temps restant en secondes
                time_diff = (unlock_datetime - now).total_seconds()
                
                # Si le délai est inférieur à 5 minutes, on ne met pas de VDF
                if time_diff > 300:  # Plus de 5 minutes
                    # Générer une clé de défi
                    challenge_key = generate_challenge_key()
                    
                    # Déterminer la difficulté du puzzle
                    # Plus la date est éloignée, plus le puzzle est long à résoudre
                    # Mais on limite le temps à 5 minutes maximum pour ne pas bloquer le navigateur
                    vdf_seconds = min(time_diff / 120, 300)  # ~0.8% du temps total, max 5 min
                    
                    print(f"Génération d'un puzzle VDF adapté: {vdf_seconds:.2f} secondes pour un délai de {time_diff:.2f} secondes")
                    
                    # Créer le time-lock puzzle
                    from vdf_crypto import generate_time_lock_puzzle, encrypt_with_challenge_key, store_original_encrypted_k_msg
                    N, T, C = generate_time_lock_puzzle(challenge_key, vdf_seconds)
                    
                    # Double chiffrement: chiffrer la clé déjà chiffrée avec la clé challenge
                    double_encrypted = encrypt_with_challenge_key(encrypted_k_msg, challenge_key)
                    
                    # Stocker l'original en mémoire/fichier pour récupération possible
                    message_id = str(uuid.uuid4())
                    store_original_encrypted_k_msg(message_id, encrypted_k_msg)
                    
                    # Remplacer la clé chiffrée originale par la version double-chiffrée
                    encrypted_k_msg = double_encrypted
                    
                    # Définir le challenge VDF
                    has_vdf_puzzle = True
                    vdf_challenge = {
                        "N": N,
                        "T": T,
                        "C": C,
                        "unlock_delay_seconds": time_diff
                    }
                    
                    print(f"Puzzle VDF généré: N={N}, T={T}, C={C}")
        except Exception as e:
            print(f"Erreur lors de la génération du VDF basé sur la date: {e}")
            # Continuer sans VDF en cas d'erreur

    # 4. Construire le message D (non signé)
    D = {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "encrypted_k_msg": base64.b64encode(encrypted_k_msg).decode(),
        "unlock_date": unlock_date,
        "is_binary": not isinstance(content, str)  # Marquer si c'est un fichier binaire
    }
    
    # Ajouter le challenge VDF si présent
    if has_vdf_puzzle:
        D["vdf_challenge"] = vdf_challenge

    # 5. Hacher D pour signature
    hashed_D = hash_dict(D)  # → bytes

    # 6. Charger la clé privée de signature du sender
    sender_dir = Path(f"client_keys/{sender}")
    priv_sign = load_private_key(sender_dir / "sign_key.pem")
    if not isinstance(priv_sign, Ed25519PrivateKey):
        raise ValueError("Sender private key must be Ed25519")

    # 7. Signer le hash de D
    signature = priv_sign.sign(hashed_D)
    signature_b64 = base64.b64encode(signature).decode()

    # 8. Créer le message final
    msg = {
        "message_id": str(uuid.uuid4()) if not has_vdf_puzzle else message_id,
        "from": sender,
        "to": recipient,
        "type": message_type,
        "payload": D,
        "signature": signature_b64
    }

    return json.dumps({"action": "send_message", "message": msg})

def decrypt_message(message, recipient_private_key):
    """
    Déchiffre un message reçu.
    
    Args:
        message (dict): Le message à déchiffrer
        recipient_private_key (X25519PrivateKey): La clé privée du destinataire
    
    Returns:
        Union[str, bytes]: Le contenu déchiffré (texte ou binaire)
    """
    try:
        # Extraire les données du payload
        payload = message.get("payload", {})
        message_id = message.get("message_id")
        
        if not payload:
            return "Erreur: payload vide"
            
        encrypted_k_msg_b64 = payload.get("encrypted_k_msg")
        nonce_b64 = payload.get("nonce")
        ciphertext_b64 = payload.get("ciphertext")
        vdf_challenge = payload.get("vdf_challenge")
        is_binary = payload.get("is_binary", False)  # Par défaut, considérer comme texte
        
        if not all([encrypted_k_msg_b64, nonce_b64, ciphertext_b64]):
            return "Erreur: message incomplet"
            
        # Convertir de base64 en bytes
        encrypted_k_msg = base64.b64decode(encrypted_k_msg_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Résoudre le VDF challenge si présent
        if vdf_challenge:
            print("Message protégé par un time-lock puzzle. Déchiffrement en cours...")
            
            # Vérifier d'abord si le message est verrouillé par date avant de tenter de récupérer la clé originale
            unlock_date_str = payload.get("unlock_date")
            unlock_date_passed = False
            
            if unlock_date_str:
                try:
                    day, month, year, hour, minute, second = unlock_date_str.split(":")
                    unlock_datetime = datetime(int(year), int(month), int(day), 
                                              int(hour), int(minute), int(second))
                    now = datetime.now()
                    unlock_date_passed = now >= unlock_datetime
                except Exception as e:
                    print(f"Erreur lors de la vérification de la date: {e}")
            
            # Option 1: Essayer d'obtenir le message chiffré original SEULEMENT si la date est passée
            original_encrypted_k_msg = None
            if unlock_date_passed or not unlock_date_str:
                original_encrypted_k_msg = get_original_encrypted_k_msg(message_id)
                if original_encrypted_k_msg:
                    print("Clé originale récupérée (date de déverrouillage atteinte).")
            
            if not original_encrypted_k_msg:
                # Option 2: Résoudre le puzzle (plus lent ou requis si la date n'est pas atteinte)
                if not unlock_date_passed and unlock_date_str:
                    print(f"SÉCURITÉ: Message verrouillé par date jusqu'au {unlock_date_str}.")
                    print("Résolution forcée du VDF puisque la date n'est pas encore atteinte.")
                else:
                    print("Message original non disponible. Résolution du puzzle temporel...")
                
                N = vdf_challenge.get("N")
                T = vdf_challenge.get("T")
                C = vdf_challenge.get("C")
                
                if all([N, T, C]):
                    # Résoudre le puzzle pour obtenir la clé de défi
                    print(f"Résolution du puzzle VDF avec {T} itérations...")
                    challenge_key = solve_time_lock_puzzle(N, T, C)
                    # Déchiffrer la clé symétrique avec la clé de défi
                    encrypted_k_msg = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)
                else:
                    return "Erreur: paramètres de puzzle incomplets"
            else:
                # Utiliser directement le message chiffré original
                encrypted_k_msg = original_encrypted_k_msg
        
        # Déchiffrer la clé symétrique avec la clé privée du destinataire
        from crypto_utils import decrypt_key_asymmetric
        k_msg = decrypt_key_asymmetric(encrypted_k_msg, recipient_private_key)
        
        # Déchiffrer le message avec la clé symétrique
        from crypto_utils import decrypt_message_symmetric
        decrypted_content = decrypt_message_symmetric(ciphertext, nonce, k_msg)
        
        # Si le contenu est binaire, le retourner tel quel, sinon le décoder en texte
        if is_binary:
            return decrypted_content  # Retourne les bytes bruts
        else:
            return decrypted_content.decode('utf-8')  # Convertit en texte
        
    except Exception as e:
        print(f"Erreur lors du déchiffrement du message: {e}")
        return f"Erreur de déchiffrement: {str(e)}"

def download_messages(username, server_response=None):
    """
    Télécharge tous les messages d'un utilisateur et les stocke dans un dossier local.
    
    Args:
        username (str): Nom d'utilisateur
        server_response (str, optional): Réponse du serveur contenant les messages. Si None, les messages seront demandés au serveur.
        
    Returns:
        dict: Informations sur les messages téléchargés
    """
    # Créer le dossier de destination s'il n'existe pas
    download_dir = Path(f"client_messages_download/{username}")
    download_dir.mkdir(parents=True, exist_ok=True)
    
    # Si aucune réponse serveur n'est fournie, demander les messages au serveur
    if server_response is None:
        # Créer la requête
        request = {
            "action": "get_messages",
            "username": username
        }
        
        # Envoyer la requête au serveur (à implémenter dans l'application principale)
        # server_response = send_request_to_server(json.dumps(request))
        return {
            "status": "error",
            "message": "Aucune réponse serveur fournie. Cette fonction doit être appelée depuis l'application."
        }
    
    # Traiter la réponse du serveur
    if isinstance(server_response, str):
        server_response = json.loads(server_response)
        
    if server_response.get("status") != "success" or "messages" not in server_response:
        return {
            "status": "error",
            "message": f"Erreur serveur: {server_response.get('message', 'Réponse invalide')}"
        }
        
    messages = server_response["messages"]
    if not messages:
        return {
            "status": "info",
            "message": "Aucun message à télécharger"
        }
    
    # Charger la clé privée de déchiffrement
    try:
        user_dir = Path(f"client_keys/{username}")
        priv_enc = load_private_key(user_dir / "enc_key.pem")
    except Exception as e:
        return {
            "status": "error",
            "message": f"Erreur de chargement de la clé privée: {e}"
        }
    
    # Déchiffrer et sauvegarder chaque message
    downloaded_messages = []
    locked_messages = []
    errors = []
    
    for msg in messages:
        try:
            message_id = msg.get("message_id", "unknown")
            sender = msg.get("from", "unknown")
            timestamp = msg.get("timestamp", "")
            
            # Créer un nom de fichier unique pour le message
            timestamp_str = timestamp.replace(" ", "_").replace(":", "-") if timestamp else ""
            filename = f"{message_id}_{sender}_{timestamp_str}.json"
            
            # Sauvegarder le message brut
            with open(download_dir / filename, "w", encoding="utf-8") as f:
                json.dump(msg, f, indent=4)
                
            # Vérifier si le message peut être déchiffré
            payload = msg.get("payload", {})
            unlock_date_str = payload.get("unlock_date")
            vdf_challenge = payload.get("vdf_challenge")
            
            is_locked = False
            
            # Vérifier si le message est verrouillé par date
            if unlock_date_str:
                try:
                    day, month, year, hour, minute, second = unlock_date_str.split(":")
                    unlock_datetime = datetime(int(year), int(month), int(day), 
                                            int(hour), int(minute), int(second))
                    now = datetime.now()
                    is_locked = now < unlock_datetime
                except Exception as e:
                    print(f"Erreur de parsing de date: {e}")
            
            # Si le message n'est pas verrouillé par date, essayer de le déchiffrer
            if not is_locked:
                try:
                    content = decrypt_message(msg, priv_enc)
                    
                    if isinstance(content, str):
                        # Sauvegarder le contenu déchiffré pour les messages texte
                        content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.txt"
                        with open(download_dir / content_filename, "w", encoding="utf-8") as f:
                            f.write(content)
                    else:
                        # Sauvegarder le contenu binaire
                        content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.bin"
                        with open(download_dir / content_filename, "wb") as f:
                            f.write(content)
                    
                    downloaded_messages.append({
                        "id": message_id,
                        "sender": sender,
                        "timestamp": timestamp,
                        "filename": content_filename,
                        "is_decrypted": True
                    })
                except Exception as e:
                    if vdf_challenge:
                        # Si le déchiffrement échoue et qu'il y a un VDF challenge, c'est probablement à cause du VDF
                        locked_messages.append({
                            "id": message_id,
                            "sender": sender,
                            "timestamp": timestamp,
                            "vdf_challenge": True
                        })
                    else:
                        errors.append({
                            "id": message_id,
                            "error": str(e)
                        })
            else:
                # Message verrouillé par date
                locked_messages.append({
                    "id": message_id,
                    "sender": sender,
                    "timestamp": timestamp,
                    "unlock_date": unlock_date_str,
                    "date_locked": True
                })
            
        except Exception as e:
            errors.append({
                "id": msg.get("message_id", "unknown"),
                "error": str(e)
            })
    
    return {
        "status": "success",
        "downloaded": len(downloaded_messages),
        "locked": len(locked_messages),
        "errors": len(errors),
        "download_dir": str(download_dir),
        "messages": downloaded_messages,
        "locked_messages": locked_messages,
        "error_details": errors
    }

def solve_vdf_for_message(username, message_id, server_response=None):
    """
    Résout manuellement le VDF pour un message spécifique.
    
    Args:
        username (str): Nom d'utilisateur
        message_id (str): ID du message
        server_response (str, optional): Réponse du serveur contenant le message. Si None, le message sera demandé.
        
    Returns:
        dict: Résultat de l'opération
    """
    # D'abord, essayer d'obtenir la clé originale directement du serveur
    # (si la date est passée, le serveur devrait la donner automatiquement)
    if server_response is None:
        # Cette fonction doit être appelée depuis l'application avec une réponse serveur
        get_key_request = {
            "action": "get_original_key",
            "username": username,
            "message_id": message_id
        }
        
        # server_response = send_request_to_server(json.dumps(get_key_request))
        return {
            "status": "error",
            "message": "Aucune réponse serveur fournie. Cette fonction doit être appelée depuis l'application."
        }
    
    if isinstance(server_response, str):
        server_response = json.loads(server_response)
    
    # Si le serveur a retourné la clé originale, pas besoin de résoudre le VDF
    if server_response.get("status") == "success" and "original_key" in server_response:
        original_key_b64 = server_response["original_key"]
        
        return {
            "status": "success",
            "message": "Clé obtenue directement du serveur",
            "key": original_key_b64,
            "solved": False
        }
    
    # Si le serveur n'a pas retourné la clé, nous devons résoudre le VDF
    # Récupérer d'abord le message
    try:
        # Charger les messages du fichier local ou de l'application
        messages_file = "messages.json"
        
        if not os.path.exists(messages_file):
            return {
                "status": "error",
                "message": "Aucun message disponible"
            }
            
        with open(messages_file, 'r') as f:
            messages_data = json.load(f)
            
        # Trouver le message spécifique
        target_message = None
        for msg in messages_data.get("messages", []):
            if msg.get("message_id") == message_id and msg.get("to") == username:
                target_message = msg
                break
                
        if not target_message:
            return {
                "status": "error",
                "message": "Message non trouvé ou vous n'êtes pas le destinataire"
            }
            
        # Vérifier si le message a un VDF challenge
        payload = target_message.get("payload", {})
        vdf_challenge = payload.get("vdf_challenge")
        
        if not vdf_challenge:
            return {
                "status": "error",
                "message": "Ce message n'a pas de VDF challenge"
            }
            
        # Extraire les paramètres du VDF
        N = vdf_challenge.get("N")
        T = vdf_challenge.get("T")
        C = vdf_challenge.get("C")
        
        if not all([N, T, C]):
            return {
                "status": "error",
                "message": "Paramètres VDF incomplets"
            }
            
        print(f"Résolution du VDF en cours pour le message {message_id}...")
        print(f"Cette opération peut prendre du temps ({T} itérations)")
        
        # Résoudre le puzzle
        challenge_key = solve_time_lock_puzzle(N, T, C)
        
        # Extraire et déchiffrer le encrypted_k_msg
        encrypted_k_msg_b64 = payload.get("encrypted_k_msg")
        if not encrypted_k_msg_b64:
            return {
                "status": "error",
                "message": "Paramètre encrypted_k_msg manquant"
            }
            
        encrypted_k_msg = base64.b64decode(encrypted_k_msg_b64)
        
        # Déchiffrer la clé symétrique avec la clé de défi
        original_k_msg = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)
        
        # Mettre à jour le message en mémoire
        payload["encrypted_k_msg"] = base64.b64encode(original_k_msg).decode()
        
        # Supprimer le VDF challenge maintenant qu'il est résolu
        if "vdf_challenge" in payload:
            del payload["vdf_challenge"]
            
        # Mettre à jour le message
        target_message["payload"] = payload
        
        # Vérifier si le message est verrouillé par date
        unlock_date_str = payload.get("unlock_date")
        is_locked = False
        
        if unlock_date_str:
            try:
                # Format du unlock_date: "14:05:2023:13:02:00" (jour:mois:année:heure:minute:seconde)
                day, month, year, hour, minute, second = unlock_date_str.split(":")
                unlock_datetime = datetime(int(year), int(month), int(day), 
                                          int(hour), int(minute), int(second))
                now = datetime.now()
                is_locked = now < unlock_datetime
                
                if is_locked:
                    # Indiquer que le message reste verrouillé par date
                    print(f"Message {message_id}: VDF résolu mais reste verrouillé par date jusqu'au {unlock_datetime.strftime('%d/%m/%Y %H:%M:%S')}")
            except Exception as e:
                print(f"Erreur lors de la vérification de la date de déverrouillage: {e}")
        
        # Sauvegarder dans un fichier local pour accès futur
        user_dir = Path(f"client_messages_download/{username}")
        user_dir.mkdir(parents=True, exist_ok=True)
        
        # Générer un nom de fichier unique
        timestamp = target_message.get("timestamp", "")
        sender = target_message.get("from", "unknown")
        timestamp_str = timestamp.replace(" ", "_").replace(":", "-") if timestamp else ""
        filename = f"{message_id}_{sender}_{timestamp_str}_solved.json"
        
        with open(user_dir / filename, "w", encoding="utf-8") as f:
            json.dump(target_message, f, indent=4)
            
        return {
            "status": "success",
            "message": "VDF résolu avec succès",
            "saved_file": str(user_dir / filename),
            "solved": True
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Erreur lors de la résolution du VDF: {e}"
        }

def solve_vdf_for_message_locally(username, message):
    """
    Résout localement le VDF pour un message sans contacter le serveur.
    
    Args:
        username (str): Nom d'utilisateur
        message (dict): Le message complet avec ses données
        
    Returns:
        dict: Résultat de l'opération
    """
    try:
        message_id = message.get("message_id")
        if not message_id:
            return {
                "status": "error",
                "message": "ID de message manquant"
            }
            
        # Vérifier d'abord si le message est verrouillé par date
        payload = message.get("payload", {})
        unlock_date_str = payload.get("unlock_date")
        is_time_locked = False
        unlock_datetime_display = None
        time_remaining = None
        
        if unlock_date_str:
            try:
                # Format du unlock_date: "14:05:2023:13:02:00" (jour:mois:année:heure:minute:seconde)
                day, month, year, hour, minute, second = unlock_date_str.split(":")
                unlock_datetime = datetime(int(year), int(month), int(day), 
                                          int(hour), int(minute), int(second))
                now = datetime.now()
                is_time_locked = now < unlock_datetime
                unlock_datetime_display = unlock_datetime.strftime("%d/%m/%Y %H:%M:%S")
                
                # Calculer le temps restant pour l'affichage
                if is_time_locked:
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
                print(f"Erreur lors de la vérification de la date de déverrouillage: {e}")
                
        # Vérifier si le message a un VDF challenge
        vdf_challenge = payload.get("vdf_challenge")
        
        if not vdf_challenge:
            return {
                "status": "error",
                "message": "Ce message n'a pas de VDF challenge"
            }
            
        # Extraire les paramètres du VDF
        N = vdf_challenge.get("N")
        T = vdf_challenge.get("T")
        C = vdf_challenge.get("C")
        unlock_delay_seconds = vdf_challenge.get("unlock_delay_seconds")
        
        if not all([N, T, C]):
            return {
                "status": "error",
                "message": "Paramètres VDF incomplets"
            }
            
        print(f"Résolution locale du VDF en cours pour le message {message_id}...")
        print(f"Cette opération peut prendre du temps ({T} itérations)")
        
        if unlock_delay_seconds:
            print(f"Ce message est conçu pour être déverrouillé après environ {unlock_delay_seconds} secondes")
        
        # Résoudre le puzzle
        challenge_key = solve_time_lock_puzzle(N, T, C)
        
        # Extraire et déchiffrer le encrypted_k_msg
        encrypted_k_msg_b64 = payload.get("encrypted_k_msg")
        if not encrypted_k_msg_b64:
            return {
                "status": "error",
                "message": "Paramètre encrypted_k_msg manquant"
            }
            
        encrypted_k_msg = base64.b64decode(encrypted_k_msg_b64)
        
        # Déchiffrer la clé symétrique avec la clé de défi
        original_k_msg = decrypt_with_challenge_key(encrypted_k_msg, challenge_key)
        
        # Créer une copie du message pour les modifications
        updated_message = json.loads(json.dumps(message))
        updated_payload = updated_message.get("payload", {})
        
        # Stocker la clé d'origine déchiffrée (après résolution du VDF)
        updated_payload["encrypted_k_msg"] = base64.b64encode(original_k_msg).decode()
        
        # Supprimer le VDF challenge maintenant qu'il est résolu
        if "vdf_challenge" in updated_payload:
            del updated_payload["vdf_challenge"]
            
        # Mettre à jour le message
        updated_message["payload"] = updated_payload
        
        # Sauvegarder dans un fichier local
        user_dir = Path(f"client_messages_download/{username}")
        user_dir.mkdir(parents=True, exist_ok=True)
        
        # Générer un nom de fichier unique
        timestamp = message.get("timestamp", "")
        sender = message.get("from", "unknown")
        timestamp_str = timestamp.replace(" ", "_").replace(":", "-") if timestamp else ""
        filename = f"{message_id}_{sender}_{timestamp_str}_solved.json"
        
        with open(user_dir / filename, "w", encoding="utf-8") as f:
            json.dump(updated_message, f, indent=4)
        
        # Préparer le résultat pour l'affichage
        result = {
            "status": "success",
            "message": "VDF résolu avec succès!",
            "saved_file": str(user_dir / filename),
            "solved": True,
            "updated_message": updated_message
        }
        
        # Si le message est toujours verrouillé par date, indiquer le temps restant
        if is_time_locked:
            result.update({
                "message": "VDF résolu avec succès, mais le message reste verrouillé par date",
                "still_time_locked": True,
                "unlock_date": unlock_datetime_display,
                "time_remaining": time_remaining
            })
            return result
        
        # Continuer avec le déchiffrement uniquement si le message n'est pas verrouillé par date
        try:
            # Charger la clé privée de déchiffrement
            user_dir_keys = Path(f"client_keys/{username}")
            with open(user_dir_keys / "enc_key.pem", "rb") as f:
                priv_enc = serialization.load_pem_private_key(f.read(), password=None)
                
            # Déchiffrer le message
            content = decrypt_message(updated_message, priv_enc)
            
            # Sauvegarder le contenu déchiffré
            if isinstance(content, str):
                content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.txt"
                with open(user_dir / content_filename, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                content_filename = f"{message_id}_{sender}_{timestamp_str}_decrypted.bin"
                with open(user_dir / content_filename, "wb") as f:
                    f.write(content)
                    
            result.update({
                "message": "VDF résolu avec succès localement et message déchiffré",
                "content_file": str(user_dir / content_filename),
                "decrypted_content": content if isinstance(content, str) else "[Contenu binaire]"
            })
            return result
        except Exception as e:
            print(f"Erreur lors du déchiffrement après résolution: {e}")
            result.update({
                "message": "VDF résolu avec succès mais erreur lors du déchiffrement: " + str(e)
            })
            return result
    
    except Exception as e:
        return {
            "status": "error",
            "message": f"Erreur lors de la résolution locale du VDF: {e}"
        }

