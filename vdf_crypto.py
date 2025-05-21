import random
import time
import math
import json
import os
import secrets
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64

def is_coprime(a, b):
    return math.gcd(a, b) == 1

def generate_time_lock_puzzle(secret_bytes, T_desired_seconds=10):
    """
    Génère un time-lock puzzle qui encode directement la clé de défi dans le VDF.
    """
    secret_int = int.from_bytes(secret_bytes, byteorder='big')

    primes_pool = [10007, 10009, 10037, 10039, 50021, 50023, 50033, 104723, 104729, 104743, 104759]
    p = random.choice(primes_pool)
    q = random.choice([x for x in primes_pool if x != p])
    N = p * q

    print(f"DEBUG - N = {N} (p = {p}, q = {q})")

    if not is_coprime(secret_int, N):
        secret_int += 1

    # Estimation du temps d'une itération
    test_iterations = 1000
    x = 2
    start_time = time.time()
    for _ in range(test_iterations):
        x = pow(x, 2, N)
    elapsed_time = time.time() - start_time
    time_per_iter = elapsed_time / test_iterations

    print(f"DEBUG - Temps mesuré par itération: {time_per_iter:.6f} secondes")

    # Calcul du nombre d'itérations pour atteindre T_desired_seconds
    T_iterations = max(1, int(T_desired_seconds / time_per_iter))
    print(f"DEBUG - Nombre d'itérations calculé: {T_iterations}")

    # Calcul de a par squarings successifs
    a = 2
    for _ in range(T_iterations):
        a = pow(a, 2, N)

    # On utilise a directement comme la clé
    return (N, T_iterations, a)

def solve_time_lock_puzzle(N, T):
    """
    Résout un time-lock puzzle et retourne la clé a sous forme de 32 octets.
    """
    a = 2
    for _ in range(T):
        a = pow(a, 2, N)

    # Convertir en 32 octets (padding à gauche si nécessaire)
    a_bytes = a.to_bytes((a.bit_length() + 7) // 8 or 1, byteorder='big')
    if len(a_bytes) < 32:
        a_bytes = (b'\x00' * (32 - len(a_bytes))) + a_bytes
    elif len(a_bytes) > 32:
        a_bytes = a_bytes[-32:]

    return a_bytes

def generate_challenge_key():
    """
    Génère une clé de défi utilisée pour le time-lock puzzle.
    
    Returns:
        bytes: Une clé de 32 bytes
    """
    return secrets.token_bytes(32)

def encrypt_with_challenge_key(data, challenge_key):
    """
    Chiffre des données avec la clé de défi.
    
    Args:
        data (bytes): Données à chiffrer
        challenge_key (bytes): Clé de défi
        
    Returns:
        bytes: Données chiffrées
    """
    aead = ChaCha20Poly1305(challenge_key)
    nonce = secrets.token_bytes(12)
    ciphertext = aead.encrypt(nonce, data, associated_data=None)
    return nonce + ciphertext

def decrypt_with_challenge_key(encrypted_data, challenge_key):
    """
    Déchiffre des données avec la clé de défi.
    
    Args:
        encrypted_data (bytes): Données chiffrées
        challenge_key (bytes): Clé de défi
        
    Returns:
        bytes: Données déchiffrées
    """
    try:
        print(f"DEBUG - decrypt_with_challenge_key:")
        print(f"  - Taille des données chiffrées: {len(encrypted_data)} octets")
        print(f"  - Challenge key (hex): {challenge_key.hex()[:16]}...")
        
        # Au moins 12 octets pour le nonce + données chiffrées
        if len(encrypted_data) < 12:
            print(f"ERREUR: Données chiffrées trop courtes ({len(encrypted_data)} octets, minimum 12)")
            return None
            
        aead = ChaCha20Poly1305(challenge_key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        print(f"  - Nonce (hex): {nonce.hex()}")
        print(f"  - Taille du ciphertext: {len(ciphertext)} octets")
        
        result = aead.decrypt(nonce, ciphertext, associated_data=None)
        print(f"  - Déchiffrement réussi, taille du résultat: {len(result)} octets")
        return result
    except Exception as e:
        print(f"ERREUR dans decrypt_with_challenge_key: {e}")
        raise

def store_original_encrypted_k_msg(message_id, encrypted_k_msg):
    """
    Stocke le message chiffré original (encrypted_k_msg) dans un fichier pour accès rapide.
    
    Args:
        message_id (str): L'ID du message
        encrypted_k_msg (bytes): Le message chiffré original
        
    Returns:
        bool: True si réussi, False sinon
    """
    keys_file = "challenge_keys.json"
    
    try:
        print(f"DEBUG - store_original_encrypted_k_msg:")
        print(f"  - ID du message: {message_id}")
        print(f"  - Taille du encrypted_k_msg: {len(encrypted_k_msg)} octets")
        
        # Charger les clés existantes ou créer une nouvelle structure
        if os.path.exists(keys_file):
            with open(keys_file, 'r') as f:
                try:
                    keys_data = json.load(f)
                    print(f"  - Fichier {keys_file} existant chargé: {len(keys_data)} clés")
                except json.JSONDecodeError:
                    print(f"  - Erreur de décodage JSON du fichier {keys_file}, création d'une structure vide")
                    keys_data = {}
        else:
            print(f"  - Fichier {keys_file} n'existe pas, création d'une structure vide")
            keys_data = {}
        
        # Stocker le message chiffré encodé en base64
        encoded = base64.b64encode(encrypted_k_msg).decode('utf-8')
        keys_data[message_id] = encoded
        print(f"  - Clé encodée en base64: {encoded[:30]}...")
        
        # Écrire dans le fichier
        with open(keys_file, 'w') as f:
            json.dump(keys_data, f, indent=4)
            
        print(f"  - Clé stockée avec succès dans {keys_file}")
        return True
    
    except Exception as e:
        print(f"ERREUR lors du stockage du message chiffré original: {e}")
        return False

def get_original_encrypted_k_msg(message_id):
    """
    Récupère le message chiffré original (encrypted_k_msg) par ID de message.
    
    Args:
        message_id (str): L'ID du message
        
    Returns:
        bytes: Le message chiffré original ou None si non trouvé
    """
    keys_file = "challenge_keys.json"
    
    try:
        print(f"DEBUG - get_original_encrypted_k_msg:")
        print(f"  - ID du message recherché: {message_id}")
        
        if not os.path.exists(keys_file):
            print(f"  - Fichier {keys_file} n'existe pas")
            return None
            
        with open(keys_file, 'r') as f:
            keys_data = json.load(f)
            print(f"  - Fichier {keys_file} chargé: {len(keys_data)} clés")
            
        if message_id in keys_data:
            encoded_key = keys_data[message_id]
            result = base64.b64decode(encoded_key)
            print(f"  - Clé trouvée pour {message_id}, taille: {len(result)} octets")
            return result
        
        print(f"  - Aucune clé trouvée pour {message_id}")
        return None
    
    except Exception as e:
        print(f"ERREUR lors de la récupération du message chiffré original: {e}")
        return None 