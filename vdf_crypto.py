import random
import time
import math
import json
import os
import secrets
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def is_coprime(a, b):
    return math.gcd(a, b) == 1

def generate_time_lock_puzzle(secret_bytes, T_desired_seconds=10):
    """
    Génère un time-lock puzzle pour chiffrer un secret (clé de chiffrement).
    
    Args:
        secret_bytes (bytes): Le secret à chiffrer (doit être convertible en int)
        T_desired_seconds (int): Temps estimé pour résoudre le puzzle
        
    Returns:
        tuple: (N, T_iterations, C) - paramètres du puzzle
    """
    # Convertir les bytes en un integer
    secret = int.from_bytes(secret_bytes, byteorder='big')
    
    # 1. Générer N = p*q (comme en RSA) - petits nombres pour un POC
    p = 104723  
    q = 104729
    N = p * q
    phi_N = (p - 1) * (q - 1)
    
    # Vérifier que secret et N sont copremiers
    if not is_coprime(secret, N):
        # Si non copremiers, ajuster légèrement le secret
        secret += 1
    
    # 2. Estimer T_iterations
    # Pour la démo, on utilise un temps d'itération fixe (plus rapide pour les tests)
    test_iterations = 1000 if T_desired_seconds > 5 else 100
    x = 12345
    start = time.time()
    for _ in range(test_iterations):
        x = pow(x, 2, N)
    time_per_iter = (time.time() - start) / test_iterations
    T_iterations = int(T_desired_seconds / time_per_iter)
    
    # Limiter le nombre d'itérations pour la démo
    T_iterations = min(T_iterations, 500000)
    
    # 3. Calculer a = 2^(2^T) mod N rapidement grâce à phi(N)
    exponent = pow(2, T_iterations, phi_N)
    a = pow(2, exponent, N)
    
    # 4. Calculer C = secret * a mod N
    C = (secret * a) % N

    return (N, T_iterations, C)

def solve_time_lock_puzzle(N, T, C):
    """
    Résout un time-lock puzzle pour retrouver le secret.
    
    Args:
        N (int): Module RSA
        T (int): Nombre d'itérations
        C (int): Valeur chiffrée
        
    Returns:
        bytes: Le secret déchiffré en bytes
    """
    # Le receiver doit faire les T squarings séquentiels
    a = 2
    for i in range(T):
        a = pow(a, 2, N)
    
    # Retrouver le secret en divisant C par a modulo N
    a_inv = pow(a, -1, N)
    secret_int = (C * a_inv) % N
    
    # Convertir l'entier en bytes (32 octets pour une clé ChaCha20)
    secret_bytes = secret_int.to_bytes(32, byteorder='big')
    return secret_bytes

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
    aead = ChaCha20Poly1305(challenge_key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aead.decrypt(nonce, ciphertext, associated_data=None)

def store_challenge_keys(message_id, challenge_key):
    """
    Stocke la clé de défi dans un fichier pour accès rapide.
    
    Args:
        message_id (str): L'ID du message
        challenge_key (bytes): La clé de défi
        
    Returns:
        bool: True si réussi, False sinon
    """
    keys_file = "challenge_keys.json"
    
    try:
        # Charger les clés existantes ou créer une nouvelle structure
        if os.path.exists(keys_file):
            with open(keys_file, 'r') as f:
                try:
                    keys_data = json.load(f)
                except json.JSONDecodeError:
                    keys_data = {}
        else:
            keys_data = {}
        
        # Stocker la clé encodée en base64
        import base64
        keys_data[message_id] = base64.b64encode(challenge_key).decode('utf-8')
        
        # Écrire dans le fichier
        with open(keys_file, 'w') as f:
            json.dump(keys_data, f, indent=4)
            
        return True
    
    except Exception as e:
        print(f"Erreur lors du stockage de la clé de défi: {e}")
        return False

def get_challenge_key(message_id):
    """
    Récupère une clé de défi par ID de message.
    
    Args:
        message_id (str): L'ID du message
        
    Returns:
        bytes: La clé de défi ou None si non trouvée
    """
    keys_file = "challenge_keys.json"
    
    try:
        if not os.path.exists(keys_file):
            return None
            
        with open(keys_file, 'r') as f:
            keys_data = json.load(f)
            
        if message_id in keys_data:
            import base64
            return base64.b64decode(keys_data[message_id])
        
        return None
    
    except Exception as e:
        print(f"Erreur lors de la récupération de la clé de défi: {e}")
        return None 