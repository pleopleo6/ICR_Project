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

def generate_large_primes(bits=129):  # 129-bit primes → N is 258 bits (to ensure N > 256-bit secret)
    """Generate large primes p and q."""
    while True:
        p = secrets.randbits(bits)
        if p > 1 and is_prime(p):
            break
    while True:
        q = secrets.randbits(bits)
        if q > 1 and is_prime(q) and q != p:
            break
    return p, q

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_time_lock_puzzle(secret_bytes, T_desired_seconds=10):
    secret_int = int.from_bytes(secret_bytes, byteorder='big')

    # Generate primes until N > secret_int (N must be at least 257 bits)
    while True:
            p, q = generate_large_primes(bits=130)  # 130-bit primes → N is 260 bits
            N = p * q
            phi_N = (p - 1) * (q - 1)  # Compute Euler's totient function
            if N > secret_int:
                break

    print(f"DEBUG - N = {N} (bits: {N.bit_length()})")
    print(f"DEBUG - secret_int bits: {secret_int.bit_length()}")


    if N <= secret_int:
        raise ValueError("N must be larger than the secret!")

    # Estimate iteration time (for setting T)
    test_iterations = 1000
    x = 2
    start_time = time.time()
    for _ in range(test_iterations):
        x = pow(x, 2, N)
    elapsed_time = time.time() - start_time
    time_per_iter = elapsed_time / test_iterations

    print(f"DEBUG - Time per iteration: {time_per_iter:.6f} seconds")

    T_iterations = max(1, int(T_desired_seconds / time_per_iter))
    print(f"DEBUG - Iterations needed: {T_iterations}")

    # Compute a = 2^(2^T mod φ(N)) mod N (using the trapdoor: φ(N))
    exponent = pow(2, T_iterations, phi_N)
    a = pow(2, exponent, N)

    # Encode the secret: C = (secret_int + a) mod N
    C = (secret_int + a) % N

    # Return (N, T, C) but NOT phi_N (keep it secret!)
    return (N, T_iterations, C)

def solve_time_lock_puzzle(N, T, C):
    a = 2
    for _ in range(T):
        a = pow(a, 2, N)

    secret_int = (C - a) % N
    secret_bytes = secret_int.to_bytes(32, byteorder='big')  # Force 32 bytes
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