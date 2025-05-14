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
    Version simplifiée basée sur VDF_Proof avec p et q variables.
    
    Args:
        secret_bytes (bytes): Le secret à chiffrer (doit être convertible en int)
        T_desired_seconds (int): Temps estimé pour résoudre le puzzle
        
    Returns:
        tuple: (N, T_iterations, C) - paramètres du puzzle
    """
    # Convertir les bytes en un integer
    secret = int.from_bytes(secret_bytes, byteorder='big')
    
    # 1. Générer N = p*q (comme en RSA)
    # Au lieu d'utiliser des valeurs fixes, générer des valeurs variables
    # en fonction du temps de déverrouillage
    
    # Liste de nombres premiers de différentes tailles pour différents niveaux de sécurité
    small_primes = [10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093]
    medium_primes = [50021, 50023, 50033, 50047, 50051, 50053, 50069, 50077, 50087, 50093]
    large_primes = [104723, 104729, 104743, 104759, 104761, 104773, 104779, 104789, 104801, 104803]
    
    # Sélectionner la taille des nombres premiers en fonction du temps de déverrouillage
    if T_desired_seconds <= 30:  # Temps court
        prime_pool = small_primes
    elif T_desired_seconds <= 300:  # Temps moyen
        prime_pool = medium_primes
    else:  # Temps long
        prime_pool = large_primes
    
    # Choisir deux nombres premiers différents aléatoirement
    p = random.choice(prime_pool)
    # Éviter p = q
    remaining_primes = [prime for prime in prime_pool if prime != p]
    q = random.choice(remaining_primes)
    
    N = p * q
    phi_N = (p - 1) * (q - 1)
    
    print(f"DEBUG - Génération VDF avec p={p}, q={q}, N={N}")
    
    # Vérifier que secret et N sont copremiers
    if not is_coprime(secret, N):
        # Si non copremiers, ajuster légèrement le secret
        secret += 1
    
    # 2. Calibrer le nombre d'itérations en fonction du temps souhaité
    # Mesurer le temps d'une itération sur un petit échantillon
    test_iterations = 1000
    x = 12345
    start = time.time()
    for _ in range(test_iterations):
        x = pow(x, 2, N)
    time_per_iter = (time.time() - start) / test_iterations
    
    # Calibration adaptative basée sur le temps de déverrouillage restant
    # ---------------------------------------------------------------------
    
    # Définir des paramètres de calibration
    MIN_ITERATIONS = 1000     # Minimum d'itérations pour assurer un niveau de sécurité de base
    MAX_ITERATIONS = 50000    # Maximum d'itérations pour ne pas surcharger le navigateur
    
    # Appliquer une échelle logarithmique pour les temps d'attente longs
    # Pour les temps courts: facteur élevé (proportion plus grande du temps d'attente)
    # Pour les temps longs: facteur plus faible (proportion plus petite du temps d'attente)
    if T_desired_seconds <= 10:
        # Pour les temps très courts (<=10s), utiliser directement ~25% du temps
        scale_factor = 0.25
    elif T_desired_seconds <= 60:
        # Pour les temps courts (<=1min), utiliser ~15% du temps
        scale_factor = 0.15
    elif T_desired_seconds <= 300:
        # Pour les temps moyens (<=5min), utiliser ~5% du temps
        scale_factor = 0.05
    elif T_desired_seconds <= 3600:
        # Pour les temps longs (<=1h), utiliser ~1% du temps
        scale_factor = 0.01
    else:
        # Pour les temps très longs (>1h), utiliser une formule logarithmique
        # Qui tend vers un pourcentage encore plus faible pour les très longs délais
        scale_factor = 0.01 * (1 - min(0.9, math.log10(T_desired_seconds/3600) * 0.3))
    
    # Calculer le temps de puzzle en fonction du facteur d'échelle
    puzzle_seconds = T_desired_seconds * scale_factor
    
    # Convertir le temps de puzzle en nombre d'itérations
    # avec ajustement pour le facteur navigateur/serveur
    browser_adjustment = 0.7  # Facteur de performance navigateur vs serveur
    T_iterations = int(puzzle_seconds / time_per_iter * browser_adjustment)
    
    # Appliquer les limites de sécurité et de performance
    T_iterations = max(MIN_ITERATIONS, min(T_iterations, MAX_ITERATIONS))
    
    # Calculer la proportion réelle que représente le puzzle par rapport au temps d'attente
    actual_percentage = (T_iterations * time_per_iter / browser_adjustment / T_desired_seconds) * 100
    
    print(f"DEBUG - VDF: Temps d'attente {T_desired_seconds:.2f}s → Puzzle {T_iterations} itérations")
    print(f"DEBUG - VDF: Facteur d'échelle {scale_factor:.4f} ({actual_percentage:.2f}% du temps d'attente)")
    
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
        import base64
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
            import base64
            encoded_key = keys_data[message_id]
            result = base64.b64decode(encoded_key)
            print(f"  - Clé trouvée pour {message_id}, taille: {len(result)} octets")
            return result
        
        print(f"  - Aucune clé trouvée pour {message_id}")
        return None
    
    except Exception as e:
        print(f"ERREUR lors de la récupération du message chiffré original: {e}")
        return None 