import random
import time
import math

def is_coprime(a, b):
    return math.gcd(a, b) == 1

def generate_time_lock_puzzle(secret, T_desired_seconds):
    # 1. Générer N = p*q (comme en RSA)
    p = 104723  
    q = 104729
    N = p * q
    phi_N = (p - 1) * (q - 1)
    
    # Vérifier que secret et N sont copremiers
    if not is_coprime(secret, N):
        raise ValueError("secret et N doivent être copremiers")

    # 2. Estimer T_iterations
    # Mesurer le temps d'une itération
    test_iterations = 1000
    x = 12345
    start = time.time()
    for _ in range(test_iterations):
        x = pow(x, 2, N)
    time_per_iter = (time.time() - start) / test_iterations
    T_iterations = int(T_desired_seconds / time_per_iter)

    # 3. Calculer a = 2^(2^T) mod N rapidement grâce à phi(N)
    # Au lieu de faire T squarings séquentiels, on peut calculer directement :
    # 2^(2^T) mod N = 2^(2^T mod phi(N)) mod N
    exponent = pow(2, T_iterations, phi_N)  # Calcule 2^T mod phi(N) rapidement
    a = pow(2, exponent, N)  # Calcule 2^(2^T mod phi(N)) mod N rapidement
    
    # 4. Calculer C = secret * a mod N
    C = (secret * a) % N

    return (N, T_iterations, C)

def solve_time_lock_puzzle(N, T, C):
    # Le receiver doit faire les T squarings séquentiels car il ne connaît pas phi(N)
    a = 2
    start_time = time.time()
    for i in range(T):
        a = pow(a, 2, N)
        #if i % 100000 == 0:
        #    print(f"\r[Receiver] Progression: {i}/{T} itérations", end="", flush=True)
    print(f"\n[Receiver] Terminé en {time.time()-start_time:.2f}s")
    
    # Retrouver le secret en divisant C par a modulo N
    # On utilise l'inverse modulaire de a pour la division
    a_inv = pow(a, -1, N)
    secret = (C * a_inv) % N
    return secret

# Test
secret = 42
T_seconds = 60
print(f"\n[Sender] Création du puzzle (secret={secret}, temps={T_seconds}s)")
N, T, C = generate_time_lock_puzzle(secret, T_seconds)
print(f"[Sender] N={N}, T={T}, C={C}")

print("\n[Receiver] Résolution...")
found_secret = solve_time_lock_puzzle(N, T, C)

print(f"\nValidation: {secret == found_secret}")
print(f"Secret: {secret}, Trouvé: {found_secret}")