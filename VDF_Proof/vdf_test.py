import random
import time
import math
import secrets

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

    # Generate N > secret_int (at least 257 bits)
    while True:
        p, q = generate_large_primes(bits=129)  # 129-bit primes → N is 258 bits
        N = p * q
        if N > secret_int:
            break

    print(f"DEBUG - N = {N} (bits: {N.bit_length()})")
    print(f"DEBUG - secret_int bits: {secret_int.bit_length()}")

    # Estimate iteration time
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

    # Compute a = 2^(2^T) mod N
    a = 2
    for _ in range(T_iterations):
        a = pow(a, 2, N)

    # Encode the secret: C = (secret_int + a) mod N
    C = (secret_int + a) % N
    return (N, T_iterations, C)

def solve_time_lock_puzzle(N, T, C):
    a = 2
    for _ in range(T):
        a = pow(a, 2, N)

    secret_int = (C - a) % N
    secret_bytes = secret_int.to_bytes(32, byteorder='big')  # Force 32 bytes
    return secret_bytes

def generate_challenge_key():
    return secrets.token_bytes(32)

# Test
key = generate_challenge_key()
print("Original key:", key.hex())

N, T, C = generate_time_lock_puzzle(key, 10)

recovered_key = solve_time_lock_puzzle(N, T, C)
print("Recovered key:", recovered_key.hex())

assert key == recovered_key, "Keys don't match!"
print("Success! Keys match.")