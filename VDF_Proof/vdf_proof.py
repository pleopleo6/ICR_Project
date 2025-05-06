import asyncio
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # Import manquant ajouté
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time

class TimeLockPuzzle:
    def __init__(self, delay_seconds: int):
        self.delay = delay_seconds
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.creation_time = datetime.now()
        self.unlock_time = self.creation_time + timedelta(seconds=delay_seconds)

    async def lock(self, message: bytes) -> dict:
        """Verrouille le message avec un délai cryptographique"""
        # 1. Génération d'une clé AES aléatoire
        secret_key = os.urandom(32)
        
        # 2. Chiffrement RSA de la clé AES
        encrypted_key = self.public_key.encrypt(
            secret_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 3. Chiffrement AES-GCM du message
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(secret_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()

        # 4. Simulation du calcul séquentiel (remplacer par chiavdf en production)
        print(f"⏳ Calcul séquentiel en cours ({self.delay}s)...")
        start = time.time()
        sequential_result = await self._compute_sequential_work(self.delay)
        computation_time = time.time() - start

        return {
            "metadata": {
                "created": self.creation_time.isoformat(),
                "unlocks_at": self.unlock_time.isoformat(),
                "computation_time": computation_time
            },
            "encrypted_key": encrypted_key,
            "ciphertext": ciphertext,
            "iv": iv,
            "tag": encryptor.tag,
            "sequential_proof": sequential_result
        }

    async def _compute_sequential_work(self, T: int) -> int:
        """Simule un calcul VDF (à remplacer par chiavdf en production)"""
        dummy = 0
        for i in range(T):
            dummy = (dummy + i) % (2**32)
            if i % 1_000_000 == 0:
                await asyncio.sleep(0)  # Yield pour asyncio
        return dummy

    @staticmethod
    async def unlock(puzzle: dict, private_key: rsa.RSAPrivateKey) -> bytes:
        """Déverrouille le message après le délai"""
        current_time = datetime.now()
        unlock_time = datetime.fromisoformat(puzzle["metadata"]["unlocks_at"])

        if current_time < unlock_time:
            remaining = (unlock_time - current_time).total_seconds()
            raise ValueError(f"Trop tôt ! Déverrouillage possible à {unlock_time} ({remaining:.1f}s restantes)")

        # 1. Déchiffrement de la clé AES
        secret_key = private_key.decrypt(
            puzzle["encrypted_key"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Déchiffrement AES-GCM
        cipher = Cipher(algorithms.AES(secret_key), modes.GCM(puzzle["iv"], puzzle["tag"]), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(puzzle["ciphertext"]) + decryptor.finalize()

async def demo():
    print("=== Time-Lock Puzzle (Python 3.13) ===")
    message = b"Message ultra secret: Launch code = 123456"
    delay = 5  # Délai en secondes

    # 1. Création du puzzle
    puzzle = TimeLockPuzzle(delay)
    print(f"\n🔒 Création à {puzzle.creation_time}")
    print(f"   Déverrouillage à {puzzle.unlock_time}")

    locked_data = await puzzle.lock(message)
    print("\n📦 Puzzle généré :")
    print(f"- Temps de calcul : {locked_data['metadata']['computation_time']:.2f}s")
    print(f"- Taille chiffrée : {len(locked_data['ciphertext'])} bytes")

    # 2. Tentative de déverrouillage immédiat (doit échouer)
    try:
        print("\n⚠️ Tentative de piratage...")
        await TimeLockPuzzle.unlock(locked_data, puzzle.private_key)
    except ValueError as e:
        print(f"   BLOCAGE : {e}")

    # 3. Attente du délai
    print(f"\n⏳ Patientez {delay} secondes...")
    await asyncio.sleep(delay)

    # 4. Déverrouillage légitime
    print("\n🔓 Ouverture du coffre...")
    unlocked = await TimeLockPuzzle.unlock(locked_data, puzzle.private_key)
    print(f"✅ Message : {unlocked.decode()}")

if __name__ == "__main__":
    asyncio.run(demo())