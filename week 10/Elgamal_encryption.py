"""
ElGamal Public-Key Cryptosystem — Demonstration
------------------------------------------------
Implements key generation, encryption, and decryption from first
principles (no external crypto libraries), then encrypts/decrypts
five sample messages and explains why the random value k must be
fresh for every encryption.
"""

import random


# ---------------------------------------------------------------------
# 1. Primality testing and prime / safe-prime generation
# ---------------------------------------------------------------------
def is_prime(n, rounds=40):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits):
    """Random odd prime with the given bit length."""
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def generate_safe_prime(bits):
    """
    Returns (p, q) with p = 2q + 1, both prime.
    Safe primes make the multiplicative group Z_p^* have a large
    prime-order subgroup, which is the standard, secure setting
    for ElGamal / Diffie-Hellman style schemes.
    """
    while True:
        q = generate_large_prime(bits - 1)
        p = 2 * q + 1
        if is_prime(p):
            return p, q


def find_generator(p, q):
    """
    Find a generator g of the order-(p-1) group, using the fact that
    for a safe prime p = 2q + 1, the only possible element orders are
    1, 2, q, and p-1. g works if g^2 != 1 and g^q != 1 (mod p).
    """
    while True:
        g = random.randrange(2, p - 1)
        if pow(g, 2, p) == 1:
            continue
        if pow(g, q, p) == 1:
            continue
        return g


# ---------------------------------------------------------------------
# 2. ElGamal key generation, encryption, decryption
# ---------------------------------------------------------------------
class ElGamal:
    def __init__(self, bits=256):
        # Public parameters
        self.p, self.q = generate_safe_prime(bits)
        self.g = find_generator(self.p, self.q)

        # Private key: random x in [2, p-2]
        self.x = random.randrange(2, self.p - 2)
        # Public key: y = g^x mod p
        self.y = pow(self.g, self.x, self.p)

    def public_key(self):
        return (self.p, self.g, self.y)

    def encrypt(self, m):
        """
        Encrypts integer message m (0 < m < p) using a FRESH random k
        for THIS call only.
            c1 = g^k mod p
            c2 = m * y^k mod p
        Returns (c1, c2, k) — k is returned only so this demo can show
        what happens if it's reused; k is normally thrown away after use.
        """
        if not (0 < m < self.p):
            raise ValueError("Message must satisfy 0 < m < p")

        k = random.randrange(2, self.p - 2)   # <-- fresh random k, each call
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.y, k, self.p)) % self.p
        return c1, c2, k

    def decrypt(self, c1, c2):
        """
        s = c1^x mod p  (this equals y^k mod p, the shared secret)
        m = c2 * s^-1 mod p
        """
        s = pow(c1, self.x, self.p)
        s_inv = pow(s, -1, self.p)          # modular inverse (Python 3.8+)
        return (c2 * s_inv) % self.p


# ---------------------------------------------------------------------
# 3. Helpers to turn text messages into integers and back
# ---------------------------------------------------------------------
def encode(text: str) -> int:
    return int.from_bytes(text.encode("utf-8"), "big")


def decode(num: int) -> str:
    length = max(1, (num.bit_length() + 7) // 8)
    return num.to_bytes(length, "big").decode("utf-8")


# ---------------------------------------------------------------------
# 4. Demonstration
# ---------------------------------------------------------------------
def main():
    print("Generating ElGamal keys (this may take a few seconds)...\n")
    eg = ElGamal(bits=256)

    print("=== Public parameters ===")
    print(f"p (prime)      = {eg.p}")
    print(f"g (generator)  = {eg.g}")
    print(f"y (public key) = {eg.y}")
    print(f"x (PRIVATE key, shown only for demo) = {eg.x}\n")

    messages = [
        "Hello World",
        "ElGamal Test",
        "Cryptography 101",
        "Secret Message #4",
        "Individual Assignment",
    ]

    print("=== Encrypting and decrypting 5 messages ===")
    records = []
    for i, msg in enumerate(messages, start=1):
        m_int = encode(msg)
        c1, c2, k = eg.encrypt(m_int)
        decrypted_int = eg.decrypt(c1, c2)
        decrypted_msg = decode(decrypted_int)

        records.append((msg, k, c1, c2, decrypted_msg))

        print(f"\nMessage {i}: {msg!r}")
        print(f"  random k used   : {k}")
        print(f"  ciphertext (c1) : {c1}")
        print(f"  ciphertext (c2) : {c2}")
        print(f"  decrypted       : {decrypted_msg!r}")
        assert decrypted_msg == msg, "Decryption failed!"

    print("\nAll 5 messages decrypted correctly. ✔\n")

    # -------------------------------------------------------------
    # 5. Demonstrate WHY reusing k is dangerous
    # -------------------------------------------------------------
    print("=== Demonstration: danger of reusing k ===")
    m1_text, m2_text = "ATTACK AT DAWN", "RETREAT AT DUSK"
    m1, m2 = encode(m1_text), encode(m2_text)

    k_shared = random.randrange(2, eg.p - 2)  # BAD: same k for both
    c1_a = pow(eg.g, k_shared, eg.p)
    c2_a = (m1 * pow(eg.y, k_shared, eg.p)) % eg.p

    c1_b = pow(eg.g, k_shared, eg.p)   # identical to c1_a
    c2_b = (m2 * pow(eg.y, k_shared, eg.p)) % eg.p

    print(f"Message A: {m1_text!r} -> c1={c1_a}, c2={c2_a}")
    print(f"Message B: {m2_text!r} -> c1={c1_b}, c2={c2_b}")
    print(f"Note c1 is IDENTICAL in both ciphertexts: {c1_a == c1_b}")

    # An eavesdropper, without knowing k or x, can compute the ratio
    # of the two plaintexts directly from the ciphertexts:
    ratio_from_ciphertexts = (c2_a * pow(c2_b, -1, eg.p)) % eg.p
    ratio_from_plaintexts = (m1 * pow(m2, -1, eg.p)) % eg.p

    print(f"\nRatio m1/m2 recovered from ciphertexts alone : {ratio_from_ciphertexts}")
    print(f"Actual ratio m1/m2                           : {ratio_from_plaintexts}")
    print(f"Match: {ratio_from_ciphertexts == ratio_from_plaintexts}")
    print(
        "\n=> Without knowing k or the private key x, an attacker who only\n"
        "   sees the two ciphertexts can compute m1 * m2^-1 mod p. If the\n"
        "   attacker later learns (or guesses) either plaintext, the other\n"
        "   is immediately exposed — the encryption has been broken.\n"
    )


if __name__ == "__main__":
    main()
