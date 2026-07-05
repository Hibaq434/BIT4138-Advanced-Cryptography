#!/usr/bin/env python3
"""
==============================================================================
RSA SECURITY SYSTEM
==============================================================================
A single-file, menu-driven educational RSA cryptography demonstration.

Implements, from scratch, using only the Python standard library:
    - Miller-Rabin probabilistic primality testing
    - Random prime generation
    - Extended Euclidean Algorithm / modular inverse
    - RSA key pair generation
    - RSA encryption / decryption (character by character)
    - SHA-256 based digital signatures and verification
    - A simple two-party "secure chat" simulation (Alice <-> Bob)
    - A demonstration of why small RSA primes are insecure

Run with:
    python rsa_security_system.py

Author: Generated for educational / coursework purposes.
==============================================================================
"""

import random
import hashlib
import time
import datetime
import sys
import os

# --------------------------------------------------------------------------
# COLORAMA SETUP
# --------------------------------------------------------------------------
# colorama gives us cross-platform coloured terminal text. We try to import
# it, and if it isn't installed we fall back to plain (uncoloured) strings
# so the program still runs without crashing.
# --------------------------------------------------------------------------
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False

    # Minimal stand-ins so the rest of the code can reference Fore.XXX safely
    class _NoColor:
        def __getattr__(self, _name):
            return ""

    Fore = _NoColor()
    Style = _NoColor()


def c_cyan(text):
    """Return text coloured cyan (used for headings)."""
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}"


def c_green(text):
    """Return text coloured green (used for successful operations)."""
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"


def c_yellow(text):
    """Return text coloured yellow (used for warnings)."""
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"


def c_red(text):
    """Return text coloured red (used for errors)."""
    return f"{Fore.RED}{text}{Style.RESET_ALL}"


# --------------------------------------------------------------------------
# GENERAL OUTPUT HELPERS
# --------------------------------------------------------------------------
def print_heading(title):
    """Print a neatly formatted, coloured section heading."""
    line = "=" * 70
    print(c_cyan(f"\n{line}"))
    print(c_cyan(f"{title.center(70)}"))
    print(c_cyan(f"{line}"))


def print_subheading(title):
    """Print a smaller coloured subheading."""
    print(c_cyan(f"\n--- {title} ---"))


def print_table_row(col1, col2, col3="", widths=(15, 15, 15)):
    """Print a neatly aligned 2 or 3 column table row."""
    w1, w2, w3 = widths
    if col3 == "":
        print(f"{str(col1):<{w1}}{str(col2):<{w2}}")
    else:
        print(f"{str(col1):<{w1}}{str(col2):<{w2}}{str(col3):<{w3}}")


def pause():
    """Wait for the user before returning to the menu."""
    input(c_yellow("\nPress ENTER to return to the main menu..."))


# ==============================================================================
# PART F (CORE) - MILLER-RABIN PRIMALITY TEST
# ==============================================================================
def is_probable_prime(n, k=20):
    """
    Miller-Rabin probabilistic primality test.

    Returns True if 'n' is *probably* prime (probability of a false positive
    is at most 4^(-k)), and False if 'n' is definitely composite.
    """
    # Handle small and trivial cases directly.
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # Write n - 1 as 2^s * d with d odd.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Run k rounds of the Miller-Rabin witness test.
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # Modular exponentiation: a^d mod n
        if x == 1 or x == n - 1:
            continue  # This witness does not prove compositeness; try again.

        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False  # 'a' is a witness that n is composite.

    return True  # n passed all k rounds: probably prime.


def generate_prime(bits):
    """
    Generate a random probable prime number with the given bit length,
    using Miller-Rabin to test candidates.
    """
    if bits < 2:
        raise ValueError("Bit length must be at least 2.")

    while True:
        # Force the top bit (so the number has the desired bit length) and
        # the bottom bit (so the number is odd) to be 1.
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


# ==============================================================================
# EXTENDED EUCLIDEAN ALGORITHM / MODULAR INVERSE
# ==============================================================================
def gcd(a, b):
    """Standard Euclidean algorithm for greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.

    Returns a tuple (g, x, y) such that:
        a*x + b*y = g = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def mod_inverse(e, phi):
    """
    Compute the modular multiplicative inverse of 'e' modulo 'phi' using
    the Extended Euclidean Algorithm. This gives us the RSA private
    exponent 'd' such that (e * d) mod phi == 1.
    """
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist (e and phi are not coprime).")
    return x % phi


# ==============================================================================
# PART A - RSA KEY GENERATION
# ==============================================================================
def choose_public_exponent(phi):
    """
    Choose a valid public exponent 'e' such that 1 < e < phi and
    gcd(e, phi) == 1. We start from the common default 65537 and search
    upward (wrapping if necessary) until we find a coprime value.
    """
    e = 65537 if phi > 65537 else 3
    if e >= phi:
        e = 3

    while gcd(e, phi) != 1:
        e += 2  # Keep e odd; even numbers > 2 can never be coprime to phi.
        if e >= phi:
            e = 3  # Wrap around and try again from a small odd number.

    return e


def generate_keypair(bits=128, verbose=True):
    """
    Generate a full RSA key pair.

    Steps:
        1. Generate two distinct primes p and q using Miller-Rabin.
        2. Compute the modulus n = p * q.
        3. Compute Euler's totient phi(n) = (p-1)(q-1).
        4. Choose a public exponent e coprime to phi(n).
        5. Compute the private exponent d = e^-1 mod phi(n) via the
           Extended Euclidean Algorithm.

    Returns a dictionary containing all generated values plus the time
    taken to generate the keys.
    """
    start_time = time.time()

    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:  # Ensure p and q are distinct primes.
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = choose_public_exponent(phi)
    d = mod_inverse(e, phi)

    elapsed = time.time() - start_time

    keys = {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e": e,
        "d": d,
        "elapsed": elapsed,
        "public_key": (e, n),
        "private_key": (d, n),
    }

    if verbose:
        display_keypair(keys)

    return keys


def display_keypair(keys):
    """Nicely display a generated RSA key pair."""
    print_subheading("Generated RSA Key Material")
    print(f"Prime P              : {keys['p']}")
    print(f"Prime Q              : {keys['q']}")
    print(f"Modulus (n)          : {keys['n']}")
    print(f"Euler Totient phi(n) : {keys['phi']}")
    print(c_green(f"Public Key  (e, n)   : {keys['public_key']}"))
    print(c_green(f"Private Key (d, n)   : {keys['private_key']}"))
    print(f"Execution Time       : {keys['elapsed']:.4f} seconds")


def prompt_key_bits():
    """Ask the user how many bits per prime to use, with a sane default."""
    raw = input(
        "Enter bit-length per prime (default 128, larger = slower & more secure): "
    ).strip()
    if raw == "":
        return 128
    try:
        bits = int(raw)
        if bits < 8:
            print(c_yellow("Bit length too small; using minimum of 8."))
            return 8
        return bits
    except ValueError:
        print(c_yellow("Invalid input; using default of 128 bits."))
        return 128


# ==============================================================================
# PART B - RSA ENCRYPTION
# ==============================================================================
def rsa_encrypt_int(m, e, n):
    """Encrypt a single integer message block m using the public key (e, n)."""
    return pow(m, e, n)


def rsa_decrypt_int(c, d, n):
    """Decrypt a single integer ciphertext block c using the private key (d, n)."""
    return pow(c, d, n)


def encrypt_message(message, e, n):
    """
    Encrypt a plaintext message character-by-character using RSA.

    Each character is converted to its ASCII value, then encrypted
    individually as m^e mod n. Displays a formatted table of the process
    and returns the list of encrypted integers.
    """
    print_subheading("Original Message")
    print(message)

    print_subheading("Encryption Table")
    print_table_row("Character", "ASCII", "Encrypted", widths=(15, 10, 20))
    print("-" * 45)

    ciphertext = []
    for ch in message:
        ascii_val = ord(ch)
        enc_val = rsa_encrypt_int(ascii_val, e, n)
        ciphertext.append(enc_val)

        display_char = "SPACE" if ch == " " else ch
        print_table_row(display_char, ascii_val, enc_val, widths=(15, 10, 20))

    print_subheading("Encrypted Ciphertext")
    print(ciphertext)

    return ciphertext


# ==============================================================================
# PART C - RSA DECRYPTION
# ==============================================================================
def decrypt_message(ciphertext, d, n):
    """
    Decrypt a list of RSA-encrypted integers back into the original
    plaintext message, character by character. Displays a formatted
    table of the process and returns the recovered string.
    """
    print_subheading("Decryption Table")
    print_table_row("Encrypted Value", "ASCII", "Character", widths=(20, 10, 15))
    print("-" * 45)

    recovered_chars = []
    for enc_val in ciphertext:
        ascii_val = rsa_decrypt_int(enc_val, d, n)
        # Guard against out-of-range values (e.g. from corrupted input).
        try:
            ch = chr(ascii_val)
        except (ValueError, OverflowError):
            ch = "?"
        recovered_chars.append(ch)

        display_char = "SPACE" if ch == " " else ch
        print_table_row(enc_val, ascii_val, display_char, widths=(20, 10, 15))

    recovered_message = "".join(recovered_chars)
    print_subheading("Recovered Message")
    print(recovered_message)

    return recovered_message


# ==============================================================================
# PART D & E - DIGITAL SIGNATURES
# ==============================================================================
def hash_message(message):
    """Compute the SHA-256 hash of a message and return the hex digest."""
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def sign_message(message, d, n):
    """
    Create a digital signature for 'message' using the RSA private key.

    The SHA-256 hash of the message is computed and converted to an
    integer. Because the hash (256 bits) may be larger than the RSA
    modulus n for small demonstration keys, the hash integer is reduced
    modulo n before signing (a common simplification for teaching
    purposes -- production systems use padding schemes such as PSS
    together with sufficiently large keys instead of a plain mod
    reduction).

    Returns (hash_hex, hash_int_mod_n, signature).
    """
    hash_hex = hash_message(message)
    hash_int = int(hash_hex, 16)
    hash_int_mod_n = hash_int % n

    signature = pow(hash_int_mod_n, d, n)  # Sign with the private exponent.

    return hash_hex, hash_int_mod_n, signature


def verify_signature(message, signature, e, n, expected_hash_mod_n):
    """
    Verify an RSA digital signature using the public key.

    Recomputes the SHA-256 hash of the message, reduces it modulo n
    (matching the signing step), recovers the signed value using the
    public exponent, and compares the two.

    Returns (recovered_hash_mod_n, original_hash_mod_n, is_valid).
    """
    hash_hex = hash_message(message)
    hash_int = int(hash_hex, 16)
    hash_int_mod_n = hash_int % n

    recovered = pow(signature, e, n)  # "Undo" the signature with e.

    is_valid = (recovered == hash_int_mod_n == expected_hash_mod_n)

    return recovered, hash_int_mod_n, is_valid


# ==============================================================================
# MENU OPTION 1: GENERATE RSA KEYS
# ==============================================================================
def menu_generate_keys(state):
    print_heading("PART A - RSA KEY GENERATION")
    bits = prompt_key_bits()
    keys = generate_keypair(bits=bits)
    state["keys"] = keys
    print(c_green("\nKeys generated and stored for use in other menu options."))
    pause()


# ==============================================================================
# MENU OPTION 2: ENCRYPT MESSAGE
# ==============================================================================
def menu_encrypt_message(state):
    print_heading("PART B - ENCRYPTION")

    if state.get("keys") is None:
        print(c_yellow("No keys found. Generating a fresh key pair (128-bit primes)..."))
        state["keys"] = generate_keypair(bits=128)

    keys = state["keys"]
    message = input("Enter the plaintext message to encrypt: ")

    if message == "":
        print(c_red("Message cannot be empty."))
        pause()
        return

    ciphertext = encrypt_message(message, keys["e"], keys["n"])
    state["last_message"] = message
    state["last_ciphertext"] = ciphertext
    print(c_green("\nMessage successfully encrypted."))
    pause()


# ==============================================================================
# MENU OPTION 3: DECRYPT MESSAGE
# ==============================================================================
def menu_decrypt_message(state):
    print_heading("PART C - DECRYPTION")

    if state.get("keys") is None:
        print(c_red("No keys available. Please generate keys first (Option 1)."))
        pause()
        return

    keys = state["keys"]

    if state.get("last_ciphertext"):
        use_last = input(
            "Use the most recently encrypted ciphertext? (y/n): "
        ).strip().lower()
        if use_last == "y":
            ciphertext = state["last_ciphertext"]
            decrypt_message(ciphertext, keys["d"], keys["n"])
            pause()
            return

    raw = input(
        "Enter ciphertext as comma-separated integers (e.g. 3955,16231,...): "
    ).strip()

    try:
        ciphertext = [int(x.strip()) for x in raw.split(",") if x.strip() != ""]
        if not ciphertext:
            raise ValueError("No values provided.")
    except ValueError:
        print(c_red("Invalid ciphertext format. Please enter comma-separated integers."))
        pause()
        return

    decrypt_message(ciphertext, keys["d"], keys["n"])
    pause()


# ==============================================================================
# MENU OPTION 4: SIGN MESSAGE
# ==============================================================================
def menu_sign_message(state):
    print_heading("PART D - DIGITAL SIGNATURE")

    if state.get("keys") is None:
        print(c_yellow("No keys found. Generating a fresh key pair (128-bit primes)..."))
        state["keys"] = generate_keypair(bits=128)

    keys = state["keys"]
    message = input("Enter the message to sign: ")

    if message == "":
        print(c_red("Message cannot be empty."))
        pause()
        return

    hash_hex, hash_mod_n, signature = sign_message(message, keys["d"], keys["n"])

    print_subheading("Original Message")
    print(message)
    print_subheading("SHA-256 Hash")
    print(hash_hex)
    print_subheading("Digital Signature")
    print(signature)

    state["last_signed_message"] = message
    state["last_signature"] = signature
    state["last_hash_mod_n"] = hash_mod_n

    print(c_green("\nMessage successfully signed."))
    pause()


# ==============================================================================
# MENU OPTION 5: VERIFY SIGNATURE
# ==============================================================================
def menu_verify_signature(state):
    print_heading("PART E - VERIFY SIGNATURE")

    if state.get("keys") is None:
        print(c_red("No keys available. Please generate keys first (Option 1)."))
        pause()
        return

    keys = state["keys"]

    if state.get("last_signature") is not None:
        use_last = input(
            "Use the most recently signed message and signature? (y/n): "
        ).strip().lower()
        if use_last == "y":
            message = state["last_signed_message"]
            signature = state["last_signature"]
            expected_hash_mod_n = state["last_hash_mod_n"]
            recovered, original, is_valid = verify_signature(
                message, signature, keys["e"], keys["n"], expected_hash_mod_n
            )
            _display_verification(original, recovered, is_valid)
            pause()
            return

    message = input("Enter the message whose signature you want to verify: ")
    try:
        signature = int(input("Enter the digital signature (integer): ").strip())
    except ValueError:
        print(c_red("Invalid signature format; it must be an integer."))
        pause()
        return

    # Recompute the expected hash directly (no prior signing step assumed).
    hash_hex = hash_message(message)
    expected_hash_mod_n = int(hash_hex, 16) % keys["n"]

    recovered, original, is_valid = verify_signature(
        message, signature, keys["e"], keys["n"], expected_hash_mod_n
    )
    _display_verification(original, recovered, is_valid)
    pause()


def _display_verification(original_hash, recovered_hash, is_valid):
    """Helper to display the result of a signature verification."""
    print_subheading("Original Hash (mod n)")
    print(original_hash)
    print_subheading("Recovered Hash (mod n)")
    print(recovered_hash)
    print_subheading("Result")
    if is_valid:
        print(c_green("Signature Valid"))
    else:
        print(c_red("Signature Invalid"))


# ==============================================================================
# MENU OPTION 6: MILLER-RABIN PRIME TEST DEMONSTRATION
# ==============================================================================
def menu_miller_rabin_demo(state):
    print_heading("PART F - MILLER-RABIN PRIMALITY TEST")

    print("Testing 10 random numbers for primality using Miller-Rabin...\n")
    print_table_row("Number", "Result", widths=(15, 20, 15))
    print("-" * 35)

    for _ in range(10):
        # Mix of small and moderately large candidates for variety.
        num = random.randint(2, 10_000)
        result = "Probably Prime" if is_probable_prime(num) else "Composite"
        colour = c_green if result == "Probably Prime" else c_red
        print_table_row(num, colour(result), widths=(15, 20, 15))

    pause()


# ==============================================================================
# MENU OPTION 7: RSA SECURE CHAT (ALICE <-> BOB)
# ==============================================================================
CHAT_LOG_FILE = "chat_history.txt"


def _get_or_create_chat_keys(state):
    """Ensure Alice and Bob each have their own RSA key pair."""
    if "alice_keys" not in state or state["alice_keys"] is None:
        print(c_yellow("Generating Alice's key pair..."))
        state["alice_keys"] = generate_keypair(bits=128, verbose=False)
    if "bob_keys" not in state or state["bob_keys"] is None:
        print(c_yellow("Generating Bob's key pair..."))
        state["bob_keys"] = generate_keypair(bits=128, verbose=False)
    return state["alice_keys"], state["bob_keys"]


def _log_chat(sender, recipient, plaintext, ciphertext, recovered):
    """Append a chat exchange to the chat_history.txt log file with a timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(CHAT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {sender} -> {recipient}\n")
        f.write(f"  Plaintext : {plaintext}\n")
        f.write(f"  Ciphertext: {ciphertext}\n")
        f.write(f"  Recovered : {recovered}\n")
        f.write("-" * 60 + "\n")


def menu_secure_chat(state):
    print_heading("PART G - RSA SECURE CHAT SIMULATION")

    alice_keys, bob_keys = _get_or_create_chat_keys(state)

    print(c_green("Alice's Public Key: ") + str(alice_keys["public_key"]))
    print(c_green("Bob's Public Key  : ") + str(bob_keys["public_key"]))
    print(c_yellow(f"\nAll exchanges will be logged to '{CHAT_LOG_FILE}'."))
    print("Type 'exit' at any time to leave the chat simulation.\n")

    while True:
        message = input(c_cyan("Alice types a message to send to Bob: "))
        if message.strip().lower() == "exit":
            print(c_yellow("Exiting secure chat simulation."))
            break
        if message == "":
            print(c_red("Message cannot be empty."))
            continue

        # Alice encrypts using Bob's PUBLIC key.
        ciphertext = [rsa_encrypt_int(ord(ch), bob_keys["e"], bob_keys["n"]) for ch in message]
        print(c_green("\nEncrypted message (sent over the 'network'):"))
        print(ciphertext)

        # Bob decrypts using his own PRIVATE key.
        recovered_chars = [chr(rsa_decrypt_int(c, bob_keys["d"], bob_keys["n"])) for c in ciphertext]
        recovered = "".join(recovered_chars)
        print(c_green("\nBob decrypts the message using his private key:"))
        print(recovered)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(c_yellow(f"[Logged at {timestamp}]\n"))

        _log_chat("Alice", "Bob", message, ciphertext, recovered)

    pause()


# ==============================================================================
# MENU OPTION 8: SMALL PRIME RISK DEMONSTRATION
# ==============================================================================
def factor_small_n(n):
    """
    Naively factor n by trial division. This is only feasible because n
    is deliberately small (built from tiny primes) -- this simulates an
    attacker who can brute-force factor a weak RSA modulus.
    """
    for candidate in range(2, int(n ** 0.5) + 1):
        if n % candidate == 0:
            return candidate, n // candidate
    return None, None  # Should not happen for a valid semiprime n.


def menu_small_prime_demo(state):
    print_heading("PART H - SMALL PRIME RISK DEMONSTRATION")

    print("Generating an intentionally WEAK RSA key pair using 8-bit primes...\n")
    weak_keys = generate_keypair(bits=8, verbose=True)

    print_subheading("Attacker's Perspective")
    print("The attacker only knows the public key (e, n). Let's see how easily")
    print("they can break it by factoring n using simple trial division.\n")

    start_time = time.time()
    factor_p, factor_q = factor_small_n(weak_keys["n"])
    elapsed = time.time() - start_time

    print(f"Recovered Prime P    : {factor_p}")
    print(f"Recovered Prime Q    : {factor_q}")
    print(f"Time to factor n     : {elapsed:.6f} seconds")

    recovered_phi = (factor_p - 1) * (factor_q - 1)
    recovered_d = mod_inverse(weak_keys["e"], recovered_phi)

    print(f"Recovered phi(n)     : {recovered_phi}")
    print(c_red(f"Recovered Private Exponent d: {recovered_d}"))

    if recovered_d == weak_keys["d"]:
        print(c_red("\nThe attacker successfully reconstructed the PRIVATE KEY!"))
    else:
        print(c_yellow("\nNote: a different valid d may be found if multiple e choices exist,"))
        print(c_yellow("but it is equally capable of decrypting any ciphertext."))

    print_subheading("Why This Is Insecure")
    print(
        "With only 8-bit primes, the modulus n is at most 16 bits long -- small\n"
        "enough that even simple trial division can factor it almost instantly.\n"
        "Once an attacker factors n into p and q, they can compute phi(n) and\n"
        "then the private exponent d exactly as the legitimate key owner did,\n"
        "completely breaking the encryption and signature scheme. Real-world RSA\n"
        "requires primes of at least 1024 bits (preferably 2048+ bits total\n"
        "modulus) so that factoring n is computationally infeasible with current\n"
        "technology."
    )

    pause()


# ==============================================================================
# MAIN MENU
# ==============================================================================
MENU_TEXT = """
1. Generate RSA Keys
2. Encrypt Message
3. Decrypt Message
4. Sign Message
5. Verify Signature
6. Miller-Rabin Prime Test
7. RSA Secure Chat
8. Demonstrate Small Prime Risk
9. Exit
"""


def show_main_menu():
    print_heading("RSA SECURITY SYSTEM")
    print(MENU_TEXT)


def main():
    """Main program loop: display the menu and dispatch to the chosen feature."""
    # 'state' persists data (like generated keys) between menu selections.
    state = {
        "keys": None,
        "last_message": None,
        "last_ciphertext": None,
        "last_signed_message": None,
        "last_signature": None,
        "last_hash_mod_n": None,
        "alice_keys": None,
        "bob_keys": None,
    }

    dispatch = {
        "1": menu_generate_keys,
        "2": menu_encrypt_message,
        "3": menu_decrypt_message,
        "4": menu_sign_message,
        "5": menu_verify_signature,
        "6": menu_miller_rabin_demo,
        "7": menu_secure_chat,
        "8": menu_small_prime_demo,
    }

    while True:
        show_main_menu()
        choice = input("Select an option (1-9): ").strip()

        if choice == "9":
            print(c_green("\nExiting RSA Security System. Goodbye!"))
            sys.exit(0)

        handler = dispatch.get(choice)
        if handler is None:
            print(c_red("Invalid selection. Please choose a number between 1 and 9."))
            continue

        try:
            handler(state)
        except KeyboardInterrupt:
            print(c_yellow("\n\nOperation cancelled by user."))
        except Exception as exc:  # noqa: BLE001 - top-level safety net for the whole app
            print(c_red(f"\nAn unexpected error occurred: {exc}"))
            print(c_yellow("Returning to the main menu."))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c_yellow("\n\nProgram interrupted. Goodbye!"))
        sys.exit(0)