# Mini AES-Inspired Encryption Simulator
# Hibaq Abdi Muktar - BIT3208 Advanced Cryptography

# --- Define S-Box (example, simplified) ---
sbox = {
    0: 14, 1: 4, 2: 13, 3: 1,
    4: 2, 5: 15, 6: 11, 7: 8,
    8: 3, 9: 10, 10: 6, 11: 12,
    12: 9, 13: 7, 14: 5, 15: 0
}

# --- Inverse S-Box for decryption ---
inv_sbox = {v: k for k, v in sbox.items()}

# --- Permutation function (simple bit reversal) ---
def permute(bits):
    return bits[::-1]

# --- Key Mixing (XOR) ---
def key_mix(value, key):
    return value ^ key

# --- Substitution ---
def substitute(value):
    return sbox[value % 16]

def inverse_substitute(value):
    return inv_sbox[value % 16]

# --- Encryption (multi-round SPN) ---
def encrypt(plaintext, key, rounds=2):
    state = plaintext
    for r in range(rounds):
        state = key_mix(state, key)
        state = substitute(state)
        state = int(str(state)[::-1])  # permutation
    return state

# --- Decryption (inverse operations) ---
def decrypt(ciphertext, key, rounds=2):
    state = ciphertext
    for r in range(rounds):
        state = int(str(state)[::-1])  # inverse permutation
        state = inverse_substitute(state)
        state = key_mix(state, key)
    return state

# --- Main Program ---
if __name__ == "__main__":
    plaintext = int(input("Enter plaintext (integer 0-15): "))
    key = int(input("Enter key (integer 0-15): "))
    rounds = int(input("Enter number of rounds: "))

    ciphertext = encrypt(plaintext, key, rounds)
    print("Ciphertext:", ciphertext)

    recovered = decrypt(ciphertext, key, rounds)
    print("Decrypted Plaintext:", recovered)
