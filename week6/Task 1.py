# Simple SPN Implementation (User Input)

# Define S-Box
sbox = {0:14, 1:4, 2:13, 3:1}

# Permutation function
def permute(bits):
    return bits[::-1]  # simple reversal

# SPN encryption
def spn_encrypt(plaintext, key):
    # Round 1: Key mixing
    mixed = plaintext ^ key
    # Substitution
    substituted = sbox[mixed % 4]
    # Permutation
    permuted = int(str(substituted)[::-1])
    return permuted

# --- User Input Section ---
plaintext = int(input("Enter plaintext (integer): "))
key = int(input("Enter key (integer): "))

ciphertext = spn_encrypt(plaintext, key)
print("Ciphertext:", ciphertext)

