# Block Cipher Security Analyzer
# Hibaq Abdi Muktar - BIT3208 Advanced Cryptography

from collections import Counter
import random

# Simple substitution-permutation network (toy model)
sbox = {0:14, 1:4, 2:13, 3:1}
inv_sbox = {v: k for k, v in sbox.items()}

def substitute(value):
    return sbox[value % 4]

def permute(value):
    return int(str(value)[::-1])

def encrypt(plaintext, key):
    mixed = plaintext ^ key
    substituted = substitute(mixed)
    permuted = permute(substituted)
    return permuted

# Avalanche Effect Testing
def avalanche_test(p1, p2, key):
    c1 = encrypt(p1, key)
    c2 = encrypt(p2, key)
    diff = c1 ^ c2
    return diff

# Frequency Distribution
def frequency_analysis(data):
    return Counter(data)

# --- Demo Run ---
p1 = 6
p2 = 7
key = 6

print("Avalanche Effect Difference:", avalanche_test(p1, p2, key))

dataset = [encrypt(random.randint(0, 15), key) for _ in range(50)]
print("Frequency Distribution:", frequency_analysis(dataset))
