# Differential Cryptanalysis Simulation


# Accept two plaintext inputs
p1 = int(input("Enter first plaintext (integer): "))
p2 = int(input("Enter second plaintext (integer): "))

# Compute difference using XOR
difference = p1 ^ p2

# Display observations
print("Plaintext 1:", p1)
print("Plaintext 2:", p2)
print("Difference (XOR):", difference)

# Observation: small changes in plaintext produce differences
if difference == 0:
    print("No difference detected.")
else:
    print("Difference observed between inputs.")
