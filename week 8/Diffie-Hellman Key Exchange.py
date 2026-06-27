# Diffie-Hellman Key Exchange Implementation

# Step 1: Accept public values
p = int(input("Enter Public Prime (p): "))
g = int(input("Enter Generator (g): "))

# Step 2: Users choose private keys
alice_private = int(input("Enter Alice Secret Key: "))
bob_private = int(input("Enter Bob Secret Key: "))

# Step 3: Generate public keys
alice_public = (g ** alice_private) % p
bob_public = (g ** bob_private) % p

print("\nGenerated Public Keys")
print("Alice Public Key:", alice_public)
print("Bob Public Key:", bob_public)

# Step 4: Compute shared secret
alice_shared_secret = (bob_public ** alice_private) % p
bob_shared_secret = (alice_public ** bob_private) % p

# Step 5: Verify both secrets are equal
print("\nShared Secrets")
print("Alice Shared Secret:", alice_shared_secret)
print("Bob Shared Secret:", bob_shared_secret)

if alice_shared_secret == bob_shared_secret:
    print("\nKey Exchange Successful!")
    print("Shared Secret:", alice_shared_secret)
else:
    print("\nKey Exchange Failed!")