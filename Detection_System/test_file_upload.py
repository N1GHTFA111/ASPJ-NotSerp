import math
import secrets
import string

# Generate a random token with the calculated length
token1 = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))

token2 = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))

# token3 = token1 ^ token2
token3 = token1 + token2

# Print the generated token
print("Generated Token:", token3)