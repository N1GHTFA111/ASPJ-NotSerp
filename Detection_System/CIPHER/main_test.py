import random
import secrets
import string

plaintext = "test1test1"
N = len(plaintext)
key = ''.join(random.choices(string.ascii_lowercase + string.digits, k=N))

#ord() returns ascii value for each character in string

xor_value = [(ord(a) ^ ord(b)) for a,b in zip(plaintext, key)]

# cipher_text = [chr(a) for a in xor_value]
cipher_text = [chr(ord(a) ^ ord(b)) for a,b in zip(plaintext, key)]

plaintext = [chr(ord(a) ^ ord(b)) for a,b in zip(cipher_text, key)]

print(''.join(cipher_text))

print(''.join(plaintext))

pt = 1000
key_val = 5601

ciphertext = pt ^ key_val

print(ciphertext)

plain = ciphertext ^ key_val

print(plain)
