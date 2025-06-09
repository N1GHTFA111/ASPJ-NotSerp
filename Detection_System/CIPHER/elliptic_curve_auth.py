import random

import primePy.primes
from primePy import primes


# using the secp256k1 curve
# y^2 = x^3 + 7

def get_y_coord(x):
    y_square = (x ** 3) + 7
    y = y_square ** 0.5
    return y


def get_base_point():
    # first choose a base point G on the curve
    point_g_x_coord = 7
    point_g_y_coord = get_y_coord(point_g_x_coord)

    return point_g_x_coord, point_g_y_coord


def generate_private_key():
    # select a large prime number which is our private key (d) and kept secret (will be stored in usermodel
    private_key = random.choice(primePy.primes.between(1, 10))
    return private_key


def key_generation(privatekey):
    # first choose a base point G on the curve
    point_g_x_coord = 7
    point_g_y_coord = get_y_coord(point_g_x_coord)

    # select a large prime number which is our private key (d) and kept secret (will be stored in usermodel
    private_key = privatekey

    # compute public key (Q) by multiplying G with d
    public_key = (point_g_x_coord * private_key, point_g_y_coord * private_key)

    return public_key

# digital signature

def encryption(base_point, hash, privateK):
    # random number k
    k = random.randint(10, 100)

    # find the point C on the curve by multiplying the base point G with k
    C = (base_point[0] * k, base_point[1] * k)

    x_coord_c = C[0]  # x coordinate of C typically used as the shared secret key

    # # calculate shared secret
    signature = (k ** -1) * (hash + x_coord_c * privateK) % 5

    print(f"Shared secret: {x_coord_c}")



    return {"Shared Secret": x_coord_c, "Signature": signature}


# def validate(shared_secret, x_coord_of_c):
#     # shared_secret_key = privateKey * C_x_coord
#     shared_secret_key = shared_secret ** -1
#     print(f"Shared secret: {shared_secret_key}")
#     C_prime_x_coord = (code*shared_secret_key)*x_coord_of_c+()
#     decrypted = encrypted_message * shared_secret_key
#     return decrypted

def decryption(signature_to_check, hash, publickey, x_coord_C, base_point):
    signature_prime = (signature_to_check**-1) % 5
    print(f"s_prime: {signature_prime}")
    # C_prime_x_coord = (hash*signature_prime) * base_point[0] + (base_point[0]*signature_to_check)*publickey

    # u1 = hash * signature_prime % 5
    # u2 = x_coord_C * signature_prime
    #
    # point_c_prime_x_coord = u1 * base_point[0] + u2 * publickey[1]
    point_c_prime_x_coord = (hash*signature_prime)*base_point[0]+(x_coord_C*signature_prime)*publickey[0]

    return {"Signature returned": {point_c_prime_x_coord}}


base_point = get_base_point()
private_key = generate_private_key()
public_key = key_generation(private_key)

message_code = 1400
encrypted_message = encryption(base_point, message_code, private_key)
print(f"Encrypted signature: {encrypted_message['Signature']}")

decrypted_msg = decryption(publickey=public_key,
                           signature_to_check=encrypted_message["Signature"],
                           x_coord_C=encrypted_message['Shared Secret'],
                           hash=message_code,
                           base_point=base_point)

print(f"Decrypted message: {decrypted_msg}")
