# advanced authentication sequence
import random
import secrets
import string

# per request csrf token

def chaining_demo():
    server_token1 = generate_32_length_number()
    server_token2 = generate_32_length_number()
    server_token3 = generate_32_length_number()

    server_exposed_token = generate_32_length_number()

    print(f"Server exposed token:   {server_exposed_token}")

    user_token1 = generate_32_length_number()
    user_token2 = generate_32_length_number()
    user_token3 = generate_32_length_number()

    # xor the user_token1 with server exposed token
    OTB1 = user_token1 ^ server_exposed_token

    # xor otb 1 with user token 2
    OTB2 = OTB1 ^ user_token2

    # xor otb 2 with user token 3
    OTB3 = OTB2 ^ user_token3

    print(f"User final token:       {OTB3}")

    # server side
    SOTB1 = server_token1 ^ server_exposed_token
    SOTB2 = SOTB1 ^ server_token2
    SOTB3 = SOTB2 ^ server_token3
    print(f"Server final token:     {SOTB3}")

    # final csrf token given to user
    final_token = SOTB3 ^ OTB3
    print(f"Final AAS token:        {final_token}")

    # to check
    break_layer1 = final_token ^ OTB3 # this will give the server final token

    break_layer2 = break_layer1 ^ server_token1
    break_layer3 = break_layer2 ^ server_token2
    break_layer4 = break_layer3 ^ server_token3

    print(f"Checked:                {break_layer4}")


    # pass user final token as csrf

    # on server side
    layer1 = OTB3 ^ user_token1
    print(f"Layer1                  {layer1}")

    layer2 = layer1 ^ user_token2
    print(f"Layer2                  {layer2}")

    layer3 = layer2 ^ user_token3
    print(f"Layer3                  {layer3}")


def generate_32_length_number():
    return int(''.join(random.choices(string.digits, k=128)))

def encrypt_action_token(server_token_1, server_token_2, server_middle_token):
    # will xor server_token1 with server middle token
    new_server_token_1 = server_token_1 ^ server_middle_token
    new_server_token_2 = server_token_2 ^ server_middle_token
    return {
        "New Server Token 1": new_server_token_1,
        "New Server Token 2": new_server_token_2,
    }

def verify_user_token(user_token_1, user_token_2, server_token1, server_token2):
    # xor back and return True if both token xor back to same server middle token
    server_middle_token1 = user_token_1 ^ server_token1
    server_middle_token2 = user_token_2 ^ server_token2

    return {
        "Server Middle 1": server_middle_token1,
        "Server Middle 2": server_middle_token2,
    }

print("Stage Alpha")
print("----------------------------------------------------------------------")


# server side token 1
server_first_code = generate_32_length_number()
print(f"Server first code:      {server_first_code}")

# server side token 2
server_second_code = generate_32_length_number()
print(f"Server second code:     {server_second_code}")

# server exposed middle token
server_middle_token = generate_32_length_number()
print(f"Server exposed code:    {server_middle_token}")

# first generate secret code for user



print("\n")
print("Stage Bravo")
print("----------------------------------------------------------------------")
# return server encrypted toekn
new_server_tokens = encrypt_action_token(server_token_1=server_first_code,
                                         server_token_2=server_second_code,
                                         server_middle_token=server_middle_token)
new_server_token1 = new_server_tokens["New Server Token 1"]
new_server_token2 = new_server_tokens["New Server Token 2"]
print(f"New server token 1:     {new_server_token1}")
print(f"New server token 2:     {new_server_token2}")

# the result of the xor between server side and middle tokens will be the 2 user keys
user_first_code = new_server_token1
print(f"User first code:        {user_first_code}")

# second generate secret code for user
user_second_code = new_server_token2
print(f"User second code:       {user_second_code}")

print("\n")
print("Stage Omega")
print("----------------------------------------------------------------------")
# return server encrypted toekn
new_server_middle_token = verify_user_token(user_token_1=user_first_code,
                                      user_token_2=user_second_code,
                                      server_token1=server_first_code,
                                      server_token2=server_second_code)
new_server_token1 = new_server_middle_token["Server Middle 1"]
new_server_token2 = new_server_middle_token["Server Middle 1"]
print(f"New server middle 1:     {new_server_token1}")
print(f"New server middle 2:     {new_server_token2}")

print("\n")
chaining_demo()

# bcrypt test

import bcrypt

password = 'password1'

bytes = password.encode('utf-8')
salt = bcrypt.gensalt()

hash = bcrypt.hashpw(bytes, salt)

print(hash)
print(len(salt))

# description
#Stage alpha

# user will be issued a public key called userpubliccode1 (one time pass)

# 2 server side codes will be generated, servercode1 and servercode2
# 1 server middleware code will be issued, servermiddle

#Stage bravo

# xor servermiddle with userpubliccode1 to produce servercode1
# xor result from above with servermiddle to produce servercode2
# this will produce servercode1 and servercode2 respectively which will be given to the user

#Stage omega

# check if the usercode1 xor with the servercode1 xor with servermiddle
# check if the usercode2 xor with the servercode2 xor with servermiddle
# if both cases exist

# allow action to take place




