
pt_block1 = 1011101110111011
pt_block2 = 1100123412341234
pt_block3 = 1450167817891098

plaintext = str(pt_block1)+str(pt_block2)+str(pt_block3)

iv = 1234567812345678

# round 1
# first xor the IV with pt_block1 to get itb-1
input_text_box1 = iv ^ pt_block1
print(input_text_box1)
# encrypt the itb-1 giving ctb-1

# add 1 (demo encryption)
cipher_text_block1 = input_text_box1 + 1

# round 2
# cbt-1 is xored with pt_block2 to get itb-2
input_text_box2 = cipher_text_block1 ^ pt_block2

# encrypt the itb-2 giving ctb-2
cipher_text_block2 = input_text_box2 + 1

# round 3
# cbt-2 is xored with pt_block3 to get itb-3
input_text_box3 = cipher_text_block2 ^ pt_block3

# encrypt the itb-3 giving ctb-3
cipher_text_block3 = input_text_box3 + 1

ciphertext = str(cipher_text_block1) + str(cipher_text_block2) + str(cipher_text_block3)

print(f"Plaintext : {plaintext}")
print(f"Ciphertext: {ciphertext}")

# decrypt

# round 1
# ctb-1 is decrypted with K giving otb-1
decrypted_output1 = cipher_text_block1 - 1

# otb-1 is xor with iv giving ptb_1
decrypted_plaintext_1 = decrypted_output1 ^ iv
print(decrypted_plaintext_1)
# round 2
# ctb-2 is decrypted with K giving otb-2
decrypted_output2 = cipher_text_block2 - 1

# otb-2 is xor with ctb_1 giving ptb_2
decrypted_plaintext_2 = decrypted_output2 ^ cipher_text_block1
print(decrypted_plaintext_2)
# round 3
# ctb-3 is decrypted with K giving otb-3
decrypted_output3 = cipher_text_block3 - 1

# otb-3 is xor with ctb_2 giving otb-3
decrypted_plaintext_3 = decrypted_output3 ^ cipher_text_block2
print(decrypted_plaintext_3)
decrypted_full_plaintext = str(decrypted_plaintext_1) + str(decrypted_plaintext_2) + str(decrypted_plaintext_3)

print(f"Decrypted plaintext: {decrypted_full_plaintext}")



