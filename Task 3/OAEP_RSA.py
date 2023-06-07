import argparse
import random 
import binascii 
import hashlib

parser = argparse.ArgumentParser()
parser.add_argument('--encrypt_plaintext', type=str, default="")
parser.add_argument('--decrypt_ciphertext', type=str, default="")
args = parser.parse_args()


def fast_mod(base, list):
    mod = list[0]
    exp = list[1]
    remainder = 1
    while exp != 0:
        if exp % 2 == 1:
            remainder = (remainder * base) % mod
        exp = exp >> 1
        base = (base ** 2) % mod
    return remainder


def writer_file(list, output_path):
    with open(output_path, 'w') as file:  
        for i in range(len(list)):
            file.write(str(list[i]) + '\n')
    file.close()

    
def encrypt_plaintext(public_key, input_path, output_path):
    plaintext = []
    with open(input_path, 'r') as file: 
        lines = file.readlines()
        for line in lines:
            plaintext.append(line.strip('\n'))
    file.close()

    print("--Start generate random number of 512 bits")
    r = "{:0512b}".format(random.SystemRandom().getrandbits(512))
    list = []
    list.append(r)
    writer_file(list, './Random_Number.txt')
    print("--Finished\n")

    hash_G = hashlib.sha512()
    hash_H = hashlib.sha512()

    print("--Start padding and encrypting")
    paddedtext = []
    ciphertext = []
    for i in range(len(plaintext)):
        currenttext = plaintext[i]
        currenttext = binascii.b2a_hex(bytes(currenttext, encoding='utf-8'))
        # exclude "0b"
        currenttext = bin(int(currenttext, 16))[2:]

        # padding
        if len(currenttext) > 512:
            print("The message of this line is longer than 512 bits")
            return 
        k1 = 512 - len(currenttext)
        currenttext = currenttext + ('0' * k1)
        
        hash_G.update(r.encode('utf-8'))
        x = "{:0512b}".format(int(currenttext, 2) ^ int(hash_G.hexdigest(), 16))
        hash_H.update(x.encode('utf-8'))
        y = "{:0512b}".format(int(r, 2) ^ int(hash_H.hexdigest(), 16))

        padded = int(x + y, 2)
        paddedtext.append(hex(padded))

        # encrypt x and y, then joint them
        cipher_x = hex(fast_mod(int(x, 2), public_key))[2:]
        cipher_y = hex(fast_mod(int(y, 2), public_key))[2:]
        while len(cipher_x) != 256:
            cipher_x = '0' + cipher_x
        while len(cipher_y) != 256:
            cipher_y = '0' + cipher_y

        cipher = '0x' + cipher_x + cipher_y
        ciphertext.append(cipher)
    
    writer_file(paddedtext, './Message_After_Padding.txt')
    writer_file(ciphertext, output_path)
    print("--Finished")


def decrypt_ciphertext(secret_key, input_path, output_path):
    ciphertext = []
    with open(input_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            ciphertext.append(line.strip('\n'))
    file.close()

    messages = []
    with open('../Task 1/Encryption/Raw_Message.txt', 'r') as file: 
        lines = file.readlines()
        for line in lines:
            messages.append(line.strip('\n'))
    file.close()

    hash_G = hashlib.sha512()
    hash_H = hashlib.sha512()

    print("--Start decrypting")
    plaintext = []
    for i in range(len(ciphertext)):
        # original length of messages
        message = messages[i]
        message = binascii.b2a_hex(bytes(message, encoding='utf-8'))
        message = bin(int(message, 16))[2:]

        # decryption
        currenttext = ciphertext[i][2:]
        cipher_x = int(currenttext[0 : 256], 16)
        cipher_y = int(currenttext[256:], 16)
        x = fast_mod(cipher_x, secret_key)
        x = "{:0512b}".format(x)
        y = fast_mod(cipher_y, secret_key)
        y = "{:0512b}".format(y)

        hash_H.update(x.encode('utf-8'))
        r = "{:0512b}".format(int(y, 2) ^ int(hash_H.hexdigest(), 16))
        hash_G.update(r.encode('utf-8'))
        plain = "{:0512b}".format(int(x, 2) ^ int(hash_G.hexdigest(), 16)) 

        plain = plain[0 : len(message)]

        plain = binascii.a2b_hex(hex(int(plain, 2))[2:]).decode('utf-8')

        plaintext.append(plain)

    writer_file(plaintext, output_path)
    print("--Finished")


def OAEP_RSA():
    public_key = []
    secret_key = []
    with open('../Task 1/key/RSA_Public_Key.txt', 'r') as file: 
        lines = file.readlines()
        for line in lines:
            public_key.append(int(line.strip('\n')))
    file.close()

    with open('../Task 1/key/RSA_Secret_Key.txt', 'r') as file: 
        lines = file.readlines()
        for line in lines:
            secret_key.append(int(line.strip('\n')))
    file.close()

    if args.encrypt_plaintext != "":
        input_path = args.encrypt_plaintext
        output_path = './Encrypted_Message.txt'
        encrypt_plaintext(public_key, input_path, output_path)

    if args.decrypt_ciphertext != "":
        input_path = args.decrypt_ciphertext
        output_path = './Decrypted_Message.txt'
        decrypt_ciphertext(secret_key, input_path, output_path)


if __name__ == '__main__':
    OAEP_RSA()
