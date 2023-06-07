import random
from binascii import b2a_hex, a2b_hex
from Crypto.Cipher import AES

def fast_mod(base, mod, exp):
    remainder = 1
    while exp != 0:
        if exp % 2 == 1:
            remainder = (remainder * base) % mod
        exp = exp >> 1
        base = (base ** 2) % mod
    return remainder

class WUP:
    def __init__(self, request, response):
        self.request = request
        self.response = response

class message:
    def __init__(self, en_WUP, en_AES_key):
        self.en_WUP = en_WUP
        self.en_AES_key = en_AES_key

class client:
    def __init__(self):
        self.public_key = []
        with open('../Task 1/key/RSA_Public_Key.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                self.public_key.append(int(line.strip('\n')))
        file.close()

        self.AES_key = random.randrange(2 ** 127, 2 ** 128)

    def reset_AES_key(self, AES_key):
        self.AES_key = AES_key

    def encrypt_WUP(self, ori_WUP):
        AES_encryptor = AES.new(a2b_hex(hex(self.AES_key)[2:]), AES.MODE_ECB)
        request = ori_WUP.request[2:]
        # request is hexadecimal
        req_bit = len(request) * 4
        # padding
        while req_bit % 128 != 0:
            request += "0"
            req_bit += 4
       
        request = bytes.fromhex(request)
        
        en_request = int(b2a_hex(AES_encryptor.encrypt(request)), 16)
        req_len = int(req_bit / 4)
        en_request = "0x{:0{}x}".format(en_request, req_len)

        return WUP(en_request, "")
                      
    def encrypt_AES_key(self):
        en_AES_key = fast_mod(self.AES_key, self.public_key[0], self.public_key[1])
        return en_AES_key


class server:
    def __init__(self, AES_key):
        self.public_key = []
        self.secret_key = []
        with open('../Task 1/key/RSA_Public_Key.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                self.public_key.append(int(line.strip('\n')))
        file.close()

        with open('../Task 1/key/RSA_Secret_Key.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                self.secret_key.append(int(line.strip('\n')))
        file.close()

        self.AES_key = AES_key
    
    def decrypt_AES_key(self, en_AES_key):
        AES_key = fast_mod(en_AES_key, self.secret_key[0], self.secret_key[1])
        return AES_key

    def decrypt_WUP(self, en_WUP, ori_len):
        AES_key_string = ""
        for i in hex(self.AES_key)[2:]:
            AES_key_string += i
        while len(AES_key_string) < 32:
            AES_key_string = "0" + AES_key_string

        AES_decryptor = AES.new(a2b_hex(AES_key_string), AES.MODE_ECB)
        # en_request is hexadecimal
        en_request = en_WUP.request[2:]

        de_request = AES_decryptor.decrypt(a2b_hex(en_request))
        de_request = int(b2a_hex(de_request)[0 : ori_len], 16)
        de_request = "0x{:0{}x}".format(de_request, ori_len)

        return WUP(de_request, "")
    
