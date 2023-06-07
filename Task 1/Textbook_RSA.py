import argparse
import random 
import binascii 

parser = argparse.ArgumentParser()
parser.add_argument('--n_bits', type=int, default=1024)
parser.add_argument('--generate_keys', action="store_true")
parser.add_argument('--encrypt_plaintext', type=str, default="")
parser.add_argument('--decrypt_ciphertext', type=str, default="")
args = parser.parse_args()


small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
                61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
                131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
                193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
                263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
                337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401,
                409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
                479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
                569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631,
                641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709,
                719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
                809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
                881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967,
                971, 977, 983, 991, 997]


def miller_rabin(p, prime_size):
    if p % 2 == 0:
        return False
    if p in small_primes:
        return True
    for prime in small_primes:
        if p % prime == 0:
            return False
        
    target = p - 1
    r = 0
    while target % 2 == 0:
        target = target >> 1
        r += 1
    d = int(target)
    
    for i in range(prime_size):
        a = random.randrange(2, p - 1)
        v = pow(a, d, p)
        if v != 1:
            j = 0
            while v != p - 1:
                if j == r - 1:
                    return False 
                else:
                    j += 1
                    v = (v ** 2) % p
    return True


def generate_prime(prime_size):
    while True:
        p = random.randrange(2 ** (prime_size - 1), 2 ** prime_size)
        if miller_rabin(p, prime_size):
            return p


def extended_euclidean(a, b):
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    while b:
        q = a // b
        s1, s0 = s0 - q * s1, s1
        t1, t0 = t0 - q * t1, t1
        a, b = b, a % b
    return a, s0


def writer_file(list, output_path):
    with open(output_path, 'w') as file:  
        for i in range(len(list)):
            file.write(str(list[i]) + '\n')
    file.close()


def generate_keys(n_bits):
    N = 1
    p = q = 1

    while N.bit_length() != n_bits:
        prime_size = n_bits // 2
        p = generate_prime(prime_size)
        q = generate_prime(n_bits - prime_size)
        N = p * q
    
    phi_N = (p - 1) * (q - 1)
    e = random.randrange(3, phi_N)
    while True:
        gcd, d = extended_euclidean(e, phi_N)
        if gcd != 1:
            e = random.randrange(3, phi_N)
        else:
            break
    public_key = (N, e)
    secret_key = (N, d % phi_N)

    list = []
    list.append(N)
    writer_file(list, './parameters/RSA_Moduler.txt')
    list[0] = p
    writer_file(list, './parameters/RSA_p.txt')
    list[0] = q
    writer_file(list, './parameters/RSA_q.txt')

    writer_file(public_key, './key/RSA_Public_Key.txt')
    writer_file(secret_key, './key/RSA_Secret_Key.txt')
    print("--Generation has completed\n")


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

    
def encrypt_plaintext(public_key, input_path, output_path):
    plaintext = []
    with open(input_path, 'r') as file: 
        lines = file.readlines()
        for line in lines:
            plaintext.append(line.strip('\n'))
    file.close()

    ciphertext = []
    for i in range(len(plaintext)):
        currenttext = plaintext[i]
        currenttext = bytes(currenttext, encoding='utf-8')
        currenttext = int(binascii.b2a_hex(currenttext), 16)
        cipher = fast_mod(currenttext, public_key)
        ciphertext.append(hex(cipher))
    
    writer_file(ciphertext, output_path)
    print("--Encryption has completed\n")


def decrypt_ciphertext(secret_key, input_path, output_path):
    ciphertext = []
    with open(input_path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            ciphertext.append(line.strip('\n'))
    file.close()

    plaintext = []
    for i in range(len(ciphertext)):
        currenttext = int(ciphertext[i][2:], 16)
        plain = fast_mod(currenttext, secret_key)
        plain = binascii.a2b_hex(hex(plain)[2:])
        
        plaintext.append(str(plain, encoding='utf-8'))

    writer_file(plaintext, output_path)
    print("--Decryption has completed\n")


def Textbook_RSA():
    if args.generate_keys:
        generate_keys(args.n_bits)
        return
    else:
        public_key = []
        secret_key = []
        with open('./key/RSA_Public_Key.txt', 'r') as file: 
            lines = file.readlines()
            for line in lines:
                public_key.append(int(line.strip('\n')))
        file.close()

        with open('./key/RSA_Secret_Key.txt', 'r') as file: 
            lines = file.readlines()
            for line in lines:
                secret_key.append(int(line.strip('\n')))
        file.close()

    if args.encrypt_plaintext != "":
        input_path = args.encrypt_plaintext
        output_path = './Encryption/Encrypted_Message.txt'
        encrypt_plaintext(public_key, input_path, output_path)

    if args.decrypt_ciphertext != "":
        input_path = args.decrypt_ciphertext
        output_path = './Encryption/Decrypted_Message.txt'
        decrypt_ciphertext(secret_key, input_path, output_path)


if __name__ == '__main__':
    Textbook_RSA()
