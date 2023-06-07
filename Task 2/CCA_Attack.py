from class_definition import client, server, WUP, message, fast_mod
from binascii import a2b_hex, b2a_hex
from Crypto.Cipher import AES

def writer_file(list, output_path):
    with open(output_path, 'w') as file:  
        for i in range(len(list)):
            file.write(str(list[i]) + '\n')
    file.close()


def generate_history_message(en_WUP, client_ori):
    en_AES_key = client_ori.encrypt_AES_key()

    Message = message(en_WUP, en_AES_key)
    return Message


def CCA_Attack(message_ori, server_ori):
    # en_AES_key is int
    en_AES_key = message_ori.en_AES_key
    key = server_ori.public_key
    AES_key = 0
    with open('./WUP_Request.txt', 'r') as file:
        lines = file.readlines()
        attack_WUP = WUP(lines[0].strip('\n'), "")
    file.close()
    logs = []

    # Attacker use ki to encrypt WUP and attach Ci encrypted by RSA public key
    for i in range(128, 0 , -1):        
        ki = int(AES_key >> 1) + (1 << 127)
        log = "This turn I will try AES key = {}\n".format(bin(ki))
        logs.append(log)

        # not include "0x"
        req_len = len(attack_WUP.request) - 2        
      
        attacker = client()
        attacker.reset_AES_key(ki)
        en_WUP = attacker.encrypt_WUP(attack_WUP)

        fac = fast_mod(2, key[0], (i - 1) * key[1])
        Ci = fast_mod(fac * en_AES_key, key[0], 1)
        Ci = bin(server_ori.decrypt_AES_key(Ci))[-128:]
        Ci = int(Ci, 2)

        target = server(Ci)
        de_WUP = target.decrypt_WUP(en_WUP, req_len)
        
        if de_WUP.request == attack_WUP.request:
            AES_key = ki
            log = "The {}-th bit of AES key is 1".format(i)
        else:
            AES_key = int(AES_key >> 1)
            log = "The {}-th bit of AES key is 0".format(i)
        logs.append(log)
    
    log = "So the AES key is {}".format(bin(AES_key))
    logs.append(log)
    writer_file(logs, "./Logs.txt")
    return AES_key

        

def whole_process():
    client_ori = client()
    server_ori = server(client_ori.AES_key)
    
    list = []
    list.append(hex(client_ori.AES_key))
    writer_file(list, './AES_Key.txt')     
    print("--AES_Key has been generated\n")


    print("--Encrypt WUP_Request")
    with open('./WUP_Request.txt', 'r') as file:
        lines = file.readlines()
        ori_WUP = WUP(lines[0].strip('\n'), "")
    file.close()
    req_len = len(ori_WUP.request) - 2

    list = []
    en_WUP = client_ori.encrypt_WUP(ori_WUP)
    list.append(en_WUP.request)
    writer_file(list, './AES_Encrypted_WUP.txt')
    print("--Finished\n")


    print("--Generate history message")
    message_ori = generate_history_message(en_WUP, client_ori)
    list = []
    list.append(message_ori.en_WUP.request)
    list.append(hex(message_ori.en_AES_key))
    writer_file(list, './History_Message.txt')
    print("--Finished\n")    

    
    print("--Start attack")
    AES_key = hex(CCA_Attack(message_ori, server_ori))
    print("--The AES key is {}".format(AES_key))
    print("--Finished, please refer to Logs.txt for more information\n")

    print("--Decrypt AES_Encrypted_WUP")
    server_new = server(int(AES_key[2:], 16))
    de_WUP = server_new.decrypt_WUP(message_ori.en_WUP, req_len)
    print("The decrypted request is {}".format(de_WUP.request))
    print("--Finished")


if __name__ == "__main__":
    whole_process()
