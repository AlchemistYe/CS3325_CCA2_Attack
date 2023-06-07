## 1.Task 1: Textbook RSA

- Raw\_Message.txt 是多行字符串的形式

- 生成指定 bits 长度的密钥：

		python Textbook_RSA.py --generate_keys --n_bits 1024

- 加密指定路径下的 Raw\_Message.txt 文件，存放到 ./Encryption/Encrypted\_Message.txt 中：
	
		python Textbook_RSA.py --encrypt_plaintext ./Encryption/Raw_Message.txt

- 解密指定路径下的 Encrypted\_Message.txt 文件，存放到 ./Encryption/Decrypted\_Message.txt 中：
	
		python Textbook_RSA.py --decrypt_ciphertext ./Encryption/Encrypted_Message.txt

-----


## 2. Task 2: CCA2 Attack

- WUP_Request.txt 是单行任意长度十六进制串（0x开头）的形式

- 两份文件，其中 class\_definition.py 定义了各种类和必要的函数，CCA\_Attack.py 具体模拟了攻击过程

- 若需要更新 client 和 server 之间的 RSA 密钥，请参考 Task 1 中重新生成指定 size 的密钥

- 模拟攻击者利用 History_Message 以及 server 进行 CCA2 攻击：

        python CCA_Attack.py


- 解密 AES\_Encrypted\_WUP.txt 结果通过终端输出

------



## 3. Task 3: OAEP

- Task 1 中的 Raw\_Message.txt 作为输入，长度不大于512-bit

- 使用 OAEP, 加密指定路径下的 Raw\_Message.txt 文件，存放到 ./Encrypted\_Message.txt 中：
		
		python OAEP_RSA.py --encrypt_plaintext "../Task 1/Encryption/Raw_Message.txt"

- 使用 OAEP, 解密指定路径下的 Encrypted\_Message.txt 文件，存放到 ./Decrypted\_Message.txt 中:

		python OAEP_RSA.py --decrypt_ciphertext ./Encrypted_Message.txt
