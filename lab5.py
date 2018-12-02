from Crypto.Cipher import AES
from Crypto.Util import Counter

from sys import argv

import base64


def dec(key, iv, cipher_text):
    ctr_d = Counter.new(128, initial_value=int(iv.encode("hex"), 16))
    decryptor = AES.new(key, AES.MODE_CTR, counter=ctr_d)
    return decryptor.decrypt(base64.b64decode(cipher_text))


def enc(key, iv, plain_text):
    ctr_e = Counter.new(128, initial_value=int(iv.encode("hex"), 16))
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr_e)
    return base64.b64encode(encryptor.encrypt(plain_text))


input_file = "input.txt"
mode = argv[1]

key = argv[2]
iv = argv[3]

with open(input_file, 'rb') as fin:
    if mode == '-d':
        print(dec(key, iv, fin.read()))
    else:
        print(enc(key, iv, fin.read()))
