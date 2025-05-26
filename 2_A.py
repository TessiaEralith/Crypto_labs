from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import mimetypes
import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from datetime import datetime
from attack import *


def key_gen(s):
    key = randint(1 << 127, (1 << 128) - 1)
    cipher = AES.new(ltb(key), AES.MODE_CBC)

    private_key = {
        "key": hex(key),
        "iv": hex(btl(cipher.iv))
    }
    s.sendall(json.dumps(private_key).encode('utf-8'))
    return ltb(key), cipher.iv

def auth(m1, m2, id, type_check_num, key, iv, s, check_id):
    if type_check_num == "r":
        check_num = str(randint(100000, 1 << 100))
    elif type_check_num == 't':
        check_num = (datetime.utcnow().strftime("%y%m%d%H%M%S"))
    else:
        print("Error")
        return

    plaintext = json.dumps({
        "check_num": check_num,
        "id": id,
        "m": m1
    }).encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    data = {
        "m": m2,
        "ct": btl(ciphertext)
    }

    s.sendall(json.dumps(data).encode('utf-8'))

    data = s.recv(65536)
    data = json.loads(data)
    print(data["m"])
    ciphertext = ltb(data["ct"])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    plaintext = json.loads(plaintext)

    if plaintext["id"] != check_id or check_num != plaintext["check_num"]:
        print("auth error")
        return
    print(plaintext["m"])


m1 = 'hello'
m2 = 'how are you?'
host='localhost'
port=12345
check_id = 12346
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.connect((host, check_id))

    key, iv = key_gen(s)
    auth(m1, m2, port, 't', key, iv, s, check_id)
