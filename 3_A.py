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


def auth(m1, m4, m5, id, key, iv, s, check_id):

    check_num = str(randint(100000, 1 << 100))

    plaintext = json.dumps({
        "r_a": check_num,
        "m": m1
    }).encode('utf-8')
    s.sendall(plaintext)

    data = s.recv(65536)
    data = json.loads(data)
    print(data["m"])
    ciphertext = ltb(data["ct"])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    plaintext = json.loads(plaintext)

    if plaintext["id"] != check_id or check_num != plaintext["r_a"]:
        print("auth error")
        return
    print(plaintext["m"])

    r_b = plaintext["r_b"]
    plaintext = json.dumps({
        "r_b": r_b,
        "r_a": check_num,
        "id": id,
        "m": m4
    }).encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    data = {
        "m": m5,
        "ct": btl(ciphertext)
    }

    s.sendall(json.dumps(data).encode('utf-8'))


m1 = 'hello'
m4 = 'how are you?'
m5 = 'good'
host='localhost'
port=12345
check_id = 12346
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.connect((host, check_id))

    key, iv = key_gen(s)
    auth(m1, m4, m5, port, key, iv, s, check_id)
