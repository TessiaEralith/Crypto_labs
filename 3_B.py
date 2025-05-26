from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify
import mimetypes
import json
import socket
from random import randint, shuffle

from datetime import datetime
from attack import *


def key_get(s):
    data = s.recv(1024).decode('utf-8')
    data = json.loads(data)
    key = unhexlify(data["key"][2:])
    iv = unhexlify(data["iv"][2:])
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    return key, iv


def auth(m2, m3, id, key, iv, s, check_id):

    data = s.recv(65536)
    data = json.loads(data)
    print(data["m"])
    check_num2 = str(randint(100000, 1 << 100))
    r_a = data["r_a"]

    plaintext = json.dumps({
        "r_a": r_a,
        "r_b": check_num2,
        "id": id,
        "m": m2
    }).encode('utf-8')

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    data = {
        "m": m3,
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

    if plaintext["id"] != check_id or plaintext["r_b"] != check_num2 or plaintext["r_a"] != r_a:
        print("auth error")
        return
    print(plaintext["m"])


m2 = 'hi'
m3= 'fine'
host = 'localhost'
port = 12346
check_id = 12345
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print(f"Сервер запущен на {host}:{port}")

    conn, addr = s.accept()
    with conn:
        print(f"Подключен клиент: {addr}")

        key, iv = key_get(conn)
        auth(m2, m3, port, key, iv, conn, check_id)