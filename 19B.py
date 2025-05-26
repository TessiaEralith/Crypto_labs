import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify
from datetime import datetime


def keyget(s):
    response = s.recv(65536).decode("utf-8")
    key = json.loads(response)
    with open("blom_B.pub", 'w') as f:
        json.dump(key, f, indent=4)


def key_gen(index):
    with open("blom_B.pub", 'r') as f:
        key = json.load(f)
        r = key["R"][index]
        F = key["F"]
        g = key["g"]
    k = 0
    for i in range(len(g)):
        k = k + g[i] * powm(r, i, F)
    return k % F

host = 'localhost'
port = 12346

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print(f"Сервер запущен на {host}:{port}")

    conn, addr = s.accept()
    with conn:
        keyget(conn)
k = key_gen(0)
print(k)