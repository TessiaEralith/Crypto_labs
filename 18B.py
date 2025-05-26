import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify
from datetime import datetime

hash_funcs = {"SHA": SHA2, "GOST": Streebog}

def keyget(s):
    response = s.recv(65536).decode("utf-8")
    key = json.loads(response)
    with open("SPEKE_B", 'w') as f:
        json.dump(key, f, indent=4)


def Diffie_Hellman(s):
    with open("SPEKE_B", 'r') as f:
        key = json.load(f)
        p = key["p"]
        w = key["w"]
        hash_type = key["hash_type"]
    g = hash_funcs[hash_type[:-3]](w.encode("utf-8"), int(hash_type[-3:]))
    g = int(g, 16)

    alpha = btl(s.recv(1024))
    y = randint(2, p - 2)
    beta = powm(g, y, p)
    s.sendall(ltb(beta))

    k = powm(alpha, y, p)
    print(k)


host = 'localhost'
port = 12346


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print(f"Сервер запущен на {host}:{port}")

    conn, addr = s.accept()
    with conn:
        # keyget(conn)
        Diffie_Hellman(conn)