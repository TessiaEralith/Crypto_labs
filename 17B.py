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

    with open("key_Diffie_B", 'w') as f:
        json.dump(key, f, indent=4)


def Diffie_Hellman(s):
    with open("key_Diffie_B", 'r') as f:
        key = json.load(f)
        p = key["p"]
        g = key["g"]
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
        keyget(conn)
        # Diffie_Hellman(conn)