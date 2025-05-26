import json
import socket
from random import randint, shuffle, getrandbits
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify
from datetime import datetime

n = 3
m = 3
A = [[0 for _ in range(m)] for _ in range(m)]

def genkey():
    R = []
    F = getprime(128)
    for i in range(n):
        r = getrandbits(32)
        R.append(r)
    key = {
        "R": R,
        "F": F
    }
    with open("blom_S.pub", 'w') as f:
        json.dump(key, f, indent=4)
    # s.sendall(json.dumps(key).encode('utf-8'))
    for i in range(m):
        for j in range(i, m):
            a = getrandbits(32)
            A[i][j] = a
            A[j][i] = a

def gen_poly(r, F):
    g = []
    for i in range(m):
        g_i = 0
        for j in range(m):
            g_i = g_i + A[i][j] * powm(r, j, F)
        g.append(g_i % F)
    return g


def send(s, index):
    with open("blom_S.pub", 'r') as f:
        key = json.load(f)
        R = key["R"]
        F = key["F"]
    key["g"] = gen_poly(R[index], F)
    s.sendall(json.dumps(key).encode('utf-8'))

host='localhost'
port=12345
port2 = 12346
genkey()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    send(s, 0)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port2))
    send(s, 1)
