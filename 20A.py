import json
import socket
from random import randint, shuffle, getrandbits
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify
from datetime import datetime

n = 3
t = 1
T = t + 1
A = []

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
    with open("Shamir_S.pub", 'w') as f:
        json.dump(key, f, indent=4)

    for i in range(T):
        a = getrandbits(32)
        A.append(a)


def gen_s(r, F):
    s = 0
    for i in range(T):
        s = s + A[i] * powm(r, i, F)
    return s % F


def send(s, index):
    with open("blom_S.pub", 'r') as f:
        key = json.load(f)
        R = key["R"]
        F = key["F"]
    key["s"] = gen_s(R[index], F)
    s.sendall(json.dumps(key).encode('utf-8'))

def secret_recovery(R, S, F):
    secret = 0
    for i in range(T):
        c = 1
        for j in range(T):
            if i == j:
                continue
            c = (c * R[j] * powm(R[j] - R[i], -1, F)) % F
        secret = (secret + S[i] * c) % F
    return secret % F
genkey()
with open("Shamir_S.pub", 'r') as f:
    key = json.load(f)
    R = key["R"]
    F = key["F"]
r1, r2 = R[0], R[1]
s1, s2 = gen_s(r1, F), gen_s(r2, F)
print(s1, s2)
print(r1, r2)
print(F)
print(secret_recovery(R, [s1, s2], F))
print(A)
print(gen_s(0, F))
# host='localhost'
# port=12345
# port2 = 12346
# genkey()
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.connect((host, port))
#     send(s, 0)
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.connect((host, port2))
#     send(s, 1)
