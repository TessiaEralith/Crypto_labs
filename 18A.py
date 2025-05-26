import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify
from datetime import datetime

hash_funcs = {"SHA": SHA2, "GOST": Streebog}

def genkey(bits, s, w, hash_type):
    p = getprime(bits)
    key = {
        "p": p,
        "w": w,
        "hash_type": hash_type
    }
    with open("SPEKE", 'w') as f:
        json.dump(key, f, indent=4)
    s.sendall(json.dumps(key).encode('utf-8'))


def Diffie_Hellman(s):
    with open("SPEKE", 'r') as f:
        key = json.load(f)
        p = key["p"]
        w = key["w"]
        hash_type = key["hash_type"]
    g = hash_funcs[hash_type[:-3]](w.encode("utf-8"), int(hash_type[-3:]))
    g = int(g, 16)
    x = randint(2, p - 2)
    alpha = powm(g, x, p)
    s.sendall(ltb(alpha))
    beta = btl(s.recv(1024))
    k = powm(beta, x, p)
    print(k)

host='localhost'
port=12345
check_id = 12346

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, check_id))
    # genkey(1024, s, 'secret', "SHA512")
    Diffie_Hellman(s)