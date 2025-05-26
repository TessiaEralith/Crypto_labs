import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify
from datetime import datetime

def genkey(bits, s):
    p = getprime(bits)
    g = get_primitive(p)
    key = {
        "p": p,
        "g": g
    }
    with open("key_Diffie", 'w') as f:
        json.dump(key, f, indent=4)
    s.sendall(json.dumps(key).encode('utf-8'))


def Diffie_Hellman(s):
    with open("key_Diffie", 'r') as f:
        key = json.load(f)
        p = key["p"]
        g = key["g"]
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
    genkey(1024, s)
    # Diffie_Hellman(s)