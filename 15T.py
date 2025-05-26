import json
import uuid
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify


def key_gen(bits):
    p, q = getprime(bits), getprime(bits)
    n = p*q
    private_key = {
        "p": p,
        "q": q,
        "n": n
    }
    print(private_key)
    return n

n = key_gen(512)
host='localhost'
port=12347
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, 12345))
s.sendall(ltb(n))
s.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, 12346))
s.sendall(ltb(n))
s.close()