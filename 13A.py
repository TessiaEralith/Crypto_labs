import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *


hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def auth(id, hash_type, s):
    z = randint(100000, 1 << 100)
    H = hash_funcs[hash_type[:-3]](ltb(z), int(hash_type[-3:]))
    plaintext = json.dumps({
        "z": z,
        "id": id
    }).encode('utf-8')
    cipher = RSA("", "50427282-efc5-45ee-9d18-d520af3f2947", "encrypt", optional={"DigestAlgoritmIdentifiers": hash_type}, mime_type="text/plain", text=plaintext)
    data = json.dumps({
        "hash": H,
        "cipher": cipher
    }).encode('utf-8')
    s.sendall(data)

    data = s.recv(1024)
    z_check = btl(data)
    return z_check == z

host='localhost'
port=12345
check_id = 12346

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, check_id))
    # print(port)
    print(auth(1, "SHA256", s))

