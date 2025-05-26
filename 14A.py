import json
import uuid
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify

hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def genPass(password, hash_type, index):
    password_info = {
        "hash_type": hash_type,
        "password": password,
        "index": index - 1
    }
    with open("password_info", 'w') as f:
        json.dump(password_info, f, indent=4)
    password = hash_funcs[hash_type[:-3]](password.encode("utf-8"), int(hash_type[-3:]))
    for i in range(1, index):
        password = hash_funcs[hash_type[:-3]](unhexlify(password), int(hash_type[-3:]))
    return password


def auth(s):
    with open("password_info", 'r') as f:
        password_info = json.load(f)
        hash_type = password_info["hash_type"]
        password = password_info["password"]
        index = password_info["index"]
    current_password = genPass(password, hash_type, index)
    password_info["password"] = current_password
    print(password_info)
    s.sendall(json.dumps(password_info).encode("utf-8"))
    return(s.recv(1024).decode("utf-8"))

# print(genPass("hello", "SHA256", 2))
host='localhost'
port=12345
check_id = 12346

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, check_id))
    with open("password_info", 'r') as f:
        password_info = json.load(f)
        index = password_info["index"]
        if index == 0:
            password = uuid.uuid4().hex
            new_pass = {
                "hash_type": "SHA256",
                "password": genPass(password, "SHA256", 5),
                "index": 5
            }
            s.sendall(json.dumps(new_pass).encode("utf-8"))
        else:
            print(auth(s))