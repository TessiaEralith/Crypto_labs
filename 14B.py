import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify

hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def check(password, hash_type, old_password):
    return old_password == hash_funcs[hash_type[:-3]](unhexlify(password), int(hash_type[-3:]))


def reg(password, hash_type, index):
    password_info = {
        "hash_type": hash_type,
        "password": password,
        "index": index
    }
    with open("password_info_B", 'w') as f:
        json.dump(password_info, f, indent=4)


def auth(s):
    data = s.recv(65536).decode("utf-8")
    data = json.loads(data)
    with open("password_info_B", 'r') as f:
        password_info = json.load(f)
        old_hash_type = password_info["hash_type"]
        old_password = password_info["password"]
        old_index = password_info["index"]
    hash_type = data["hash_type"]
    password = data["password"]
    index = data["index"]

    if index == old_index - 1 and old_hash_type == hash_type and (check(password, hash_type, old_password)):
        s.sendall(b"OK")
        password_info["password"] = password
        password_info["index"] = index
        with open("password_info_B", 'w') as f:
            json.dump(password_info, f, indent=4)
    else: s.sendall(b"Error")

# reg("SHA256", "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50", 2)

host = 'localhost'
port = 12346
check_id = 12345
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print(f"Сервер запущен на {host}:{port}")

    conn, addr = s.accept()
    with conn:
        print(f"Подключен клиент: {addr}")
        with open("password_info_B", 'r') as f:
            password_info = json.load(f)
            index = password_info["index"]
        if index == 1:
            data = conn.recv(65536).decode("utf-8")
            data = json.loads(data)
            hash_type = data["hash_type"]
            password = data["password"]
            index = data["index"]
            reg(password, hash_type, index)
        else:
            auth(conn)
