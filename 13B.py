import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *

hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def auth(s):
    data = s.recv(65536)
    data = json.loads(data)
    h = data["hash"]
    ciphertext = data["cipher"]['EncryptedContentInfo']['encryptedContent']
    hash_type = data["cipher"]['EncryptedContentInfo']['OPTIONAL']['DigestAlgoritmIdentifiers']
    plaintext = RSA("", "50427282-efc5-45ee-9d18-d520af3f2947", "decrypt", cipher=ciphertext).decode('utf-8')
    plaintext = json.loads(plaintext)
    z = plaintext["z"]
    reference_signature = hash_funcs[hash_type[:-3]](ltb(z), int(hash_type[-3:]))
    if reference_signature == h:
        s.sendall(ltb(z))
    else:
        s.sendall(b'Error')




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
        auth(conn)


