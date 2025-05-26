import socket
import json
from random import randint
from hash import Streebog
from SHA import SHA2
from attack import *
from datetime import datetime

hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def get_key(host='localhost', port=12346):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Сервер запущен на {host}:{port}")

        conn, addr = s.accept()
        with conn:
            print(f"Подключен клиент: {addr}")

            # Получаем данные от клиента
            data = conn.recv(1024).decode('utf-8')
            data = json.loads(data)
            with open("member2_keys", 'w') as f:
                json.dump(data, f, indent=4)
            # Получаем данные от клиента
            data = conn.recv(1024).decode('utf-8')
            data = json.loads(data)
            with open("member2_keys.pub", 'w') as f:
                json.dump(data, f, indent=4)

# get_key()

def sign(host='localhost', port=12346):
    with open("member2_keys.pub", 'r') as f:
        public_key = json.load(f)
        p = public_key['p']
        q = public_key['q']
        alpha = public_key['alpha']

    with open("member2_keys", 'r') as f:
        private_key = json.load(f)
        k = private_key['k']


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Сервер запущен на {host}:{port}")

        conn, addr = s.accept()
        with conn:
            print(f"Подключен клиент: {addr}")

            # Получаем данные от клиента
            lamda_i = btl(conn.recv(1024))
            t = randint(2, q-1)
            R = powm(alpha, t, p)
            conn.sendall(ltb(R))
            E = btl(conn.recv(1024))
            S = (t + k * lamda_i * E) % q
            conn.sendall(ltb(S))


sign()