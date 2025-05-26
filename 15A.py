import json
import uuid
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify


def auth(n, socket):

    s = 0
    while gcd(s, n) != 1:
        s = randint(1, n-1)
    v = powm(s, 2, n)
    print(v)
    socket.sendall(ltb(v))
    resp = socket.recv(1024)
    for i in range(10):
        z = randint(2, n - 2)
        x = powm(z, 2, n)
        print(x)
        socket.sendall(ltb(x))

        c = btl(socket.recv(1024))

        y = (z*powm(s, c, n)) % n
        print(y, x, c)
        socket.sendall(ltb(y))


host='localhost'
port=12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print(f"Сервер запущен на {host}:{port}")

    conn, addr = s.accept()
    with conn:
        print(f"Подключен клиент: {addr}")
        n = btl(conn.recv(1024))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, 12346))
auth(n, s)

# s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s1.bind((host, port))
# s1.listen()
# conn, addr = s1.accept()
#         with conn:
#             auth([s1, s2])

