import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify


def auth(socket, n):
    v = btl(socket.recv(1024))
    print(n, v)
    socket.sendall(b"good")
    for i in range(10):
        x = btl(socket.recv(1024))
        print(x)
        c = randint(0, 1)
        socket.sendall(ltb(c))
        y = btl(socket.recv(1024))
        if not (y != 0 and powm(y, 2, n) == (x * powm(v, c, n)) % n):
            print("Error")
            return
    return True


host='localhost'
port=12346

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print(f"Сервер запущен на {host}:{port}")
    conn, addr = s.accept()
    with conn:
        print(f"Подключен клиент: {addr}")
        n = btl(conn.recv(1024))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Подключен клиент: {addr}")
        print(auth(conn, n))


