import socket
import json
from random import randint
from hash import Streebog
from SHA import SHA2
from attack import *
from datetime import datetime

hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def check_El_Gamal(m, alpha, beta, p, hash_type, signature):
    message = ltb(int(m, 16))

    gamma, sigma = int(signature[0], 16), int(signature[1], 16)
    reference_hash = hash_funcs[hash_type[:-3]](message, int(hash_type[-3:]))
    check_signature = powm(alpha, int(reference_hash, 16), p)

    return (powm(beta, gamma, p) * powm(gamma, sigma, p)) % p == check_signature


def sign(hash_type, text, path_to_keys):


    with open(path_to_keys + ".pub", 'r') as f:
        public_key = json.load(f)
        alpha = public_key['alpha']
        beta = public_key['beta']
        p = public_key['p']

    with open(path_to_keys, 'r') as f:
        private_key = json.load(f)
        a = private_key['a']

    s = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))

    r = randint(1, p - 2)
    while gcd(r, p - 1) != 1:
        r = randint(1, p - 2)

    gamma = powm(alpha, r, p)
    sigma = ((int(s, 16) - a * gamma) * powm(r, -1, p - 1)) % (p - 1)
    return (hex(gamma), hex(sigma))

def finish_CAdES(text, hash_type, utc_time,path_to_keys, json_data):
    text = ltb(int(text, 16)) + utc_time.encode('utf-8')
    signature = sign(hash_type, text, path_to_keys)

    with open(path_to_keys + ".pub", 'r') as f:
        public_key = json.load(f)
        alpha = public_key['alpha']
        beta = public_key['beta']
        p = public_key['p']

    json_data['SignerInfos']["UnsignedAttributes"] = {
        "OBJECT_IDENTIFIER": "",
        "SET_OF_AttributeValue": {
            "timestamp": utc_time,
            "signature": signature,  # (hash + timestamp),
            "certificate": {
                "alpha": hex(alpha),
                "beta": hex(beta),
                "p": hex(p)
            }
        }

    }
    return json_data




def start_server(host='localhost', port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Сервер запущен на {host}:{port}")

        while 1:
            conn, addr = s.accept()
            with conn:
                print(f"Подключен клиент: {addr}")

                # Получаем данные от клиента
                data = conn.recv(65536).decode('utf-8')
                print(f"Получены данные: {data}")

                # Парсим JSON
                json_data = json.loads(data)
                alpha, beta, p = json_data["SignerInfos"]["SubjectPublicKeyInfo"]["alpha"], json_data["SignerInfos"]["SubjectPublicKeyInfo"]["beta"], json_data["SignerInfos"]["SubjectPublicKeyInfo"]["p"]
                alpha, beta, p = int(alpha, 16), int(beta, 16), int(p,16)
                m, hash_type, signature = json_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"], json_data["DigestAlgoritmIdentifiers"], json_data["SignerInfos"]["SignatureValue"]
                if check_El_Gamal(m, alpha, beta, p, hash_type, signature):
                    utc_now = (datetime.utcnow().strftime("%y%m%d%H%M%S"))
                    json_data = finish_CAdES(m+signature[0][2:]+signature[1][2:], hash_type, utc_now, '61e93dda-4845-410d-bb7e-0343a740ae5e', json_data)

                    # Отправляем модифицированный JSON обратно клиенту
                    conn.sendall(json.dumps(json_data).encode('utf-8'))
                else: conn.sendall(b'{"incorrect signature" : "True"}')



start_server()