import socket
import json
from hash import Streebog
from SHA import SHA2
from attack import ltb, btl, padRSA, unpadRSA, genkeyRSA, powm
from datetime import datetime

hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def check_group_sign(m, alpha, p, L, hash_type, signature):
    message = ltb(int(m, 16))
    # reference_signature = hash_funcs[hash_type[:-3]](message, int(hash_type[-3:]))
    U, E, S = int(signature[0], 16), int(signature[1], 16), int(signature[2], 16)
    R = (powm(U * L, -E, p) * powm(alpha, S, p)) % p
    chech_E = int(hash_funcs[hash_type[:-3]](message + ltb(R) + ltb(U), int(hash_type[-3:])), 16)
    return chech_E == E


def sign(hash_type, text, path_to_keys):

    with open(path_to_keys, 'r') as f:
        private_key = json.load(f)
        d = private_key['d']
        p = private_key['p']
        q = private_key['q']

    s = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))
    pudding_text = padRSA(ltb(int(s, 16)), 255)

    signed_text = hex(powm(btl(pudding_text), d, p*q))
    return signed_text

def finish_CAdES(text, hash_type, utc_time,path_to_keys, json_data):
    text = ltb(int(text, 16)) + utc_time.encode('utf-8')
    signature = sign(hash_type, text, path_to_keys)

    with open(path_to_keys + ".pub", 'r') as f:
        public_key = json.load(f)
        e = public_key['e']
        n = public_key['n']

    json_data['SignerInfos']["UnsignedAttributes"] = {
        "OBJECT_IDENTIFIER": "",
        "SET_OF_AttributeValue": {
            "DigestAlgoritmIdentifiers": hash_type,  # GOST512, GOST256, SHA512, SHA256
            "SignatureAlgorithmIdentifier": "RSAdsi",  # RSAdsi, DSAdsi, ...
            "timestamp": utc_time,
            "signature": signature,  # (hash + timestamp),
            "certificate": {
                "e": hex(e),
                "n": hex(n)
            }
        }

    }

    return json_data


def start_server(host='localhost', port=12347):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Сервер запущен на {host}:{port}")

        conn, addr = s.accept()
        with conn:
            print(f"Подключен клиент: {addr}")

            # Получаем данные от клиента
            data = conn.recv(65536).decode('utf-8')
            print(f"Получены данные: {data}")

            # Парсим JSON
            json_data = json.loads(data)
            alpha, p, L = json_data["SignerInfos"]["SubjectPublicKeyInfo"]["alpha"], json_data["SignerInfos"]["SubjectPublicKeyInfo"]["p"], json_data["SignerInfos"]["SubjectPublicKeyInfo"]["L"]
            m, hash_type, signature = json_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"], json_data["DigestAlgoritmIdentifiers"], json_data["SignerInfos"]["SignatureValue"]
            if check_group_sign(m, int(alpha, 16), int(p, 16), int(L, 16), hash_type, signature):
                utc_now = (datetime.utcnow().strftime("%y%m%d%H%M%S"))
                text = m + signature[0][2:] + signature[1][2:] + signature[2][2:]
                json_data = finish_CAdES(text, hash_type, utc_now, 'da4589f5-e0b4-44c2-afb5-65af2bcace61', json_data)

                # Отправляем модифицированный JSON обратно клиенту
                conn.sendall(json.dumps(json_data).encode('utf-8'))
            else: conn.sendall(b'{"incorrect signature" : "True"}')

start_server()