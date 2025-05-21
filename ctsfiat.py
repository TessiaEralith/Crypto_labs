import socket
import json
from random import randint
from hash import Streebog
from SHA import SHA2
from attack import *
from datetime import datetime

hash_funcs = {"SHA": SHA2, "GOST": Streebog}



def key_genFiat(bits_hash, bits_key):
    a, b = [], []
    p, q = getprime(bits_key), getprime(bits_key)
    n = p*q
    for i in range(40):
        a_i = randint(5, n-5)
        a.append(a_i)
        b.append(powm(powm(a_i, -1, n), 2, n))

        # if b_i == powm(powm(a_i, -1, n), 2, n):
        #     b.append(b_i)
        # else: print("ERROR")

    public_key = {
        'b': b,
        'n': n
    }
    private_key = {
        'a': a,
        "p": p,
        "q": q
    }
    with open("fiat_shamir_cts" + f'{bits_hash}' + '.pub', 'w') as f:
        json.dump(public_key, f, indent=4)
    with open("fiat_shamir_cts" + f'{bits_hash}', 'w') as f:
        json.dump(private_key, f, indent=4)
    # print(f"Key gen in {filename}")
# key_genFiat(256, 1024)


def key_recovery(b, n, bits_hash):
    for i in range(bits_hash - 40):
        b_i = (b[i - 39] * b[i - 23] * b[i - 37] * b[i - 30] * b[i - 16] * b[i - 1] * b[i - 10] * b[i - 20]) % n
        b.append(b_i)
    return b






def check_Fiat_Shamir(message, b, hash, t, n, hash_type):
    message = ltb(int(message, 16))
    m = int(hash_type[-3:])
    s = int(hash, 16)
    w = 1
    b = key_recovery(b, n, m)
    for i in range(m):
        s_i = s & 1
        s >>= 1
        w = (w * powm(b[m - 1 - i], s_i, n)) % n
    w = (powm(t, 2, n) * w) % n

    reference_hash = hash_funcs[hash_type[:-3]](message + ltb(w), int(hash_type[-3:]))

    return hash == reference_hash


def sign(hash_type, text):
    m = int(hash_type[-3:])

    path_to_keys = "fiat_shamir_cts" + str(m)
    with open(path_to_keys + ".pub", 'r') as f:
        public_key = json.load(f)
        b = public_key['b']
        n = public_key['n']

    with open(path_to_keys, 'r') as f:
        private_key = json.load(f)
        a = private_key['a']

    a = key_recovery(a, n, m)
    r = randint(1, n - 1)
    u = powm(r, 2, n)


    hash = hash_funcs[hash_type[:-3]](text + ltb(u), m)
    s = int(hash, 16)

    t = 1
    for i in range(m):
        s_i = s & 1
        s >>= 1
        t = (t * powm(a[m-1-i], s_i, n)) % n
    t = (t * r) % n
    return hash, hex(t)



def finish_CAdES(text, hash_type, utc_time, json_data):
    text = ltb(int(text, 16)) + utc_time.encode('utf-8')
    signature = sign(hash_type, text)

    with open("fiat_shamir_cts" + str(hash_type[-3:]) + ".pub", 'r') as f:
        public_key = json.load(f)
        b = public_key['b']
        n = public_key['n']

    json_data['SignerInfos']["UnsignedAttributes"] = {
        "OBJECT_IDENTIFIER": "",
        "SET_OF_AttributeValue": {
            "timestamp": utc_time,
            "signature": signature,  # (hash + timestamp),
            "certificate": {
                "b": b,
                "n": hex(n)
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
                data = conn.recv(65536*1024).decode('utf-8')
                print(f"Получены данные: {data}")
                # with open("fiat_shamir" + f'certificate', 'w') as f:
                #     json.dump(data, f, indent=4)
                # Парсим JSON
                json_data = json.loads(data)
                b, n = json_data["SignerInfos"]["SubjectPublicKeyInfo"]["b"], json_data["SignerInfos"]["SubjectPublicKeyInfo"]["n"]
                n = int(n, 16)
                m, hash_type, signature = json_data["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"], json_data["DigestAlgoritmIdentifiers"], json_data["SignerInfos"]["SignatureValue"]
                if check_Fiat_Shamir(m, b, signature[0], int(signature[1],16), n, hash_type):
                    utc_now = (datetime.utcnow().strftime("%y%m%d%H%M%S"))
                    json_data = finish_CAdES(m+signature[0]+signature[1][2:], hash_type, utc_now, json_data)
                    # print("good")
                    # Отправляем модифицированный JSON обратно клиенту
                    conn.sendall(json.dumps(json_data).encode('utf-8'))
                else: conn.sendall(b'{"incorrect signature" : "True"}')



start_server()