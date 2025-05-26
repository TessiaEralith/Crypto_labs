import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify


hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def check_RSA(m, e, n, hash_type, signature):
    message = ltb(int(m, 16))
    reference_signature = hash_funcs[hash_type[:-3]](message, int(hash_type[-3:]))
    check_signature = powm(int(signature, 16), int(e, 16), int(n, 16))
    unpad_check_signature = hex(btl(unpadRSA(ltb(check_signature), 255)))[2:]
    return reference_signature == unpad_check_signature


def keyget(s, check_id):
    response = s.recv(65536).decode("utf-8")
    # print(response)
    data = json.loads(response)
    ciphertext = data['EncryptedContentInfo']['encryptedContent']
    plaintext = RSA("", "126a3301-1933-467d-a59f-1047625c04f0", "decrypt", cipher=ciphertext).decode('utf-8')
    plaintext = json.loads(plaintext)
    k, t, S = plaintext["k"], plaintext["t"], plaintext["S"]
    e, n = S["SignerInfos"]["SubjectPublicKeyInfo"]["e"], S["SignerInfos"]["SubjectPublicKeyInfo"]["n"]
    m, hash_type, signature = S["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"], S["DigestAlgoritmIdentifiers"], S["SignerInfos"]["SignatureValue"]

    check_text = json.dumps({
        "id": check_id,
        "k": k,
        "t": t
    }).encode("utf-8")
    if check_RSA(m, e, n, hash_type, signature) and m == hex(btl(check_text)):
        key = {
            "k": k
        }
        with open("keyB", 'w') as f:
            json.dump(key, f, indent=4)
        return True
    else:
        return False

host = 'localhost'
port = 12346

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    s.listen()
    print(f"Сервер запущен на {host}:{port}")

    conn, addr = s.accept()
    with conn:
        print(keyget(conn, port))