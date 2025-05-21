import mimetypes
import json
import socket
from random import randint
from hash import Streebog
from SHA import SHA2
from attack import *


hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def CAdES(mime_type, DigestAlgoritm, SignatureAlgorithm, message, SignatureValue, alpha, beta, p):
    certificate = {
        "CMSVersion": 1,
        "DigestAlgoritmIdentifiers": DigestAlgoritm,  # GOST512, GOST256, SHA512, SHA256
        "EncapsulatedContentInfo": {
            "ContetntType": mime_type,  # MIME type
            "OCTET_STRING_OPTIONAL": message
        },
        "SignerInfos": {
            "CMSVersion": 1,
            "SignerIdentifier": "Eberzin Kirill",
            "DigestAlgoritmIdentifiers": DigestAlgoritm,  # GOST512, GOST256, SHA512, SHA256
            "SignatureAlgorithmIdentifier": SignatureAlgorithm,  # RSAdsi, DSAdsi, ...
            "SignatureValue": SignatureValue,
            "SubjectPublicKeyInfo": {
                "alpha": alpha,
                "beta": beta,
                "p": p
            },
            # "UnsignedAttributes": {
            #     "OBJECT_IDENTIFIER": "$signatrue-time-stamp",
            #     "SET_OF_AttributeValue": {
            #         "hash": "$hash",
            #         "timestamp": "$timestamp",
            #         "signature": "$sign",  # (hash + timestamp),
            #         "certificate": "$keys"
            #     }
            # }
        }
    }
    return certificate


def sign(hash_type, path_to_file, path_to_keys):
    with open(path_to_file, 'rb') as f:
        text = f.read()

    with open(path_to_keys + ".pub", 'r') as f:
        public_key = json.load(f)
        alpha = public_key['alpha']
        beta = public_key['beta']
        p = public_key['p']

    with open(path_to_keys, 'r') as f:
        private_key = json.load(f)
        a = private_key['a']

    mime_type, _ = mimetypes.guess_type(path_to_file)
    s = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))

    r = randint(1, p-2)
    while gcd(r, p-1) != 1:
        r = randint(1, p - 2)

    gamma = powm(alpha, r, p)
    sigma = ((int(s, 16) - a*gamma) * powm(r, -1, p-1)) % (p-1)

    return CAdES(mime_type, hash_type, "DSAdsi", hex(btl(text)), (hex(gamma), hex(sigma)), hex(alpha), hex(beta), hex(p))


def check_El_Gamal(m, alpha, beta, p, hash_type, signature, utc_time):
    text = ltb(int(m, 16)) + utc_time.encode('utf-8')

    gamma, sigma = int(signature[0], 16), int(signature[1], 16)
    reference_hash = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))
    check_signature = powm(alpha, int(reference_hash, 16), p)

    return (powm(beta, gamma, p) * powm(gamma, sigma, p)) % p == check_signature


def send_json_to_server(certificate, host='localhost', port=12345):
    m, hash_type, signature = certificate["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"], certificate["DigestAlgoritmIdentifiers"], certificate["SignerInfos"]["SignatureValue"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Отправляем JSON на сервер
        json_data = json.dumps(certificate)
        s.sendall(json_data.encode('utf-8'))

        # Получаем ответ от сервера
        response = s.recv(65536).decode('utf-8')
        data = json.loads(response)
        print(data)
        alpha, beta, p = data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["alpha"], data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["beta"], data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["p"]
        alpha, beta, p = int(alpha, 16), int(beta, 16), int(p, 16)
        timestamp, signaturects = data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["timestamp"], data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["signature"]
        if check_El_Gamal(m+signature[0][2:]+signature[1][2:], alpha, beta, p, hash_type, signaturects, timestamp):
            data['SignerInfos']["UnsignedAttributes"]["OBJECT_IDENTIFIER"] = timestamp
        return data
        # return response

# key_genEl_Gamal(1024)
certificate = sign("SHA256", "cipher.txt", "24f78966-b021-4e90-b6bf-7eb389d3058a")

# with open('certificate.txt', 'w') as out:
#     json.dump(certificates, out, indent=4)
# print(certificate)

print(send_json_to_server(certificate))
