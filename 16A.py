import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *
from binascii import unhexlify
from datetime import datetime


hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def keygen():
    k = randint(1 << 255, (1 << 256) - 1)
    key = {
        "k": k
    }
    with open("key", 'w') as f:
        json.dump(key, f, indent=4)


def CAdES(mime_type, DigestAlgoritm, SignatureAlgorithm, message, SignatureValue, e, n, timestamp):
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
                "e": e,
                "n": n
            },
            "UnsignedAttributes": {
                "OBJECT_IDENTIFIER": timestamp,
                "SET_OF_AttributeValue": {
                    "timestamp": timestamp,
                }
            }
        }
    }
    return certificate


def sign(id, k, hash_type, path_to_keys):
    with open(path_to_keys + ".pub", 'r') as f:
        public_key = json.load(f)
        e = public_key['e']
        n = public_key['n']

    with open(path_to_keys, 'r') as f:
        private_key = json.load(f)
        d = private_key['d']

    t = (datetime.utcnow().strftime("%y%m%d%H%M%S"))
    text = json.dumps({
        "id": id,
        "k": k,
        "t": t
    }).encode("utf-8")
    s = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))
    pudding_text = padRSA(ltb(int(s, 16)), 255)

    signed_text = hex(powm(btl(pudding_text), d, n))
    return CAdES('text/plain', hash_type, "RSAdsi", hex(btl(text)), signed_text, hex(e), hex(n), t)


def send(s, hash_type, id, path_to_B_keys, path_to_k="key"):
    with open(path_to_k, 'r') as f:
        key = json.load(f)
        k = key["k"]
    S = sign(id, k, hash_type, "50427282-efc5-45ee-9d18-d520af3f2947")
    t = S["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["timestamp"]

    data = json.dumps({
        "k": k,
        "t": t,
        "S": S
    }).encode("utf-8")
    cipher = RSA('', path_to_B_keys, "encrypt", mime_type="text/plain", text=data)
    s.sendall(json.dumps(cipher).encode('utf-8'))




host='localhost'
port=12345
check_id = 12346

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, check_id))
    keygen()
    send(s, "SHA512", check_id, "126a3301-1933-467d-a59f-1047625c04f0")