import mimetypes
import json
import socket
from random import randint
from hash import Streebog
from SHA import SHA2
from attack import *

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
    with open("fiat_shamir" + f'{bits_hash}' + '.pub', 'w') as f:
        json.dump(public_key, f, indent=4)
    with open("fiat_shamir" + f'{bits_hash}', 'w') as f:
        json.dump(private_key, f, indent=4)
    # print(f"Key gen in {filename}")


def key_recovery(a, n, bits_hash):
    for i in range(bits_hash - 40):
        a_i = (a[i-39] * a[i-23] * a[i-37] * a[i-30] * a[i-16] * a[i-1] * a[i-10] * a[i-20]) % n
        a.append(a_i)
    return a


def CAdES(mime_type, DigestAlgoritm, SignatureAlgorithm, message, SignatureValue, b, n):
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
                "b": b,
                "n": n,
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


def sign(hash_type, path_to_file):
    m = int(hash_type[-3:])
    with open(path_to_file, 'rb') as f:
        text = f.read()
    path_to_keys = "fiat_shamir" + str(m)
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

    mime_type, _ = mimetypes.guess_type(path_to_file)
    hash = hash_funcs[hash_type[:-3]](text + ltb(u), m)
    s = int(hash, 16)

    t = 1
    for i in range(m):
        s_i = s & 1
        s >>= 1
        t = (t * powm(a[m-1-i], s_i, n)) % n
    t = (t * r) % n

    return CAdES(mime_type, hash_type, "Fiat-Shamir", hex(btl(text)), (hash, hex(t)), b, hex(n))


def check_Fiat_Shamir(message, b_cts, hash, t, n, hash_type, utc_time):
    text = ltb(int(message, 16)) + utc_time.encode('utf-8')

    m = int(hash_type[-3:])
    s = int(hash, 16)
    w = 1
    b = key_recovery(b_cts, n, m)
    for i in range(m):
        s_i = s & 1
        s >>= 1
        w = (w * powm(b[m - 1 - i], s_i, n)) % n
    w = (powm(t, 2, n) * w) % n
    # b = b[:40]
    reference_hash = hash_funcs[hash_type[:-3]](text + ltb(w), int(hash_type[-3:]))

    return hash == reference_hash


def send_json_to_server(certificate, host='localhost', port=12345):
    m, hash_type, signature = certificate["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"], certificate["DigestAlgoritmIdentifiers"], certificate["SignerInfos"]["SignatureValue"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Отправляем JSON на сервер
        json_data = json.dumps(certificate)

        s.sendall(json_data.encode('utf-8'))

        # # Получаем ответ от сервера
        response = s.recv(65536*1024).decode('utf-8')
        data = json.loads(response)
        # print(data)
        b, n = data["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["b"], data["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["n"]
        # print(len(b))
        n = int(n, 16)

        timestamp, signaturects = data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["timestamp"], data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["signature"]
        if check_Fiat_Shamir(m+signature[0]+signature[1][2:], b, signaturects[0], int(signaturects[1],16), n, hash_type, timestamp):
            data['SignerInfos']["UnsignedAttributes"]["OBJECT_IDENTIFIER"] = timestamp
            data["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["b"] = data["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["b"][:40]
        # print(len(data["SignerInfos"]["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["b"]))
        return data



# certificates = sign("SHA256", "cipher.txt")
# #
# with open('certificate.txt', 'w') as out:
# #     json_data = json.load(out)
#
#     json.dump(certificates, out, indent=4)
# # certificate = sign("SHA256", "cipher.txt")
# print(send_json_to_server(certificates))
# key_genFiat(256, 1024)
q,c = getprime(512), getprime(512)
while not miller_rabin(2*q*c+1, 100):
    q, c = getprime(512), getprime(512)
print(2*q*c+1)