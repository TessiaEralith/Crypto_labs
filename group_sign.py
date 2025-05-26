import mimetypes
import json
import socket
from random import randint, shuffle
from hash import Streebog
from SHA import SHA2
from attack import *

hash_funcs = {"SHA": SHA2, "GOST": Streebog}
g = 2


def keygen_lead(bits):
    return genkeyRSA(1024)


def keygen_group(bits, socket_array):
    q, c = getprime(bits // 2), getprime(bits // 2)
    while not miller_rabin(2 * q * c + 1, 100):
        q, c = getprime(bits // 2), getprime(bits // 2)
    p = 2 * q * c + 1
    a = randint(2, p - 2)
    while not (powm(a, 2 * q, p) != 1 and powm(a, 2 * c, p) != 1 and powm(a, c * q, p) != 1):
        a = randint(2, p - 2)
    alpha = powm(a, 2 * c, p)

    public_key = {
        'p': p,
        'alpha': alpha,
        'q': q
    }
    P = []
    for i in range(g):
        k = randint(2, q - 2)
        P.append(powm(alpha, k, p))
        private_key = {
            'k': k,
        }
        # index = randint(0, 1)
        socket_array[i].sendall(json.dumps(private_key).encode('utf-8'))
        socket_array[i].sendall(json.dumps(public_key).encode('utf-8'))
    public_key['P'] = P
    z = randint(2, q - 2)
    public_key['L'] = powm(alpha, z, p)
    private_key_lead = {
        'z': z,
    }
    with open("group_keys" + '.pub', 'w') as f:
        json.dump(public_key, f, indent=4)
    with open("group_keys", 'w') as f:
        json.dump(private_key_lead, f, indent=4)


def CAdES(mime_type, DigestAlgoritm, SignatureAlgorithm, message, SignatureValue, p, alpha, q, P, L):
    certificate = {
        "CMSVersion": 1,
        "DigestAlgoritmIdentifiers": DigestAlgoritm,  # GOST512, GOST256, SHA512, SHA256
        "EncapsulatedContentInfo": {
            "ContetntType": mime_type,  # MIME type
            "OCTET_STRING_OPTIONAL": message
        },
        "SignerInfos": {
            "CMSVersion": 1,
            "SignerIdentifier": "Eberzin Kirill group",
            "DigestAlgoritmIdentifiers": DigestAlgoritm,  # GOST512, GOST256, SHA512, SHA256
            "SignatureAlgorithmIdentifier": SignatureAlgorithm,  # RSAdsi, DSAdsi, ...
            "SignatureValue": SignatureValue,
            "SubjectPublicKeyInfo": {
                "p": p,
                "alpha": alpha,
                "q": q,
                "P": P,
                "L": L

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


def sign(path_to_file, hash_type, socket_array):
    with open(path_to_file, 'rb') as f:
        text = f.read()

    with open("group_keys.pub", 'r') as f:
        public_key = json.load(f)
        P = public_key['P']
        p = public_key['p']
        q = public_key['q']
        L = public_key['L']
        alpha = public_key['alpha']

    with open("group_keys", 'r') as f:
        private_key = json.load(f)
        z = private_key['z']

    with open("50427282-efc5-45ee-9d18-d520af3f2947", 'r') as f:
        private_key = json.load(f)
        d = private_key['d']
        n = private_key['p'] * private_key['q']

    mime_type, _ = mimetypes.guess_type(path_to_file)
    H = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))
    H = int(H, 16)
    U = 1
    lamda = []
    R_all = []
    R = 1
    for i in range(g):  # 1 шаг и немного 3
        lamda_i = powm(H + P[i], d, n)
        lamda.append(lamda_i)
        U = (U * powm(P[i], lamda[i], p)) % p
        socket_array[i].sendall(ltb(lamda_i))
        R_i = btl(socket_array[i].recv(1024))
        R = (R_i * R) % p
        R_all.append(R_i)
    T = randint(2, q - 1)
    R = (R * powm(alpha, T, p)) % p  # конец 3 шага

    E = int(hash_funcs[hash_type[:-3]](text + ltb(R) + ltb(U), int(hash_type[-3:])), 16)
    S = 0
    for i in range(g):
        socket_array[i].sendall(ltb(E))
        S_i = btl(socket_array[i].recv(1024))
        if R_all[i] != (powm(P[i], -lamda[i] * E, p) * powm(alpha, S_i, p)) % p:
            print("error")
            break
        S = (S + S_i) % q
    S = (S + T + z * E) % q
    return CAdES(mime_type, hash_type, "group signature", hex(btl(text)), (hex(U), hex(E), hex(S)), hex(p), hex(alpha), hex(q), P, hex(L))


def check_RSA(m, e, n, hash_type, signature, utc_time):
    text = ltb(int(m, 16)) + utc_time.encode('utf-8')

    reference_signature = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))
    check_signature = powm(int(signature, 16), int(e, 16), int(n, 16))
    unpad_check_signature = hex(btl(unpadRSA(ltb(check_signature), 255)))[2:]

    return reference_signature == unpad_check_signature


def send_json_to_server(certificate, host='localhost', port=12347):
    m, hash_type, signature = certificate["EncapsulatedContentInfo"]["OCTET_STRING_OPTIONAL"], certificate["DigestAlgoritmIdentifiers"], certificate["SignerInfos"]["SignatureValue"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Отправляем JSON на сервер
        json_data = json.dumps(certificate)
        s.sendall(json_data.encode('utf-8'))

        # Получаем ответ от сервера
        response = s.recv(65536).decode('utf-8')
        data = json.loads(response)
        e, n = data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["e"], data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["n"]
        timestamp, signaturects = data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["timestamp"], data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["signature"]
        if check_RSA(m+signature[0][2:]+signature[1][2:]+signature[2][2:], e, n, hash_type, signaturects, timestamp):
            data['SignerInfos']["UnsignedAttributes"]["OBJECT_IDENTIFIER"] = timestamp
        return data
        # return response



host = 'localhost'
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.connect((host, 12345))
s2.connect((host, 12346))
S = [s1, s2]
certificate = sign("cipher.txt", "SHA256", S)
print(send_json_to_server(certificate))

# shuffle(S)
# genkeyRSA(1024)
# keygen_group(1024, S)
