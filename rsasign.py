import mimetypes
import json
import socket
from hash import Streebog
from SHA import SHA2
from attack import ltb, btl, padRSA, unpadRSA, genkeyRSA, powm


hash_funcs = {"SHA": SHA2, "GOST": Streebog}


def CAdES(mime_type, DigestAlgoritm, SignatureAlgorithm, message, SignatureValue, e, n):
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
        e = public_key['e']
        n = public_key['n']

    with open(path_to_keys, 'r') as f:
        private_key = json.load(f)
        d = private_key['d']

    mime_type, _ = mimetypes.guess_type(path_to_file)
    s = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))
    pudding_text = padRSA(ltb(int(s, 16)), 255)

    signed_text = hex(powm(btl(pudding_text), d, n))


    return CAdES(mime_type, hash_type, "RSAdsi", hex(btl(text)), signed_text, hex(e), hex(n))


def check_RSA(m, e, n, hash_type, signature, utc_time):
    text = ltb(int(m, 16)) + utc_time.encode('utf-8')

    reference_signature = hash_funcs[hash_type[:-3]](text, int(hash_type[-3:]))
    check_signature = powm(int(signature, 16), int(e, 16), int(n, 16))
    unpad_check_signature = hex(btl(unpadRSA(ltb(check_signature), 255)))[2:]

    return reference_signature == unpad_check_signature


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
        e, n = data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["e"], data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["certificate"]["n"]
        timestamp, signaturects = data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["timestamp"], data['SignerInfos']["UnsignedAttributes"]["SET_OF_AttributeValue"]["signature"]
        if check_RSA(m+signature[2:], e, n, hash_type, signaturects, timestamp):
            data['SignerInfos']["UnsignedAttributes"]["OBJECT_IDENTIFIER"] = timestamp
        return data
        # return response


certificate = sign("SHA256", "cipher.txt", "126a3301-1933-467d-a59f-1047625c04f0")

#certificate = {"CMSVersion": 1, "DigestAlgoritmIdentifiers": "SHA256", "EncapsulatedContentInfo": {"ContetntType": "text/plain", "OCTET_STRING_OPTIONAL": "0x68656c6c6f"}, "SignerInfos": {"CMSVersion": 1, "SignerIdentifier": "Eberzin Kirill", "DigestAlgoritmIdentifiers": "SHA256", "SignatureAlgorithmIdentifier": "RSAdsi", "SignatureValue": "0x5fb055525a68fb5a4aec017e777a0c54d0f8dd9c43be978cfa0d8d9d0cc0e01fb39641e9cd0c63f6b4957fdc363f8a0594c473e9dc1e60b4bc7c96f71f6cfd0f95e37cf328a55e879f34e110107050ff8035b431bb0be2f3fb7ce26365ae41954f28a46973872b7657a222ab62263e614915bc201ec495b786d540fb1a4d22d8a51b09729cbabad4eace45076209ea3f7d4f6a8879b8c76ebf196332e832b9df467817a83754ac1dcd4e9f234ef9bb2c90a45506bb792d50a8d67102fc815aabaaf77c0ec9e6b1e23236f74248a4737c6a98797101661ecfdfb14f9e46a0f18bef8b1b66703b73c6ce7bf0a6fcc8a64b38dad916dbfd9a91eb742ad6ca02b386", "SubjectPublicKeyInfo": {"e": "0xf443", "n": "0x6f255a7ac58f1aadf91f10315921695d40d8e1ebc02ad21cab3112982bc73575ae40d54315ff2e104ba24983118e16ad7f1b4b471e65693c1fe5e1c024b6b727bd2d3b919884e89706e4d1dd55ac80aa417529f764189c3e18c296201ffb8971a0204c740b31dfbb52804dcd4ec5ce746914866406bddbb0cc54c6d31d7c962636804a62b47f1a29be09761306b184ad7440998e7c53b3969ea249a7ed06757163451b26b7c30e80fdf9db43e1f7314991fb1fa91d447b255d165844836f87cd080e75120a755f8e5b2f72f9a736d7717205defdac73247f20ecc14a94d4d81dd6cd06272096513eb925e710fde6f848c276d5452fec7b3d05fd1efe8abcbe97"}}}
print(send_json_to_server(certificate))
