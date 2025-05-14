from SHA import SHA2
from hash import Streebog
from attack import btl

hash_funcs = {"SHA": [SHA2, 4], "STREEBOG": [Streebog, 8]}

def HMAC(m, K, function, mod):
    b = mod // hash_funcs[function][1]
    ipad = btl(b'\x36' * b)
    opad =btl(b'\x5c' * b)
    if len(K) <= b:
        K += b'\x00' *  (b - len(K))
        K = btl(K)
    else:
        K = hash_funcs[function][0](K, mod)
        K = int(K, 16)

    in_text = (K ^ ipad).to_bytes(b, 'big') + m
    in_hash = hash_funcs[function][0](in_text, mod)

    out_text = (K ^ opad).to_bytes(b, 'big') + int(in_hash, 16).to_bytes(mod // 8, 'big')
    return hash_funcs[function][0](out_text, mod)

# print(hash_funcs["SHA"][0](b'hello world', 256))

print(HMAC(b'hello world', b'secret', "SHA", 256))
