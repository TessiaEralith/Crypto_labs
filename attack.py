import string

from Crypto.Util.number import sieve_base, bytes_to_long as b2l, long_to_bytes as l2b 
from sympy.ntheory import factorint
import numpy as np
import math
import random
import time
import timeit
import json
import mimetypes
import uuid

class Field:
    
    def gen_coeff(self, num):
        coeff = []
        while num!=0:
            coeff.append(num % self.characteristic)
            num//= self.characteristic
        return coeff[::-1]


    def gen_field(self):
        field = []
        for i in range(self.characteristic**self.n):
            coeff = self.gen_coeff(i)
            poly = np.poly1d(coeff)
            field.append(poly)
        return field
    
    
    def gen_poly(self):
        k = []
        for _ in range(self.n):
            k.append(random.randint(0, self.characteristic-1))
        k.append(random.randint(1, self.characteristic-1))
        x = np.poly1d(k[::-1])
        return x
    
    
    def gen_prime_poly(self):
        while 1:
            probably_prime_poly = self.gen_poly()
            size = pow(self.characteristic, self.n)
            result_field = []
            right_field = self.gen_field()
            for i in range(1, size):
                res = [np.poly1d([0])]
                for j in range(1, size):
                    _, mul = np.polydiv(np.polymul(right_field[i], right_field[j]), probably_prime_poly)
                    m = mul.coeffs
                    for l in range(len(m)):
                        m[l] %= self.characteristic
                    mul = np.poly1d(m)
                    if mul not in res and mul != np.poly1d([0]):
                        res.append(mul)
                    else: 
                        break
                if len(res) != len(right_field):
                    break
                else: result_field.append(res)
            else:
                return probably_prime_poly
            
                      


    def __init__(self, value, characteristic, n = 1):
        self.characteristic = characteristic
        self.n = n
        self.value = value
        
        self.prime_poly = self.gen_prime_poly()
    

    def __add__(self, other):
        if isinstance(other, Field) and self.characteristic == other.characteristic:
            su = np.polyadd(self.value, other.value)
            coeff = su.coeffs
            res = []
            for i in coeff:
                res.append(i % self.characteristic)
            polynome = np.poly1d(res)
            return Field(polynome, self.characteristic, polynome.o)
        return NotImplemented

    def __mul__(self, other):
        if self.n >= other.n:
            n = self.n
            prime_poly = self.prime_poly
        else:
            n = other.n
            prime_poly = other.prime_poly
        if isinstance(other, Field) and self.characteristic == other.characteristic:
            _, mul = np.polydiv(np.polymul(self.value, other.value), prime_poly)
            m = mul.coeffs
            for l in range(len(m)):
                m[l] %= self.characteristic
            mul = np.poly1d(m)
            return Field(mul, self.characteristic, n)
        return NotImplemented

def gcd_extendedv2(num1, num2):
    a2, a1, b2, b1 = 1, 0, 0, 1
    while num2 != 0:
        q = num1 // num2
        r, a, b = num1 - q*num2, a2 - q*a1, b2 - q*b1
        num1, num2, a2, a1, b2, b1 = num2, r, a1, a, b1, b
    return num1, a2, b2


def solve_m1(a, b, m):
    d, u, _ = gcd_extendedv2(a, m)
    if b % d != 0:
        return "Error! b not divisible by d"
    m1, a, b = m // d, a //  d, b // d
    x = []
    for i in range(d):
        res =(u * b + m1 * i)%m
        x.append(res)
        print(f"x ≡ {res} (mod {m})")
    x.sort()
    return x
print(solve_m1(-5, 6, 107))
# print(solve_m1(1148, 2219, 2709))

def powv2(n, e):
    x = 1
    while e:
        if e & 1:
            x *= n
        n *= n
        e >>= 1
    return x

def powm(n, e, m):
    x = 1
    if e == -1:
        x = solve_m1(n, 1, m)
        return x[0]
    while e:
        if e & 1:
            x = (x * n) % m
        n = (n * n) % m
        e >>= 1
    return x

def miller_rabin(n, k):

    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False
    if n == 1:
        return True
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = powm(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = powm(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


    

def continued_fraction(p, q):
    res = []
    b = 1
    while b != 0:
        res.append(p // q)
        b = p % q
        p = q
        q = b
    return res


def suitable_fraction(p, q):
    coefficient = continued_fraction(p, q)
    P, Q = [coefficient[0], coefficient[0] * coefficient[1] + 1], [1, coefficient[1]]
    for i in range(2, len(coefficient)):
        P.append(P[i - 1] * coefficient[i] + P[i - 2])
        Q.append(Q[i - 1] * coefficient[i] + Q[i - 2])
    return P, Q


def attack(e, n):
    P, Q = suitable_fraction(e, n)
    p, q = 1, 1
    for i in range(len(continued_fraction(e, n))):
        p, q = P[i], Q[i]
        if p == 0:
            continue
        if (e * q) % p == 1:
            print(p)
            break
    return q


def yakobi(a, n):
    g = 1
    s = 0
    while 1:
        if a == 0:
            return 0
        elif a == 1:
            return g
        k = 0
        while a % 2 != 1:
            a //= 2
            k += 1
        a1 = a
        if (k % 2 == 0) or (n % 8 == 1) or (n % 8 == 7):
            s = 1
        elif (n % 8 == 3) or (n % 8 == 5):
            s = -1
        if a1 == 1: return g * s
        if (n % 4 == 3) and (a1 % 4 == 3): s = -s
        a = n % a1
        n = a1
        g *= s
        # print(f'k = {k}\ns = {s}\na = {a}\nn = {n}\ng = {g}\n')


def solovey_shtrassen(n, k):
    for _ in range(k):
        a = random.randrange(2, n-2)
        r = powm(a, (n-1)//2, n)
        if r != 1 and r != n - 1:
            return False
        s = yakobi(a, n) % n
        if s != r:
            return False
    return True

def find_khN(p):
    N = 1
    while yakobi(N, p) != -1:
        N += 1
    p -= 1
    k = 0
    while p % 2 != 1:
        p //= 2
        k += 1
    return k, p, N


def check_root(a, m):
    n = 0
    while m % 2 == 0:
        n += 1
        m //= 2
    if n >= 3 and a % 8 == 1:
        return True
    elif n == 2 and a % 4 == 1:
        return True

def solve_p2(a, p):
    if yakobi(a, p) != 1:
        print("not root")
        return None
    k, h, N = find_khN(p)
    a1 = powm(a, (h + 1) // 2, p)
    a2 = powm(a, -1, p)
    N1 = powm(N, h, p)
    N2 = 1
    j = 0
    for i in range(k - 1):
        b = a1 * N2 % p
        c = a2 * powm(b, 2, p) % p
        d = powm(c, powv2(2, k - 2 - i), p)
        if d == 1:
            j = 0
        elif d == p - 1:
            j = 1
        N2 = N2 * powv2(N1, powv2(2, i) * j) % p
    return a1 * N2 % p
print(solve_p2(14, 193))

def gcd(num1, num2):
    while num1 != 0:
        num2 %= num1
        num1, num2 = num2, num1
    return num2



# def powm(n, e, m):
#     x = 1
#     while e:
#         if e & 1:
#             x = (x * n) % m
#         n = (n * n) % m
#         e >>= 1
#     return x


def ferma(n, t):
    for i in range(t):
        a = random.randint(2, n-2)
        if powm(a, n-1, n) != 1:
            return "composite"
    return "probably prime"


def getbits(n):
    res = 1
    for i in range(n-2):
        res <<= 1
        res += random.randint(0, 1)
    res <<= 1
    res += 1
    return res

def getprime(n):
    p = getbits(n)
    while not miller_rabin(p, 100): 
        p = getbits(n)
    return p




def gcd_extended(num1, num2):
    if num1 == 0:
        return 0, 1
    else:
        x, y = gcd_extended(num2 % num1, num1)
    return y - (num2 // num1) * x, x


def pairs_gcd(list):
    for i in range(len(list) + 1):
        for j in range(i + 1, len(list)):
            if gcd(list[i], list[j]) != 1:
                return False
    return True


def crt(m, a):
    if (len(m) != len(a)):
        print("Error len")
        return None
    if not (pairs_gcd(m)):
        try:
            M = math.lcm(*m)
            sum_alpha = 0
            sum_a = 0
            for i in range(len(m)):
                alpha = M // m[i]
                sum_alpha += alpha
                sum_a += a[i] * alpha
            return (sum_a * pow(sum_alpha, -1, M)) % M
        except:
            return None
    M = math.prod(m)
    x = 0
    for i in range(len(m)):
        n = pow(M // m[i], -1, m[i])
        x += M // m[i] * a[i] * n % M
    return x % M

def prod(m):
    res = 1
    for i in m:
        res *= i
    return res

def crt_lagrange(m, a):
    if (len(m) != len(a)):
        print("Error len")
        return None
    if not (pairs_gcd(m)):
        return None
    M = prod(m)
    x = 0
    for i in range(len(m)):
        n = pow(M // m[i], -1, m[i])
        x += M // m[i] * a[i] * n % M
    return x % M

def crt_garner(m, a): #долго работает, лучше использовать первую версию
    n = len(m)
    x = [0 for _ in range(n)]
    result = 0
    for i in range(n):
        x[i] = a[i]
        for j in range(i):
            if (i == j): continue
            r = pow(m[j], -1, m[i])
            x[i] = r * (x[i] - x[j])
            x[i] %= m[i]
        M = math.prod(m[:i])
        result += x[i] * M
    return result % math.lcm(*m)

def crt_extended(m, a):
    M = math.lcm(*m)
    sum_alpha = 0
    sum_a = 0
    for i in range(len(m)):
        alpha = M // m[i]
        sum_alpha += alpha
        sum_a += a[i] * alpha
    return (sum_a * pow(sum_alpha, -1, M)) % M



m = [52, 51, 50, 49, 48, 47, 46, 45, 44, 43]
a = [29, 3, 37, 27, 9, 8, 43, 42, 33, 10]
# print(crt(m, a))



def isqrt(n):
  x = n
  y = (x + n // x) // 2
  while y < x:
    x = y
    y = (x + n // x) // 2
  return x

def fermat(n):
    a = isqrt(n) # int(ceil(n**0.5))
    b2 = a*a - n
    b = isqrt(n) # int(b2**0.5)
    count = 0
    while b*b != b2:
        a = a + 1
        b2 = a*a - n
        b = isqrt(b2) # int(b2**0.5)
        count += 1
    p=a+b
    q=a-b
    assert n == p * q
    print('a=',a)
    print('b=',b)
    print('p=',p)
    print('q=',q)
    print('pq=',p*q)
    return p, q


def comp_func(x, n):
    return (powm(x, 2, n) + 1) % n

def factorintp(n, k):
    for _ in range(k):
        c = random.randrange(0, n-1)
        a, b = c, c
        while(1):
            a, b = comp_func(a, n), comp_func(comp_func(b, n), n)
            d = gcd(a - b, n)
            if d > 1 and d < n:
                return d
            elif d == n:
                break

def gen_sieve_base(n):
    base = []
    for i in sieve_base:
        if i*i > n:
            return base
        elif i * i == n:
            # print(f"found n = {i}^2")
            base.append(i)
            return base
        elif random.randint(-n, n) % 2 == 0:
            base.append(i)
    return base

def factorintp_1(n, k):
    for _ in range(k):
        base = gen_sieve_base(n)
        a = random.randrange(2, n-2)
        d = gcd(a, n)
        if d >= 2:
            return d
        for i in base:
            l = int(math.log(n)/math.log(i))
            a = powm(a, powv2(i,l), n)
        d = gcd(a-1, n)
        if d == 1 or d == n:
            continue
        else: 
            return d

def factorint(n, k = 1000):
    result = {}
    e = 0
    while n&1 == 0:
        n >>= 1
        e += 1
    if e != 0:
        result[2] = e
    while not (miller_rabin(n, 100)):
        try:
            d = factorintp_1(n, k)
        except:
            d = factorintp(n, k)
        e = 0
        if d != None:
            while n % d == 0:
                n //= d
                e +=1
            div = factorint(d, k)
            for i in div:
                div[i] *= e
            result.update(div)
    if n!= 1:
        result[n] = 1 
    return dict(sorted(result.items()))


def get_divisors(prime_factors):
    divisors = [1]
    for prime, exponent in prime_factors.items():
        new_divisors = []
        for i in range(1, exponent + 1):
            for d in divisors:
                div = pow(prime, i) * d
                if div not in divisors:
                    new_divisors.append(div)
        divisors.extend(new_divisors)
    divisors.sort()
    return divisors

def branching_function(a, b, c, p):
    if c < (p-1) // 2:
        return (a*c) % p
    else:
        return (b*c) % p

def log(c, p, r, uv):
    if c < (p-1) // 2:
        uv['u'] = (uv['u'] + 1) % r
    else:
        uv['v'] = (uv['v'] + 1) % r
    return uv

def discrete_log(a, b, p, k = 10000):
    u, v = 2, 2
    d = get_divisors(factorint(p-1))
    order = 0
    for o in d:
        if powm(a, o, p) == 1:
            order = o
            break
    c = (powm(a, u, p) * powm(b, v, p)) % p 
    d = c
    uvc, uvd = {'u': 2, 'v': 2}, {'u': 2, 'v': 2}
    print(0, c, d, uvc, uvd, order)
    for _ in range(1, p//2):
        
        c, uvc = branching_function(a, b, c, p), log(c, p, order, uvc)
        d , uvd = branching_function(a, b, d, p), log(d, p, order, uvd)
        d , uvd = branching_function(a, b, d, p), log(d, p, order, uvd)
        print(_, c, d, uvc, uvd, order)
        if (c % p) == (d % p):
            
            x = solve_m1(uvd['v']-uvc['v'], uvc['u']-uvd['u'], order)
            return x[0]

# print(discrete_log(3, 2, 11))
# print(discrete_log(10, 64, 107))
def gen_filename():
    random_uuid = uuid.uuid4()
    return str(random_uuid)

def genkeyRSA(bits):
    p, q = getprime(bits), getprime(bits)
    n, phi = p*q, (p-1) * (q-1)
    e = random.randint(11, powv2(2, 16))
    while gcd(phi, e) != 1:
        e = random.randint(11, powv2(2, 16))
    d = powm(e, -1, phi)
    filename = gen_filename()
    
    public_key = {
        'e': e,
        'n': n
    }
    private_key = {
        'd': d,
        'p': p,
        'q': q,
        'exponent1': d % (p - 1),
        'exponent2': d % (q - 1),
        'cpefficient': powm(q, -1, p)
    }

    with open(filename + '.pub', 'w') as f:
        json.dump(public_key, f, indent=4)
    with open(filename, 'w') as f:
        json.dump(private_key, f, indent=4)
    print(f"Key gen in {filename}")


def btl(s):
    return int.from_bytes(s, 'big')


def ltb(n):
    s = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return s


def padRSA(text, size):
    new_text = b''
    blocks = len(text)//(size-1)
    for i in range(blocks):
        new_text += (text[i*(size-1):(i+1)*(size-1)])
        new_text += b'\x01'
    new_text += text[blocks*(size-1):]
    pad = (size - len(new_text) % size) % size
    new_text += (pad.to_bytes(1, 'big') * pad)
    return new_text


def unpadRSA(text, size):
    unpad = text[-1]
    if unpad != 0:
        text = text[:-unpad]
    else:
        text = tex
    unpad_text = b''
    blocks = len(text)//(size)
    for i in range(0, blocks):
        unpad_text += text[size*i:(i+1)*(size)-1] 
    unpad_text += text[blocks * size:]
    return unpad_text


def RSA(path_to_file, path_to_keys, action): 
    if action == "encrypt":
        mime_type, _ = mimetypes.guess_type(path_to_file)
        cipher = ''
        with open(path_to_keys + ".pub", 'r') as f:
            public_key = json.load(f)
            e = public_key['e']
            n = public_key['n']

        with open(path_to_file, 'rb') as f:
            text = f.read()

        text = padRSA(text, 255)

        for i in range(len(text)//255):
            cipher_part = hex(powm(btl(text[i*255:(i+1)*255]), e, n))[2:]
            if len(cipher_part) < 512:
                cipher_part = (512 - len(cipher_part))*'0' + cipher_part
            cipher += cipher_part

        data = {
        "Version": 0,
        "EncryptedContentInfo": {
            "ContentType": mime_type,
            "ContentEncryptionAlgorithmIdentifier": "rsaEncryption",
            "encryptedContent": cipher, 
            "OPTIONAL": {} 
            }
        }
        with open(f'{path_to_file}_encrypted', 'w') as f:
            json.dump(data, f, indent=4)
        return "Encrypted"
    elif action == "decrypt":
        text = b''
        with open(path_to_keys, 'r') as f:
            private_key = json.load(f)
            d = private_key['d']
            p = private_key['p']
            q = private_key['q']

        with open(path_to_file, 'r') as f:
            data = json.load(f)
        
        cipher = data['EncryptedContentInfo']['encryptedContent']

        for i in range(0, len(cipher), 512):
            cipher_part = cipher[i:i+512]
            part_text = ltb(powm(int("0x" + cipher_part, 16), d, p*q))
            if len(part_text) < 255:
               part_text = (0).to_bytes(1, 'big') * (255 - len(part_text)) + part_text
            text += part_text
      
        text = unpadRSA(text, 255)

        with open(f'{path_to_file}_decrypted', 'wb') as f:
            f.write(text)
        return "Decrypted"
    else:
        print("Unknown operation")
        return None

# RSA('Бумажный_Федя.pdf','1733324568938552', 'encrypt')
# RSA('Бумажный_Федя.pdf_encrypted','1733324568938552', 'decrypt')


def key_genRabin(bits):
    p, q = getprime(bits), getprime(bits)
    while p % 4 != 3:
        p = getprime(bits)
    while q % 4 != 3:
        q = getprime(bits)
    filename = gen_filename()
    
    public_key = {
        'n': p*q
    }
    private_key = {
        'p': p,
        'q': q
    }
    with open(filename + '.pub', 'w') as f:
        json.dump(public_key, f, indent=4)
    with open(filename, 'w') as f:
        json.dump(private_key, f, indent=4)
    print(f"Key gen in {filename}")

def Rabin(action, path_to_keys = "None"):
    if action == "encrypt":
        with open(path_to_keys + ".pub", 'r') as f:
            public_key = json.load(f)
            n = public_key['n']
        text = btl(input("Введите текст: ").encode())
        return powm(text, 2, n)

    elif action == "decrypt":
        with open(path_to_keys, 'r') as f:
            private_key = json.load(f)
            p = private_key['p']
            q = private_key['q']
            n = p*q
        
        cipher = int(input("Введите шифр(числом): "))
        _, y_p, y_q = gcd_extendedv2(p, q)
        m_p, m_q = powm(cipher, (p+1)//4, p), powm(cipher, (q+1)//4, q)
        m1, m3 = (y_p * m_q * p + y_q * m_p * q ) % n, (y_p * m_q * p - y_q * m_p * q ) % n 
        m2, m4 = n - m1, n - m3
        return [ltb(m1), ltb(m2), ltb(m3), ltb(m4)]
    
    elif action == "gen_key":
        bits = int(input("Введите размерность ключа: "))
        key_genRabin(bits)
        return
# Rabin("gen_key")
# print(Rabin("encrypt", "84e10244-68aa-4422-a1ff-d7d5d8f9631a"))
# print(Rabin("decrypt", "84e10244-68aa-4422-a1ff-d7d5d8f9631a"))


def get_primitive(p):
    order = 0
    d = get_divisors(factorint(p-1))
    while order != p-1:
        alpha = random.randint(2, p-1)
        for o in d:
            if powm(alpha, o, p) == 1:
                order = o
                if order != p - 1:
                    break
    return alpha


def key_genEl_Gamal(bits):
    p = getprime(bits)
    a = random.randint(1, p-1)
    d = get_divisors(factorint(p-1))
    alpha = get_primitive(p)
    betta = powm(alpha, a, p)

    filename = gen_filename()
    
    public_key = {
        'p': p,
        'alpha': alpha,
        'betta': betta
    }
    private_key = {
        'a': a
    }
    with open(filename + '.pub', 'w') as f:
        json.dump(public_key, f, indent=4)
    with open(filename, 'w') as f:
        json.dump(private_key, f, indent=4)
    print(f"Key gen in {filename}")


def El_Gamal(action, path_to_keys = "None"):
    if action == "encrypt":
        with open(path_to_keys + ".pub", 'r') as f:
            public_key = json.load(f)
            p = public_key['p']
            alpha = public_key['alpha']
            betta = public_key['betta']
        text = btl(input("Введите текст: ").encode())

        r = random.randint(0, p-2)
        c1, c2 = powm(alpha, r, p), (text*powm(betta, r, p)) % p
        return (c1, c2)

    elif action == "decrypt":
        with open(path_to_keys + ".pub", 'r') as f:
            public_key = json.load(f)
            p = public_key['p']
        with open(path_to_keys, 'r') as f:
            private_key = json.load(f)
            a = private_key['a']
        
        c1, c2 = map(int, input().split(','))
        m = (c2 * powm(powm(c1, a, p), -1, p)) % p
        return ltb(m)
    
    elif action == "gen_key":
        bits = int(input("Введите число: "))
        key_genEl_Gamal(bits)


def b64_encode(string):
    alf = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if not isinstance(string, bytes):
        string = string.encode('utf8')
    result = '=' * (3 - len(string)%3)
    string = btl(string)
    if '=' in result:
        string <<= (result.count('=') * 2)
    while string > 0:
        result = alf[string & 0x3f] + result
        string >>= 6
    return result


def b64_decode(string):
    alf = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    result = 0
    end_string_index = string.count('=')
    string = string[:-end_string_index]
    for i in string:
        result <<= 6
        result |= alf.index(i)
    result >>= (2 * end_string_index)
    return ltb(result)

# for i in range(1000):
#     s = getprime(100)
#     b64 = b64_encode(ltb(s))
#     decoded = b64_decode(b64)
#     if ltb(s) != decoded:
#         print(s)
#         break

def b32_pad(string):
    dic_str = {1:'======', 2:'====', 3:'===', 4:'=', 0:''}
    dic_bits = {1:2, 2:4, 3:1, 4:3, 0:0}
    return dic_str[len(string) % 5], dic_bits[len(string) % 5]


def b32_unpad(string):
    dic_bits = {6:2, 4:4, 3:1, 1:3, 0:0}
    return  dic_bits[string.count('=')]

def b32_encode(string):
    alf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    if not isinstance(string, bytes):
        string = string.encode('utf8')
    result, bits_padding_len = b32_pad(string)
    string = btl(string)
    if '=' in result:
        string <<= bits_padding_len
    while string > 0:
        result = alf[string & 0x1f] + result
        string >>= 5
    return result


def b32_decode(string):
    alf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    result = 0
    bits_unpad_len = b32_unpad(string)
    end_string_index = string.count('=')
    string = string[:-end_string_index]
    for i in string:
        result <<= 5
        result |= alf.index(i)
    result >>= bits_unpad_len
    return ltb(result)

for i in range(1000):
    s = getprime(25)
    b32 = b32_encode(ltb(s))
    decoded = b32_decode(b32)
    if ltb(s) != decoded:
        print(s)
        break

# El_Gamal("gen_key")
# print(El_Gamal("encrypt", "1c1c0b8f-dc0b-4904-b414-2b4b1dd4ad29"))
# print(El_Gamal("decrypt", "1c1c0b8f-dc0b-4904-b414-2b4b1dd4ad29"))

# print(long_to_bytes(pow(c, d, n)))
# while not b"RDGCTF{" in long_to_bytes(pow(c, d, n)):
#     k += 1
#     d = attack(e, n, k)
# #

# a = 14952342227559366099719941386076058435614351428884763924901190367792414784074564892057879585025309595847684554219482517762987599677975603066559012828078320808309786516568154754232094595153442894381728000304148448831889330924452896802717849965565181028078944699888327313897078645437169518932593791065010120978089546873060274780772501105053374706153387946424375723099098019811069139117252764840752194408759130169846223491391000281483083344974652793531663680387249173672554095462230843857631798396392752936549252240621054303150335033172333938777005594392856740986308347936967577051680995552060936276503732282166098037992
# b = 5616684565046349371552297148121358673036243455915112457566766393105726751045068745823215689908895952497298287701722048346611888447895498526554170229019964654683171266437275101129316950453597861163778357340195404469482834612302204632306352174417078526923055161433947392883747363580895849985110378031423292659600271987886978409954669492265817466976879348552206777708533803762545052095100889962058582705822448953441316359838685184433066083199471892206922243471083349279019709579436074984432994932651932979070964873376199260537871479115699199989227614913216323385050643746149703222828737577832194195815970690189830696101
# z = 13104239217631655422319315146706823019010613107057156425929475912213089398363100723192298089951674573328913989447963267114786857023548912245106766391860727403863689591669105722029964132457780732569950038809750495617535056286844478175070346451303591672485014698598708767765817234979781058499709612841412914581408208329650809971390456786555625355749200250077725957285979513359547677575848964702410734344950964589365856143460462619500741543510198582722770378590679355988981072251485245180835339711315233466142755413824968478748900244983209797349906676961778724138651164868782637475420189279574582093019222618850380443020
# p = 31586223145127639493327658066878834204140160656700372121917806652983980256375739545954841423527843886820549832566205280333270975438649963799600772989143215326283472877345289042490733761771264659786250812950087494998948875542101415528465008565998665009814606956071982039729471707340164420098308494463731182991653040846845486555823803727073520151929159324216724366935036946054693858995492135698511947472613954153735530203722835595779264225971987468013732469978525944428083186952208285026331343823253594243173481644108930765362088349667633117817655121978240456454252134830867826419767573282159879635952365835771338817489
# N = 28973379127013522374951294189879900178554014672182678643808338373425028176538750103508992977435065675844147448418494148760366715428666057420737497218343679104707753492381102073004805294949314273103182866637101785991731611600229334401255972193630606372538438205714622440160885379438483257350780021299894221372895666555268885108846800535626434084493908945119876434991580076269833720095302174403556495730356789636803910480370687369837142830261665762518912011626899599687593191068749160258688008170131946758248650367338955439760786736383237951814351430731313281532918692823604125907588833966019758016988291013147978107127
# A = Matrix([[1,0, 0, a*N],
#             [0, 1, 0, b*N],
#             [0, 0, 1, z*N],
#             [0, 0, 0, N*n]])
# S = A.LLL()
# x = Integer(S[0][0])
# y = Integer(S[0][1])
# print(x)
# print(y)
