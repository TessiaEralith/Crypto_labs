import string

from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from sympy.ntheory import factorint
import math
import random
import time
import timeit
def miller_rabin(n, k):

    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
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
    a1 = pow(a, (h + 1) // 2, p)
    a2 = pow(a, -1, p)
    N1 = pow(N, h, p)
    N2 = 1
    j = 0
    for i in range(k - 1):
        b = a1 * N2 % p
        c = a2 * pow(b, 2, p) % p
        d = pow(c, pow(2, k - 2 - i), p)
        if d == 1:
            j = 0
        elif d == p - 1:
            j = 1
        N2 = N2 * pow(N1, 2 ** i * j) % p
    return a1 * N2 % p


def gcd_extended(num1, num2):
    if num1 == 0:
        return 0, 1
    else:
        x, y = gcd_extended(num2 % num1, num1)
    return y - (num2 // num1) * x, x


def pairs_gcd(list):
    for i in range(len(list) + 1):
        for j in range(i + 1, len(list)):
            if math.gcd(list[i], list[j]) != 1:
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

def crt_lagrange(m, a):
    if (len(m) != len(a)):
        print("Error len")
        return None
    if not (pairs_gcd(m)):
        return None
    M = math.prod(m)
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
print(crt(m, a))



def isqrt(n):
  x = n
  y = (x + n // x) // 2
  while y < x:
    x = y
    y = (x + n // x) // 2
  return x

def fermat(n, verbose=True):
    a = isqrt(n) # int(ceil(n**0.5))
    b2 = a*a - n
    b = isqrt(n) # int(b2**0.5)
    count = 0
    while b*b != b2:
        if verbose:
            print('Trying: a=%s b2=%s b=%s' % (a, b2, b))
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
