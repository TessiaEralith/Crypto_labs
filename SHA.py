from attack import btl, ltb

H = [[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
     [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
      0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    ]

K = [
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
    [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]
    ]

def Ch(x, y, z, mode):
    not_x = (1 << mode//8) - 1 ^ x
    return (x & y) ^ (not_x & z)


def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def rot(x, offset, mode):
    # for _ in range(offset):
    #     bit = x & 1
    #     x = x >> 1 | bit << (mode // 8 - 1)
    end_bits = x & (1 << offset) - 1
    x >>= offset
    end_bits <<= (mode // 8 - offset)
    return end_bits + x


def Σ0(x, mode):
    if mode == 256:
        return rot(x, 2, mode) ^ rot(x, 13, mode) ^ rot(x, 22, mode)
    return rot(x, 28, mode) ^ rot(x, 34, mode) ^ rot(x, 39, mode)


def Σ1(x, mode):
    if mode == 256:
        return rot(x, 6, mode) ^ rot(x, 11, mode) ^ rot(x, 25, mode)
    return rot(x, 14, mode) ^ rot(x, 18, mode) ^ rot(x, 41, mode)


def σ0(x, mode):
    if mode == 256:
        return rot(x, 7, mode) ^ rot(x, 18, mode) ^ (x >> 3)
    return rot(x, 1, mode) ^ rot(x, 8, mode) ^ (x >> 7)


def σ1(x, mode):
    if mode == 256:
        return rot(x, 17, mode) ^ rot(x, 19, mode) ^ (x >> 10)
    return rot(x, 19, mode) ^ rot(x, 61, mode) ^ (x >> 6)


def pad256(m):
    l = len(m)
    k = 447 - (l << 3) & 0x1ff
    return (btl(m) << 1 | 1) << k << 64 | l << 3


def pad512(m):
    l = len(m)
    k = 895 - (l << 3) & 0x3ff
    return (btl(m) << 1 | 1) << k << 128 | l << 3


def SHA256(m):
    H_i = []
    for i in range(8):
        H_i.append(H[0][i])
    if len(m) % 64 != 0:
        m = ltb(pad256(m))
    for i in range(len(m) // 64):
        a, b, c, d, e, f, g, h = H_i[0], H_i[1], H_i[2], H_i[3], H_i[4], H_i[5], H_i[6], H_i[7]
        W = []
        for t in range(64):
            if t < 16:
                w_t = btl(m[64*i + 4*t : 64*i + 4*(t+1)])
            else:
                w_t = σ1(W[t-2], 256) + W[t-7] + σ0(W[t-15], 256) + W[t-16] & 0xffffffff
            W.append(w_t)

            T_1 = h + Σ1(e, 256) + Ch(e, f, g, 256) + K[0][t] + w_t & 0xffffffff
            T_2 = Σ0(a, 256) + Maj(a, b, c) & 0xffffffff
            h, g, f = g, f, e
            e = d + T_1 & 0xffffffff
            d, c, b = c, b, a
            a = T_1 + T_2 & 0xffffffff

        H_i[0] = a + H_i[0] & 0xffffffff
        H_i[1] = b + H_i[1] & 0xffffffff
        H_i[2] = c + H_i[2] & 0xffffffff
        H_i[3] = d + H_i[3] & 0xffffffff
        H_i[4] = e + H_i[4] & 0xffffffff
        H_i[5] = f + H_i[5] & 0xffffffff
        H_i[6] = g + H_i[6] & 0xffffffff
        H_i[7] = h + H_i[7] & 0xffffffff

    result = H_i[0].to_bytes(4, 'big') + H_i[1].to_bytes(4, 'big') + H_i[2].to_bytes(4, 'big') + H_i[3].to_bytes(4, 'big') + \
        H_i[4].to_bytes(4, 'big') + H_i[5].to_bytes(4, 'big') + H_i[6].to_bytes(4, 'big') + H_i[7].to_bytes(4, 'big')
    result = hex(btl(result))[2:]
    return '0' * (64 - len(result)) + result


def SHA512(m):
    H_i = []
    for i in range(8):
        H_i.append(H[1][i])
    if len(m) % 64 != 0:
        m = ltb(pad512(m))
    for i in range(len(m) // 128):
        W = []
        a, b, c, d, e, f, g, h = H_i[0], H_i[1], H_i[2], H_i[3], H_i[4], H_i[5], H_i[6], H_i[7]
        for t in range(80):
            if t < 16:
                w_t = btl(m[128*i + 8*t : 128*i + 8*(t+1)])
            else:
                w_t = σ1(W[t-2], 512) + W[t-7] + σ0(W[t-15], 512) + W[t-16] & 0xffffffffffffffff
            W.append(w_t)

            T_1 = h + Σ1(e, 512) + Ch(e, f, g, 512) + K[1][t] + w_t & 0xffffffffffffffff
            T_2 = Σ0(a, 512) + Maj(a, b, c) & 0xffffffffffffffff
            h, g, f = g, f, e
            e = d + T_1 & 0xffffffffffffffff
            d, c, b = c, b, a
            a = T_1 + T_2 & 0xffffffffffffffff

        H_i[0] = a + H_i[0] & 0xffffffffffffffff
        H_i[1] = b + H_i[1] & 0xffffffffffffffff
        H_i[2] = c + H_i[2] & 0xffffffffffffffff
        H_i[3] = d + H_i[3] & 0xffffffffffffffff
        H_i[4] = e + H_i[4] & 0xffffffffffffffff
        H_i[5] = f + H_i[5] & 0xffffffffffffffff
        H_i[6] = g + H_i[6] & 0xffffffffffffffff
        H_i[7] = h + H_i[7] & 0xffffffffffffffff

    result = H_i[0].to_bytes(8, 'big') + H_i[1].to_bytes(8, 'big') + H_i[2].to_bytes(8, 'big') + H_i[3].to_bytes(8, 'big') + \
        H_i[4].to_bytes(8, 'big') + H_i[5].to_bytes(8, 'big') + H_i[6].to_bytes(8, 'big') + H_i[7].to_bytes(8, 'big')
    result = hex(btl(result))[2:]
    return '0' * (128 - len(result)) + result

def SHA2(m, mode):
    if mode == 256:
        return SHA256(m)
    elif mode == 512:
        return SHA512(m)
    return "Error! Wrong mode"

# print(SHA256(b'hello world'))
# print(SHA512(b'hello world'))
