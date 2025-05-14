from attack import btl, ltb
A = [
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
]

pi = [
    0xfc, 0xee, 0xdd, 0x11, 0xcf, 0x6e, 0x31, 0x16, 0xfb, 0xc4, 0xfa, 0xda, 0x23, 0xc5, 0x04, 0x4d,
    0xe9, 0x77, 0xf0, 0xdb, 0x93, 0x2e, 0x99, 0xba, 0x17, 0x36, 0xf1, 0xbb, 0x14, 0xcd, 0x5f, 0xc1,
    0xf9, 0x18, 0x65, 0x5a, 0xe2, 0x5c, 0xef, 0x21, 0x81, 0x1c, 0x3c, 0x42, 0x8b, 0x01, 0x8e, 0x4f,
    0x05, 0x84, 0x02, 0xae, 0xe3, 0x6a, 0x8f, 0xa0, 0x06, 0x0b, 0xed, 0x98, 0x7f, 0xd4, 0xd3, 0x1f,
    0xeb, 0x34, 0x2c, 0x51, 0xea, 0xc8, 0x48, 0xab, 0xf2, 0x2a, 0x68, 0xa2, 0xfd, 0x3a, 0xce, 0xcc,
    0xb5, 0x70, 0x0e, 0x56, 0x08, 0x0c, 0x76, 0x12, 0xbf, 0x72, 0x13, 0x47, 0x9c, 0xb7, 0x5d, 0x87,
    0x15, 0xa1, 0x96, 0x29, 0x10, 0x7b, 0x9a, 0xc7, 0xf3, 0x91, 0x78, 0x6f, 0x9d, 0x9e, 0xb2, 0xb1,
    0x32, 0x75, 0x19, 0x3d, 0xff, 0x35, 0x8a, 0x7e, 0x6d, 0x54, 0xc6, 0x80, 0xc3, 0xbd, 0x0d, 0x57,
    0xdf, 0xf5, 0x24, 0xa9, 0x3e, 0xa8, 0x43, 0xc9, 0xd7, 0x79, 0xd6, 0xf6, 0x7c, 0x22, 0xb9, 0x03,
    0xe0, 0x0f, 0xec, 0xde, 0x7a, 0x94, 0xb0, 0xbc, 0xdc, 0xe8, 0x28, 0x50, 0x4e, 0x33, 0x0a, 0x4a,
    0xa7, 0x97, 0x60, 0x73, 0x1e, 0x00, 0x62, 0x44, 0x1a, 0xb8, 0x38, 0x82, 0x64, 0x9f, 0x26, 0x41,
    0xad, 0x45, 0x46, 0x92, 0x27, 0x5e, 0x55, 0x2f, 0x8c, 0xa3, 0xa5, 0x7d, 0x69, 0xd5, 0x95, 0x3b,
    0x07, 0x58, 0xb3, 0x40, 0x86, 0xac, 0x1d, 0xf7, 0x30, 0x37, 0x6b, 0xe4, 0x88, 0xd9, 0xe7, 0x89,
    0xe1, 0x1b, 0x83, 0x49, 0x4c, 0x3f, 0xf8, 0xfe, 0x8d, 0x53, 0xaa, 0x90, 0xca, 0xd8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xa4, 0x2d, 0x2b, 0x09, 0x5b, 0xcb, 0x9b, 0x25, 0xd0, 0xbe, 0xe5, 0x6c, 0x52,
    0x59, 0xa6, 0x74, 0xd2, 0xe6, 0xf4, 0xb4, 0xc0, 0xd1, 0x66, 0xaf, 0xc2, 0x39, 0x4b, 0x63, 0xb6,
]

tau = [
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
    0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39,
    0x02, 0x0a, 0x12, 0x1a, 0x22, 0x2a, 0x32, 0x3a,
    0x03, 0x0b, 0x13, 0x1b, 0x23, 0x2b, 0x33, 0x3b,
    0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c,
    0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d,
    0x06, 0x0e, 0x16, 0x1e, 0x26, 0x2e, 0x36, 0x3e,
    0x07, 0x0f, 0x17, 0x1f, 0x27, 0x2f, 0x37, 0x3f,
]

C = [
        0xb1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507,
        0x6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7,
        0xf574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2,
        0xef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e,
        0x4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57,
        0xae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e,
        0xf4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493,
        0x9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e,
        0x378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb,
        0xabbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced,
        0x7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b,
        0x378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720
]


def X(a, b):
    return a ^ b


def S(byte_string):
    result = b''
    for i in byte_string:
        result += ltb(pi[i])
        # byte_string = byte_string[1:]
        # print(i, byte_string)
    return result


def P(byte_string):
    result = b''
    for i in range(8):
        for j in range(8):
            result += ltb(byte_string[i+j*8])
    return result


def L(byte_string):
    vectors = [byte_string[i:i + 8] for i in range(0, 64, 8)]
    # print(vectors)
    result = b''
    for vector in vectors:
        vector =  btl(vector)
        print(hex(vector))
        c = 0
        for i in range(64):
            c ^= A[63-i] if vector & 1 == 1 else 0
            print(hex(c))
            vector >>= 1
        print()
        result += (c).to_bytes(8, 'big')
    return result


def LPS(byte_string):
    return L(P(S(byte_string)))


def LPSX(K, m):
    K = btl(K)
    m = btl(m)
    return LPS((X(K, m).to_bytes(64, 'big')))


def E(K, m):
    for i in range(12):
        m = LPSX(K, m)
        K = LPS((btl(K) ^ C[i]).to_bytes(64, 'big'))
    return X(btl(K), btl(m))


def g(N, h, m):
    K = LPS((h ^ N).to_bytes(64, 'big')) # h = g(0, h, N.to_bytes(64, 'big'))
    result = E(K, m) ^ h ^ btl(m)
    return result


def padding(M):
    length = 512 - btl(M).bit_length()
    M = (1).to_bytes(length + 7 // 8, 'big') + M
    return M


def unpad(M):
    m = btl(M) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    return ltb(m)


def Streebog(M, bits):
    M = M[::-1]
    if bits == 256:
        IV = 0x1010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101
    elif bits == 512:
        IV = 0
    else:
        return "ERROR, invalid bits length"
    h, N, sigma = IV, 0, 0
    while len(M) >= 64:
        m = unpad(M)
        h = g(N, h, m)
        N = (N + 512) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        sigma = (sigma + btl(m)) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        M = M[:-64]
    m = padding(M)
    h = g(N, h, m)
    # print(hex(btl(m)))
    N = (N + len(M) * 8) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    sigma = (sigma + btl(m)) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    # print(hex(N), hex(h))
    # print()
    h = g(0, h, N.to_bytes(64, 'big'))
    # print(hex(h))
    h = g(0, h, (sigma).to_bytes(64, 'big'))
    h = h >> (512- bits)
    hash_streebog =h.to_bytes(bits//8, "little") # хэш получается задом наперёд, поэтому тут его переворачиваем
    h = int.from_bytes(hash_streebog, "big")
    h = hex(h)[2:]
    print(len(h))
    # return h
    return '0' * (bits//4 - len(h)) + h



m = 0xfbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1
m = ltb(m)
m = b'210987654321098765432109876543210987654321098765432109876543210'
check = 0x46433ed624df433e452f5e7d92452f5ed98937e4acd989375f14f117995f14f1c0b64bc266c0b64bbe2d092067be2d09ec4e7ab0e0ec4e7a2cfdea48eb2cfdea
check = ltb(check)
# print(hex(int("01000110010000110011111011010110001001001101111101000011001111100100010100101111010111100111110110010010010001010010111101011110110110011000100100110111111001001010110011011001100010010011011101011111000101001111000100010111100110010101111100010100111100011100000010110110010010111100001001100110110000001011011001001011101111100010110100001001001000000110011110111110001011010000100111101100010011100111101010110000111000001110110001001110011110100010110011111101111010100100100011101011001011001111110111101010", 2)))
# print(L(check))
# print(Streebog(m, 512))
# print(Streebog(b'hello world', 512))


# print(unpad(0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012))


# vector = b"\x00"*64
# m = b'10987654321098765432109876543210987654321098765432109876543210'
# # print(padding(m))
# m = b'\x01210987654321098765432109876543210987654321098765432109876543210'
# K = LPS(vector)
# h = 0
# print(g(0, h, m))
# print((b'\x01210987654321098765432109876543210987654321098765432109876543210'))
# IV = 0x1010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101