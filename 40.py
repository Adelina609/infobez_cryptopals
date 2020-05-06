from Crypto.Util.number import getPrime
import random

def intToBytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

# НОД
def gcd(a, b):
    while b != 0:
        a, b = b, a % b

    return a

# НОК
def lcm(a, b):
        return a // gcd(a, b) * b

#обратное число по модулю
def invMod(a, n):
    t, r = 0, n
    new_t, new_r = 1, a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n
    return t

class RSAImplementation:
    def __init__(self, key_length):
        #по задаче e=3
        self.e = 3
        phi = 0

        while gcd(self.e, phi) != 1:
            p, q = getPrime(key_length // 2), getPrime(key_length // 2)
            phi = lcm(p - 1, q - 1)
            self.n = p * q

        self._d = invMod(self.e, phi)

    def encrypt(self, binary_data):
        int_data = int.from_bytes(binary_data, byteorder='big')
        return pow(int_data, self.e, self.n)

    def decrypt(self, encrypted_int_data):
        int_data = pow(encrypted_int_data, self._d, self.n)
        return intToBytes(int_data)

#извлечь кубический корень
def find_cube_root(n):
    lo = 0
    hi = n

    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < n:
            lo = mid + 1
        else:
            hi = mid

    return lo

#по китайской теореме об остатках
def rsaBroadcastAttack(ciphertexts):
    c0, c1, c2 = ciphertexts[0][0], ciphertexts[1][0], ciphertexts[2][0]
    n0, n1, n2 = ciphertexts[0][1], ciphertexts[1][1], ciphertexts[2][1]
    m0, m1, m2 = n1 * n2, n0 * n2, n0 * n1

    t0 = (c0 * m0 * invMod(m0, n0))
    t1 = (c1 * m1 * invMod(m1, n1))
    t2 = (c2 * m2 * invMod(m2, n2))
    c = (t0 + t1 + t2) % (n0 * n1 * n2)

    return intToBytes(find_cube_root(c))


def main():
    plaintext = b"0x2134567987654"
    ciphertexts = []
    for _ in range(3):
        rsa = RSAImplementation(1024)
        ciphertexts.append((rsa.encrypt(plaintext), rsa.n))

    print(rsaBroadcastAttack(ciphertexts) == plaintext)


main()