#*********39********

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


def main():
    rsa = RSAImplementation(1024)
    test = b"0x34567676789234598723454567895678"
    print(rsa.decrypt(rsa.encrypt(test)) == test)

main()