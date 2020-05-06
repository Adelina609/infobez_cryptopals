from random import randint
from Crypto.Util.number import getPrime

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
        raise Exception("нельзя получить обратное число")
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
    
    
def oracul(ciphertext, rsa_server):
    e, n = rsa_server.get_public_key()

    while True:
        s = randint(2, n - 1)
        if s % n > 1:
            break

    new_ciphertext = (pow(s, e, n) * ciphertext) % n

    new_plaintext = rsa_server.decrypt(new_ciphertext)
    int_plaintext = int.from_bytes(new_plaintext, byteorder='big')

    r = (int_plaintext * invMod(s, n)) % n

    return intToBytes(r)


class RSAServer:
    def __init__(self, rsa):
        self._rsa = rsa
        self._decrypted = set()

    def get_public_key(self):
        return self._rsa.e, self._rsa.n

    def decrypt(self, data):
        if data in self._decrypted:
            raise Exception("Это было расшифровано ранее")
        self._decrypted.add(data)
        return self._rsa.decrypt(data)


def main():
    plaintext = b"0x234509876435"
    rsa = RSAImplementation(1024)
    ciphertext = rsa.encrypt(plaintext)
    rsa_server = RSAServer(rsa)

    # Test if the attack works
    recovered_plaintext = oracul(ciphertext, rsa_server)
    print(recovered_plaintext == plaintext)

main()