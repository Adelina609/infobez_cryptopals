from 42 import RSAImplementation as rsa

plain = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='.decode('base64')
plain_i = long(plain.encode('hex'), 16)

def oracul(priv, cipher):
    pt = rsa.decrypt(priv, cipher)
    return pt & 1

def decode_int(i):
    v = hex(long(i))[2:-1]
    if len(v) & 1: v = '0' + v
    return v.decode('hex')

def extract_bits(priv, pub, cipher):
    N = pub[1]
    c2 = rsa.encrypt(pub, 2)
    cipher = (cipher * c2) % N
    
    for _ in range(1024):
        yield oracul(priv, cipher)
        cipher = (cipher * c2) % N

def main()
    pub, priv = rsa(1024)
    N = pub[1]
    cipher = rsa.encrypt(pub, plain_i)
    
    lo, hi = 0, N
    for b in extract_bits(priv, pub, cipher):
        mid = (lo + hi) / 2
        if b == 1:
            lo = mid
        else:
            hi = mid

    print decode_int(hi)

main()