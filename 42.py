from 42 import RSAImplementation
from hashlib import sha1
from re import match
from binascii import unhexlify
from 39 import int_to_bytes

ciphers = []

asn1_sha1_prefix = '3021300906052b0e03021a05000414'

def rsaSign(priv, msg):
    d, n = priv
    
    modlen = RSAImplementation.byte_len(n)
    h = sha1(msg).hexdigest()
    
    npad = modlen - 2 - 1 - len(asn1_sha1_prefix + h) / 2
    
    mr = '0001' + ('ff' * npad) + '00' + asn1_sha1_prefix + h
    mr = long(mr, 16)
    return RSAImplementation.decrypt(priv, mr)

def rsaVerify(pub, sig, msg):
    e, n = pub
    modlen = RSAImplementation.byte_len(n)
    mr = RSAImplementation.encrypt(pub, sig)
    h = sha1(msg).hexdigest().lower()
    
    mrh = ('%0' + str(modlen * 2) + 'x') % mr
    if match('^0001ff+00' + asn1_sha1_prefix + h, mrh):
        return 'ok'
    else:
        return 'bad signature'

def forge_signature(message, key_length):

    block = b'\x00\x01\xff\x00' + asn1_sha1_prefix + unhexlify(sha1(message))
    garbage = (((key_length + 7) // 8) - len(block)) * b'\x00'
    block += garbage
    pre_encryption = int.from_bytes(block, byteorder='big')
    forged_sig = find_cube_root(pre_encryption)
    return int_to_bytes(forged_sig)

def main():
    pub, priv = RSAImplementation(3, 1024)
    msg = 'hi mom'
    
    good_sig = rsaSign(priv, msg)
    assert 'ok' == rsaVerify(pub, good_sig, msg)
    
    # forge
    forge_signature(msg, 1024)
    print rsaVerify(pub, bad_sig, msg)

main()