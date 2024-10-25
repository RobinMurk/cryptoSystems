#!/usr/bin/env python3

import time, os, sys
from pyasn1.codec.der import decoder # type: ignore

# $ sudo apt-get install python3-pycryptodome
sys.path = sys.path[1:] # removes current directory from aes.py search path
from Cryptodome.Cipher import AES          # type: ignore # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ecb-mode
from Cryptodome.Util.strxor import strxor  # type: ignore # https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#crypto-util-strxor-module
from hashlib import pbkdf2_hmac
import hashlib, hmac # do not use any other imports/libraries

# took 7.5 hours

#==== ASN1 encoder start ====
# put your DER encoder functions here
def asn1_len(value_bytes):
    # helper function - should be used in other functions to calculate length octet(s)
    # value_bytes - bytes containing TLV value byte(s)
    # returns length (L) byte(s) for TLV
    length = len(value_bytes)
    if length < 128:
        return bytes([0 << 8 | length])
    else:
        ammount_of_bytes = 0
        length_bytes = b''
        while length != 0:
            b = length & 255
            length = length >> 8
            length_bytes = bytes([b]) + length_bytes
            ammount_of_bytes += 1
        return bytes([128 | ammount_of_bytes]) + length_bytes

def asn1_boolean(boolean):
    # BOOLEAN encoder has been implemented for you
    if boolean:
        boolean = b'\xff'
    else:
        boolean = b'\x00'
    return bytes([0x01]) + asn1_len(boolean) + boolean

def asn1_null():
    # returns DER encoding of NULL
    return b'\x05\x00'

def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER
    if i == 0:
        return b'\x02' + asn1_len(bytes([0])) + bytes([0])

    b = b''
    while i != 0:
        bits = [i & 255]
        b = bytes(bits) + b
        i = i >> 8

    if b[0] & 128:
        b = bytes([0]) + b
    
    return b'\x02' + asn1_len(b) + b

def asn1_bitstring(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING

    b = b''
    padding = (8 - len(bitstr)) % 8
    bitstr = bitstr + '0' * padding

    for el in range(0, len(bitstr), 8):
        bitstr_el = bitstr[el:el+8]
        byte = 0
        for x in bitstr_el:
            byte <<= 1
            if x == '1':
                byte |= 1
        
        b = b + bytes([byte])
    
    value_bytes = bytes([padding]) + b

    return b'\x03' + asn1_len(value_bytes) + value_bytes

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    return b'\x04' + asn1_len(octets) + octets

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    b = bytes([40 * oid[0] + oid[1]])

    for x in range(2,len(oid)):
        number = oid[x]
        if number > 127:
            num_bytes = bytes([number & 127])
            number >>= 7
            while number != 0:
                bits = [(number & 127) ^ 128]
                num_bytes = bytes(bits) + num_bytes
                number >>= 7
            b += num_bytes
        else:
            b += bytes([number])
    
    return b'\x06' + asn1_len(b) + b

def asn1_sequence(der):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return bytes([48]) + asn1_len(der) + der
    
def asn1_set(der):
    # der - DER bytes to encapsulate into set
    # returns DER encoding of SET
    return bytes([49]) + asn1_len(der) + der

def asn1_utf8string(utf8bytes):
    # utf8bytes - bytes containing UTF-8 encoded unicode characters (e.g., b"F\xc5\x8d\xc5\x8d")
    # returns DER encoding of UTF8String
    return b'\x0c' + asn1_len(utf8bytes) + utf8bytes

def asn1_utctime(time):
    # time - bytes containing timestamp in UTCTime format (e.g., b"121229010100Z")
    # returns DER encoding of UTCTime
    return b'\x17' + asn1_len(time) + time

def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type
    return bytes([160 | tag]) + asn1_len(der) + der


#==== ASN1 encoder end ====


# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():

    # measure time for performing 10000 iterations
    start = time.time()
    iter = 0
    while time.time() - start < 1:
        iter += 1
 
    print("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter))

    return iter # returns number of iterations that can be performed in 1 second


def encrypt(pfile, cfile):

    # benchmarking
    iter = benchmark()

    # asking for a password
    passwd = input("enter password: ").encode()

    # derieving keys
    salt = os.urandom(8)
    key = pbkdf2_hmac('sha1',passwd,salt,iter,48)
    aes_key = key[:16]
    hmac_key = key[16:]
    original_IV = os.urandom(16)
    IV = original_IV


    # reading plaintext
    file_contents = open(pfile,'rb').read()

    # padding plaintext
    padding = 16 - len(file_contents)%16
    if padding == 0:
        padding = 16
    padded_ptext = file_contents + padding * bytes([padding])


    # encrypting padded plaintext
    ciphertext = b''
    cipher = AES.new(aes_key,AES.MODE_ECB)

    for i in range(0,len(padded_ptext),16):
        block = padded_ptext[i:i+16]
        encrypted_block = cipher.encrypt(strxor(block,IV))
        ciphertext += encrypted_block
        IV = encrypted_block


    # MAC calculation (iv+ciphertext)
    hmac_digest = cipher_to_hmac(original_IV,ciphertext,hmac_key)

    # constructing DER header
    der_header = asn1_sequence(
                    asn1_sequence(
                        asn1_octetstring(salt)+
                        asn1_integer(iter)+
                        asn1_integer(48)
                    )+
                    asn1_sequence(
                        asn1_objectidentifier([2,16,840,1,101,3,4,1,2])+
                        asn1_octetstring(original_IV)
                    )+
                    asn1_sequence(
                        asn1_sequence(
                            asn1_objectidentifier([2,16,840,1,101,3,4,2,1])+
                            asn1_null()
                        )+
                        asn1_octetstring(hmac_digest)
                    )
                )
    
    # writing DER header and ciphertext to file
    file = open(cfile, 'wb')
    file.write(der_header)
    file.write(ciphertext)
    file.close()


def decrypt(cfile, pfile):

    # reading DER header and ciphertext
    f = open(cfile, 'rb')
    contents = f.read()
    asn1, ciphertext = decoder.decode(contents)
    f.close()

    # asking for a password
    passwd = input("enter password: ").encode()

    # derieving keys
    salt = bytes(asn1[0][0])
    iter = int(asn1[0][1])
    length = int(asn1[0][2])
    original_IV = bytes(asn1[1][1])
    given_digest = bytes(asn1[2][1])
    key = pbkdf2_hmac('sha1',passwd,salt,iter,length)

    #derived keys from PBKDF2
    aes_key = key[:16]
    hmac_key = key[16:]


    # before decryption checking MAC (iv+ciphertext)
    calculated_digest = cipher_to_hmac(original_IV,ciphertext,hmac_key)
    if not hmac.compare_digest(calculated_digest,given_digest):
        print("digests dont match, aborting...")
        return

    # decrypting ciphertext
    IV = original_IV
    padded_text = b''
    cipher = AES.new(aes_key,AES.MODE_ECB)


    for i in range(0,len(ciphertext),16):
        encrypted_block = ciphertext[i:i+16]
        decrypted_block = strxor(cipher.decrypt(encrypted_block),IV)
        padded_text += decrypted_block
        IV = encrypted_block
    

    #removing padding and writing plaintext to file
    padding_int = int(padded_text[-1])
    plain_text = padded_text[0:(len(padded_text) - padding_int)]
    file = open(pfile, 'wb')
    file.write(plain_text)
    file.close()

def cipher_to_hmac(IV,contents, key):
        contents = IV + contents
        digest = hmac.new(key, None, hashlib.sha256)
        for i in range(0,len(contents),16):
            digest.update(contents[i:i+16])
       
        return digest.digest()

def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
