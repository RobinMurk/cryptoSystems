#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# took 9 hours (please specify here how much time your solution required)


def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bi(b):
    # converts bytes to integer
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i

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

def pem_to_der(content:bytes):
    # converts PEM content to DER
    
    lines = content.splitlines()
    text = []
    for line in lines:
        if not line.startswith(b'----'):    
            text.append(line.strip())
    
    text = b''.join(text)
    content = codecs.decode(text,'base64')
    return content

def get_key_file_content(filename:str) -> bytes:
    f = open(filename,'rb')
    content = f.read()
    f.close()
    if content.startswith(b'-----'):
        return pem_to_der(content)
    return content

def get_pubkey(filename):
    # reads public key file encoded using SubjectPublicKeyInfo structure and returns (N, e)
    content = get_key_file_content(filename)
    

    # DER-decode the DER to get RSAPublicKey DER structure, which is encoded as BITSTRING
    asn1, _ = decoder.decode(content)
    bit_String = asn1[1]

    # convert BITSTRING to bytestring
    # DER-decode the bytestring (which is actually DER) and return (N, e)
    pubkey, _ = decoder.decode(bit_String.asOctets())   #.asOctets() makes the bitstring into Octets

    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file encoded using PrivateKeyInfo (PKCS#8) structure and returns (N, d)
    content = get_key_file_content(filename)
    asn1, _ = decoder.decode(content)

    # DER-decode the DER to get RSAPrivateKey DER structure, which is encoded as OCTETSTRING
    privkey = asn1[2].asOctets()

    # DER-decode the octetstring (which is actually DER) and return (N, d)
    privkey, _ = decoder.decode(privkey)


    return int(privkey[1]), int(privkey[3])


def pkcsv15pad_encrypt(plaintext:bytes, n:int) -> bytes:
    # pad plaintext for encryption according to PKCS#1 v1.5

    # calculate number of bytes required to represent the modulus N
    size = (n.bit_length() + 7) // 8
    # plaintext must be at least 11 bytes smaller than the modulus
    if size - len(plaintext) < 11:
        print("file size too big")
        return
    
    random_bytes = b''
    for i in range(0,size - (len(plaintext) + 3)):
        rand = os.urandom(1)
        if rand != b'\x00':
            random_bytes += rand

    padded_plaintext = b'\x00\x02' + random_bytes + b'\x00' + plaintext
    # generate padding bytes
    return padded_plaintext

def pkcsv15pad_sign(plaintext:bytes, n:int) -> bytes:
    # pad plaintext for signing according to PKCS#1 v1.5

    # calculate bytelength of modulus N
    size = (n.bit_length() + 7) // 8

    # plaintext must be at least 11 bytes smaller than the modulus N
    if size - len(plaintext) < 11:
        print("file size too big")
        return
    
    # generate padding bytes
    random_bytes = b'\xFF' * (size - (len(plaintext) + 3))
    padded_plaintext = b'\x00\x01' + random_bytes + b'\x00' + plaintext

    return padded_plaintext

def pkcsv15pad_remove(plaintext:bytes) -> bytes:
    idx = plaintext[3:].find(b'\x00')
    return plaintext[idx + 4:]



def encrypt(keyfile, plaintextfile, ciphertextfile):
    #get public key (N, e)
    (N, e) = get_pubkey(keyfile)

    f = open(plaintextfile,'rb')
    ready_Plaintext = pkcsv15pad_encrypt(f.read(),N)
    f.close()


    message = bi(ready_Plaintext)
    c = pow(message, e, N)
    ciphertext = ib(c)
    f = open(ciphertextfile,'wb')
    f.write(ciphertext)
    f.close()

def decrypt(keyfile, ciphertextfile, plaintextfile):
    #get public key (N, e)
    (N, d) = get_privkey(keyfile)

    f = open(ciphertextfile,'rb')
    ciphertext = f.read()
    f.close()

    #get the original text
    message_int = pow(bi(ciphertext), d, N)
    message = ib(message_int, (N.bit_length() + 7) // 8)
    message = pkcsv15pad_remove(message)

    f = open(plaintextfile,'wb')
    f.write(message)
    f.close()

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    f = open(filename,'rb')
    content = f.read()
    f.close()

    #create digest
    digest = hashlib.sha256(content).digest()
    
    asn1 = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([2,16,840,1,101,3,4,2,1])+
            asn1_null()
        )+
        asn1_octetstring(digest))

    return asn1

def sign(keyfile, filetosign, signaturefile):
    digest = digestinfo_der(filetosign)
    (N, d) = get_privkey(keyfile)

    padded = pkcsv15pad_sign(digest, N)
    message_int = bi(padded)
    signature = pow(message_int, d, N)
    signature_bytes = ib(signature, (N.bit_length() + 7) // 8)

    f = open(signaturefile,'wb')
    f.write(signature_bytes)
    f.close()

def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    f = open(signaturefile,'rb')
    content = f.read()
    f.close()

    (N, e) = get_pubkey(keyfile)
    
    message_int = bi(content)
    message = pow(message_int, e, N)
    message_padded = ib(message,(N.bit_length() + 7) // 8)
    message = pkcsv15pad_remove(message_padded)
    
    digest = digestinfo_der(filetoverify)

    if message == digest:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
