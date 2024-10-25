#!/usr/bin/env python3

import argparse, codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took 13 hours (please specify here how much time your solution required)


# parse arguments
parser = argparse.ArgumentParser(description='issue TLS server certificate based on CSR', add_help=False)
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("CA_private_key_file", help="CA private key (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()

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

def pem_to_der(content:bytes) -> bytes:
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----END CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename:str):

    
    f = open(filename,'rb')
    content = f.read()
    f.close()
    if content.startswith(b'-----'):
        content = pem_to_der(content)
    
    asn1, _ = decoder.decode(content)

    # DER-decode the DER to get RSAPrivateKey DER structure, which is encoded as OCTETSTRING
    privkey = asn1[2].asOctets()

    # DER-decode the octetstring (which is actually DER) and return (N, d)
    privkey, _ = decoder.decode(privkey)


    return int(privkey[1]), int(privkey[3])
    # reads RSA private key file and returns (n, d)

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


def digestinfo_der(m:bytes):
    # returns ASN.1 DER-encoded DigestInfo structure containing SHA256 digest of m

    #create digest
    digest = hashlib.sha256(m).digest()
    

    asn1 = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([2,16,840,1,101,3,4,2,1])+
            asn1_null()
        )+
        asn1_octetstring(digest))

    return asn1


def sign(m, keyfile:str) -> bytes:
    # signs DigestInfo of message m
    digest = digestinfo_der(m)
    (N, d) = get_privkey(keyfile)

    padded = pkcsv15pad_sign(digest, N)
    message_int = bi(padded)
    signature = pow(message_int, d, N)
    signature = ib(signature, (N.bit_length() + 7) // 8)
    return signature


def get_subject_cn(csr_der):

    # returns CommonName value from CSR's Distinguished Name field
    subject_field = decoder.decode(csr_der)[0][0][1]
    # looping over Distinguished Name entries until CN found
    for _set_ in subject_field:
        seq = _set_[0]
        if seq[0] == (2,5,4,3):
            cn = str(seq[1])
            return cn
    return ValueError("CN not found")



def get_subjectPublicKeyInfo(csr_der):
    # returns DER-encoded subjectPublicKeyInfo from CSR
    info = encoder.encode(decoder.decode(csr_der)[0][0][2])
    return info

def get_subjectName(cert_der):
    # returns DER-encoded subject name from CA certificate
    info = encoder.encode(decoder.decode(cert_der)[0][0][5])
    return info


def asn1_bitstring_der(data:bytes) -> str:
    str_data = ""
    for byte in data:
        str_data += format(byte, '08b')
    return str_data

def issue_certificate(private_key_file, issuer, subject, pubkey):
    # receives CA private key filename, DER-encoded CA Distinguished Name, self-constructed DER-encoded subject's Distinguished Name and DER-encoded subjectPublicKeyInfo
    # returns X.509v3 certificate in PEM format
    sha256_identifier:bytes = asn1_sequence(
                            asn1_objectidentifier([1,2,840,113549,1,1,11])+
                            asn1_null()
                            )
    
    time:bytes = asn1_sequence(
            asn1_utctime(b"120229010100Z")+
            asn1_utctime(b"301229010100Z")
    )

    TBScertificate:bytes = asn1_sequence(
                asn1_tag_explicit(asn1_integer(2),0)+
                asn1_integer(2)+
                sha256_identifier+
                issuer+
                time+
                subject+
                pubkey+
                asn1_tag_explicit(asn1_sequence(
                    asn1_sequence(
                        asn1_objectidentifier([2,5,29,19])+
                        asn1_boolean(True)+
                        asn1_octetstring(
                            asn1_sequence(
                                asn1_boolean(False)
                            )
                        )
                    )+
                    asn1_sequence(
                        asn1_objectidentifier([2,5,29,15])+
                        asn1_boolean(True)+
                        asn1_octetstring(
                            asn1_bitstring("10000000")
                        )
                    )+
                    asn1_sequence(
                        asn1_objectidentifier([2,5,29,37])+
                        asn1_boolean(True)+
                        asn1_octetstring(
                            asn1_sequence(
                                asn1_objectidentifier([1,3,6,1,5,5,7,3,1])
                            )
                        )
                    )
                ),3)
            )

    
    signatureValue = sign(TBScertificate,private_key_file)
    
    certificate_der = asn1_sequence(
        TBScertificate+
        sha256_identifier+
        asn1_bitstring(asn1_bitstring_der(signatureValue))
    ) 
    certificate_der = codecs.encode(certificate_der,'base64')

    pem = b"-----BEGIN CERTIFICATE-----\n" + certificate_der.strip() + b"\n-----END CERTIFICATE-----"

    return pem

# obtain subject's CN from CSR
csr_der = pem_to_der(open(args.csr_file, 'rb').read())
subject_cn_text = get_subject_cn(csr_der)
print("[+] Issuing certificate for \"%s\"" % subject_cn_text)

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)

# construct subject name DN for end-entity's certificate
subject_to_add = subject_cn_text.encode()
subject = asn1_sequence(
            asn1_set(
                asn1_sequence(
                    asn1_objectidentifier([2,5,4,3])+
                    asn1_utf8string(subject_to_add)
                )
            )
)

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, 'rb').read())
CAsubject = get_subjectName(CAcert)

# issue certificate
cert_pem = issue_certificate(args.CA_private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, 'wb').write(cert_pem)

