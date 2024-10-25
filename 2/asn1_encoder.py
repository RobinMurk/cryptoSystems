#!/usr/bin/env python3
import sys   # do not use any other imports/libraries

# took 15 hours (please specify here how much time your solution required)

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

# figure out what to put in '...' by looking on ASN.1 structure required (see slides)
# asn1 = asn1_tag_explicit(asn1_sequence(... + asn1_boolean(True) + asn1_bitstring("011") ...), 0)
asn1 = asn1_tag_explicit(
            asn1_sequence(
                asn1_set(
                    asn1_integer(5)+
                    asn1_tag_explicit(
                        asn1_integer(200),2)+
                    asn1_tag_explicit(
                        asn1_integer(65407),11))+
                asn1_boolean(True)+
                asn1_bitstring("011")+
                asn1_octetstring(b'\x00' + b'\x01' + 49 * b'\x02')+
                asn1_null()+
                asn1_objectidentifier([1,2,840,113549,1])+
                asn1_utf8string(b"hello.")+
                asn1_utctime(b"250223010900Z")
                ),0)
open(sys.argv[1], 'wb').write(asn1)
