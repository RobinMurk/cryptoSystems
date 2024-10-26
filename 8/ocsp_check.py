#!/usr/bin/env python3

import codecs, datetime, hashlib, re, sys, socket # do not use any other imports/libraries
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder # type: ignore
from pyasn1.type import namedtype, univ # type: ignore

# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280 # type: ignore

# took 7 hours (please specify here how much time your solution required)

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


def get_response_body(connection):
    header = b''
    while b'\r\n\r\n' not in header:
        header += connection.recv(1)

    # get HTTP response length
    length = int(re.search('content-length:\s*(\d+)\s', header.decode(), re.S+re.I).group(1))

    # read HTTP response body
    body = b''
    read_bytes = 0
    while read_bytes < length:
        single_byte = connection.recv(1)
        if single_byte == b'':
            print("ERROR: content length does not match actual body size")
            return body
        body += single_byte
        read_bytes += 1

    return body

def pem_to_der(content):
    # converts PEM-encoded X.509 certificate (if it is in PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    # gets subject DN from certificate
    return encoder.encode(decoder.decode(cert)[0][0][5])

def get_key(cert):
     # gets subjectPublicKey from certificate
    return decoder.decode(cert)[0][0][6][1].asOctets()

def get_serial(cert):
    # gets serial from certificate
    return int(decoder.decode(cert)[0][0][1])

def produce_request(cert, issuer_cert) -> bytes:
    # makes OCSP request in ASN.1 DER form

    # construct CertID (use SHA1)
    issuer_name = get_name(issuer_cert)
    issuer_key = get_key(issuer_cert)
    serial = get_serial(cert)

    issuer_name_dig = hashlib.sha1(issuer_name).digest()
    issuer_key_dig = hashlib.sha1(issuer_key).digest()

    print("[+] OCSP request for serial:", serial)

    # construct entire OCSP request
    cert_ID = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([1,3,14,3,2,26])+
            asn1_null()
        )+
        asn1_octetstring(issuer_name_dig)+
        asn1_octetstring(issuer_key_dig)+
        asn1_integer(serial)
    )

    return \
    asn1_sequence(
        asn1_sequence(
            asn1_sequence(
                asn1_sequence(
                    cert_ID
                )
            )
        )
    )

def send_req(ocsp_req:bytes, ocsp_url:str):
    # sends OCSP request to OCSP responder
    # parse OCSP responder's url
    url = urlparse(ocsp_url)
    host = url.netloc
    print("[+] Connecting to %s..." % (host))

    # connect to host
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((host, 80))

    # send HTTP POST request
    req_post = f"POST / HTTP/1.1\r\n"
    req_host = f"Host: {host} \r\n"
    req_type = f"Content-Type: application/ocsp-request\r\n"
    req_len = f"Content-Length: {len(ocsp_req)}\r\n"
    req_conn = f"Connection: close\r\n\r\n"
    req = req_post+req_host+req_type+req_len+req_conn

    connection.send(req.encode()+ocsp_req)

    # get response body
    return get_response_body(connection)

def get_ocsp_url(cert):
    # gets the OCSP responder's url from the certificate's AIA extension


    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.1': # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in the certificate!")
    exit(1)

def get_issuer_cert_url(cert):
    # gets the CA's certificate URL from the certificate's AIA extension (hint: see get_ocsp_url())
    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.2': # CAIssuer
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

def download_issuer_cert(issuer_cert_url:str):
    # downloads issuer certificate
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # parse issuer certificate url
    url = urlparse(issuer_cert_url)
    host = url.netloc
    path = url.path

    # connect to host
    connection = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    connection.connect((host,80))

    # send HTTP GET request
    req_get = f"GET {path} HTTP/1.1\r\n"
    req_host = f"Host: {host}\r\n"
    req_conn = f"Connection: close\r\n\r\n"
    req = req_get+req_host+req_conn
    connection.send(req.encode())

    #get response body
    return get_response_body(connection)

def parse_ocsp_resp(ocsp_resp):
    # parses OCSP response
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    response = responseBytes.getComponentByName('response')

    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    certID = response0.getComponentByName('certID')
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(response0.getComponentByName('nextUpdate')), '%Y%m%d%H%M%SZ')

    # let's assume that the certID in the response matches the certID sent in the request

    # let's assume that the response is signed by a trusted responder

    print("[+] OCSP producedAt: %s +00:00" % producedAt)
    print("[+] OCSP thisUpdate: %s +00:00" % thisUpdate)
    print("[+] OCSP nextUpdate: %s +00:00" % nextUpdate)
    print("[+] OCSP status:", certStatus)

cert = pem_to_der(open(sys.argv[1], 'rb').read())

ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)
issuer_cert = download_issuer_cert(issuer_cert_url)

ocsp_req = produce_request(cert, issuer_cert)
ocsp_resp = send_req(ocsp_req, ocsp_url)
parse_ocsp_resp(ocsp_resp)
