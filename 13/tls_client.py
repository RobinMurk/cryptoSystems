#!/usr/bin/env python3

import argparse, codecs, hmac, socket, sys, time, os, datetime
from hashlib import sha1, sha256
from Cryptodome.Cipher import ARC4
from pyasn1.codec.der import decoder  # do not use any other imports/libraries
from urllib.parse import urlparse

# took 10 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

def get_pubkey_certificate(cert):
    # reads the certificate and returns (n, e)

     # gets subjectPublicKey from certificate
    pubkey = decoder.decode(cert)[0][0][6][1].asOctets()
    pubkey = decoder.decode(pubkey)[0]

    return int(pubkey[0]), int(pubkey[1])


def pkcsv15pad_encrypt(plaintext, n) -> bytes:
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


def rsa_encrypt(cert, m):
    # encrypts message m using public key from certificate cert
    #get public key (N, e)
    (N, e) = get_pubkey_certificate(cert)
    ready_Plaintext = pkcsv15pad_encrypt(m,N)
    if not ready_Plaintext:
        print("no ready_Plaintext")
        
    message = bi(ready_Plaintext)
    c = pow(message, e, N)
    return ib(c)




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



# returns TLS record that contains ClientHello handshake message
def client_hello():
    global client_random, handshake_messages, TLS_SUPPORTED

    print("--> ClientHello()")
    
    client_randomness = ib(int(time.time()), 4) + os.urandom(28)
    client_random = client_randomness
    session_id_len = b'\x00'

    csuite_len = b'\x00\x06'
    # list of cipher suites the client supports
    csuite = b"\x00\x05" # TLS_RSA_WITH_RC4_128_SHA
    csuite+= b"\x00\x2f" # TLS_RSA_WITH_AES_128_CBC_SHA
    csuite+= b"\x00\x35" # TLS_RSA_WITH_AES_256_CBC_SHA

    compression = b'\x01\x00'

    client_hello_body = TLS_SUPPORTED + client_randomness + session_id_len + csuite_len + csuite + compression

    # add Handshake message header
    client_hello_header = b'\x01' + b'\x00\x00' + ib(len(client_hello_body))


    client_hello_complete_packet = client_hello_header + client_hello_body
    handshake_messages += client_hello_complete_packet

    # add record layer header
    record_header = b"\x16\x03\x03\x00" + ib(len(client_hello_complete_packet))
    record = record_header + client_hello_complete_packet

    return record

# returns TLS record that contains ClientKeyExchange message containing encrypted pre-master secret

def client_key_exchange():
    global server_cert, premaster, handshake_messages, TLS_SUPPORTED

    print("--> ClientKeyExchange()")

    premaster = TLS_SUPPORTED + os.urandom(46)
    encrypted_premaster = rsa_encrypt(server_cert, premaster)
    premaster_body = ib(len(encrypted_premaster), 2) + encrypted_premaster
    header = b'\x10' + ib(len(premaster_body), 3)

    #add the header
    full_exchange = header + premaster_body
    handshake_messages += full_exchange

    # add TLS record header
    record = b'\x16\x03\x03' + ib(len(full_exchange), 2) + full_exchange
    return record


# returns TLS record that contains ChangeCipherSpec message
def change_cipher_spec():
    print("--> ChangeCipherSpec()")

    cipher_spec_header = b'\x01'
    record = b'\x14' + TLS_SUPPORTED + ib(len(cipher_spec_header),2) + cipher_spec_header
    return record

# returns TLS record that contains encrypted Finished handshake message
def finished():
    global handshake_messages, master_secret

    print("--> Finished()")
    client_verify = PRF(master_secret, b"client finished" + sha256(handshake_messages).digest(), 12)
    finished = b'\x14' + ib(len(client_verify), 3) + client_verify
    handshake_messages += finished
    finished = encrypt(finished,b'\x16',TLS_SUPPORTED)

    #add TLS record header
    record = b'\x16' + TLS_SUPPORTED + ib(len(finished), 2) + finished
    return record

# returns TLS record that contains encrypted Application data
def application_data(data):
    print("--> Application_data()")
    print(data.decode().strip())
    DATA = encrypt(data,b'\x17',TLS_SUPPORTED)
    
    #add TLS record header
    record = b'\x17' + TLS_SUPPORTED + ib(len(DATA), 2) + DATA

    return record

# parse TLS Handshake messages
def parsehandshake(r):
    global server_hello_done_received, server_random, server_cert, handshake_messages, server_change_cipher_spec_received, server_finished_received

    # decrypt if encryption enabled
    if server_change_cipher_spec_received:
        r = decrypt(r, b"\x16", b"\x03\x03")

    # read Handshake message type and length from message header
    htype, hlength = r[0:1], bi(r[1:4])

    body = r[4:4+hlength]
    handshake = r[:4+hlength]
    handshake_messages+= handshake

    if htype == b"\x02":
        print("	<--- ServerHello()")
        server_random = body[2: 34]
        gmt = body[2: 6]
        gmt = datetime.datetime.fromtimestamp(bi(gmt))
        sessid_len = bi(body[34: 35])
        sessid_len_last_pos = 35 + sessid_len
        sessid = body[35: 35 + sessid_len_last_pos]
        cipher = body[sessid_len_last_pos: sessid_len_last_pos + 2]
        compression = body[sessid_len_last_pos + 2: sessid_len_last_pos + 3]

        print("	[+] server randomness:", server_random.hex().upper())
        print("	[+] server timestamp:", gmt)
        print("	[+] TLS session ID:", sessid.hex().upper())

        if cipher==b"\x00\x2f":
            print("	[+] Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA")
        elif cipher==b"\x00\x35":
            print("	[+] Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA")
        elif cipher==b"\x00\x05":
            print("	[+] Cipher suite: TLS_RSA_WITH_RC4_128_SHA")
        else:
            print("[-] Unsupported cipher suite selected:", cipher.hex())
            sys.exit(1)

        if compression!=b"\x00":
            print("[-] Wrong compression:", compression.hex())
            sys.exit(1)

    elif htype == b"\x0b":
        print("	<--- Certificate()")
        
        certlen = bi(body[3: 6])
        print("	[+] Server certificate length:", certlen)
        cert = body[6: 6 + certlen]
        server_cert = cert

    elif htype == b"\x0e":
        print("	<--- ServerHelloDone()")
        server_hello_done_received = True

    elif htype == b"\x14":
        print("	<--- Finished()")
        # hashmac of all Handshake messages except the current Finished message (obviously)
        verify_data_calc = PRF(master_secret, b"server finished" + sha256(handshake_messages[:-4-hlength]).digest(), 12)
        server_verify = body
        if server_verify!=verify_data_calc:
            print("[-] Server finished verification failed!")
            sys.exit(1)
        server_finished_received = True
    else:
        print("[-] Unknown Handshake Type:", htype.hex())
        sys.exit(1)

    # handle the case of several Handshake messages in one record
    leftover = r[4+len(body):]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    global server_change_cipher_spec_received

    # parse TLS record header and pass the record body to the corresponding parsing method
    ctype = r[0:1]
    c = r[5:]

    # handle known types
    if ctype == b"\x16":
        print("<--- Handshake()")
        parsehandshake(c)
    elif ctype == b"\x14":
        print("<--- ChangeCipherSpec()")
        server_change_cipher_spec_received = True
    elif ctype == b"\x15":
        print("<--- Alert()")
        if server_change_cipher_spec_received:
            c = decrypt(c,b'\x15',TLS_SUPPORTED)
        level, desc = c[0], c[1]
        if level == 1:
            print("	[-] warning:", desc)
        elif level == 2:
            print("	[-] fatal:", desc)
            sys.exit(1)
        else:
            sys.exit(1)
    elif ctype == b"\x17":
        print("<--- Application_data()")
        data = decrypt(c, b"\x17", b"\x03\x03")
        print(data.decode().strip())
    else:
        print("[-] Unknown TLS Record type:", ctype.hex())
        sys.exit(1)

# PRF defined in TLS v1.2
def PRF(secret, seed, l):

    out = b""
    A = hmac.new(secret, seed, sha256).digest()
    while len(out) < l:
        out += hmac.new(secret, A + seed, sha256).digest()
        A = hmac.new(secret, A, sha256).digest()
    return out[:l]

# derives master_secret
def derive_master_secret():
    global premaster, master_secret, client_random, server_random
    master_secret = PRF(premaster, b"master secret" + client_random + server_random, 48)

# derives keys for encryption and MAC
def derive_keys():
    global premaster, master_secret, client_random, server_random
    global client_mac_key, server_mac_key, client_enc_key, server_enc_key, rc4c, rc4s

    key_block = PRF(master_secret, b"key expansion" + server_random + client_random, 136)
    mac_size = 20
    key_size = 16
    iv_size = 16

    client_mac_key = key_block[:mac_size]
    server_mac_key = key_block[mac_size:mac_size*2]
    client_enc_key = key_block[mac_size*2:mac_size*2+key_size]
    server_enc_key = key_block[mac_size*2+key_size:mac_size*2+key_size*2]

    rc4c = ARC4.new(client_enc_key)
    rc4s = ARC4.new(server_enc_key)

# HMAC SHA1 wrapper
def HMAC_sha1(key, data):
    return hmac.new(key, data, sha1).digest()

# calculates MAC and encrypts plaintext
def encrypt(plain, type, version):
    global client_mac_key, client_enc_key, client_seq, rc4c

    mac = HMAC_sha1(client_mac_key, ib(client_seq, 8) + type + version + ib(len(plain), 2) + plain)
    ciphertext = rc4c.encrypt(plain + mac)
    client_seq+= 1
    return ciphertext

# decrypts ciphertext and verifies MAC
def decrypt(ciphertext, type, version):
    global server_mac_key, server_enc_key, server_seq, rc4s

    d = rc4s.decrypt(ciphertext)
    mac = d[-20:]
    plain = d[:-20]

    # verify MAC
    mac_calc = HMAC_sha1(server_mac_key, ib(server_seq, 8) + type + version + ib(len(plain), 2) + plain)
    if mac!=mac_calc:
        print("[-] MAC verification failed!")
        sys.exit(1)
    server_seq+= 1
    return plain

# read from the socket full TLS record
def readrecord():
    record = b""

    # read TLS record header (5 bytes)
    for _ in range(5):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed! (no TLS header found)")
            exit(1)
        record += buf

    # find data length
    datalen = bi(record[3:5])

    # read TLS record body
    for _ in range(datalen):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed! (no body found)")
            exit(1)
        record += buf

    return record

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
url = urlparse(args.url)
host = url.netloc.split(':')
if len(host) > 1:
    port = int(host[1])
else:
    port = 443
host = host[0]


path = url.path

client_random = b""	# will hold client randomness
server_random = b""	# will hold server randomness
server_cert = b""	# will hold DER encoded server certificate
premaster = b""		# will hold 48 byte pre-master secret
master_secret = b""	# will hold master secret
handshake_messages = b"" # will hold concatenation of handshake messages
TLS_SUPPORTED = b'\x03\x03'

# client/server keys and sequence numbers
client_mac_key = b""
server_mac_key = b""
client_enc_key = b""
server_enc_key = b""
client_seq = 0
server_seq = 0

# client/server RC4 instances
rc4c = b""
rc4s = b""

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
server_change_cipher_spec_received = False
server_finished_received = False

while not server_hello_done_received:
    parserecord(readrecord())

s.send(client_key_exchange())
s.send(change_cipher_spec())
derive_master_secret()
derive_keys()
s.send(finished())

while not server_finished_received:
    parserecord(readrecord())

s.send(application_data(b"GET / HTTP/1.0\r\n\r\n"))
parserecord(readrecord())

print("[+] Closing TCP connection!")
s.close()
