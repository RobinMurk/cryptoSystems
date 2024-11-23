#!/usr/bin/env python3

import argparse, codecs, datetime, os, socket, sys, time # do not use any other imports/libraries
from urllib.parse import urlparse

# took 4 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
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

# returns TLS record that contains ClientHello Handshake message
def client_hello():

    print("--> ClientHello()")

    TLS_supported = b'\x03\x02'   #TODO NB! ALL of the testcases can accept b'\x03\x02'. 
                                  #facebook.com did not accept b'\x03\x03' but others on test case did. 
                                  # if the metod would be changed to try to
                                  # test with another TLS level, then this would work.
    client_randomness = ib(int(time.time()), 4) + os.urandom(28)
    session_id_len = b'\x00'

    csuite_len = b'\x00\x06'
    # list of cipher suites the client supports
    csuite = b"\x00\x05" # TLS_RSA_WITH_RC4_128_SHA
    csuite+= b"\x00\x2f" # TLS_RSA_WITH_AES_128_CBC_SHA
    csuite+= b"\x00\x35" # TLS_RSA_WITH_AES_256_CBC_SHA

    compression = b'\x01\x00'

    client_hello_body = TLS_supported + client_randomness + session_id_len + csuite_len + csuite + compression

    # add Handshake message header
    client_hello_header = b'\x01' + b'\x00\x00' + ib(len(client_hello_body))


    client_hello_complete_packet = client_hello_header + client_hello_body
    # add record layer header
    record_header = b"\x16\x03\x03\x00" + ib(len(client_hello_complete_packet))
    record = record_header + client_hello_complete_packet

    return record

# returns TLS record that contains 'Certificate unknown' fatal Alert message
def alert():
    print("--> Alert()")

    # add alert message
    alert_message = b'\x02' + ib(40)
    # add record layer header
    record = b'\x15\x03\x03' + b'\00\x02' + alert_message

    return record

# parse TLS Handshake messages
def parsehandshake(r:bytes):
    global server_hello_done_received
    # read Handshake message type and length from message header
    htype = r[0:1]
    handshake_length = bi(r[1:4])
    full_body = r[4:]
    body = full_body[0: handshake_length]

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
        cert = codecs.encode(cert,"base64")
        if args.certificate:
            with open(args.certificate, 'wb') as file:
                file.write(b'-----BEGIN CERTIFICATE-----\n')
                file.write(cert)
                file.write(b'-----END CERTIFICATE-----\n')
            print("	[+] Server certificate saved in:", args.certificate)

    elif htype == b"\x0e":
        print("	<--- ServerHelloDone()")
        server_hello_done_received = True
    else:
        print("[-] Unknown Handshake type:", htype.hex())
        sys.exit(1)

    # handle the case of several Handshake messages in one record
    leftover = full_body.replace(body, b'')
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    # parse TLS record header and pass the record body to the corresponding parsing method (i.e., parsehandshake())

    if(r[0] == 22):
        parsehandshake(r[5:])
    else:   
        print("[-] Got errror with body, ",r[5:])
        sys.exit(1)


# read from the socket full TLS record
def readrecord():
    global s

    record = b""

    # read the TLS record header (5 bytes)
    record_header = s.recv(5)
    # find data length
    data_length = bi(record_header[3:5])
    # read the TLS record body
    for i in range(0,data_length):
        record += s.recv(1)
    return record_header + record  #send the full record

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
url = urlparse(args.url)
host = url.netloc.split(':')
if len(host) > 1:
    port = int(host[1])
else:
    port = 443
host = host[0]
path = url.path

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
while not server_hello_done_received:
    parserecord(readrecord())
s.send(alert())

print("[+] Closing TCP connection!")
s.close()
