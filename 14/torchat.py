#!/usr/bin/env python3

# sudo apt install python3-socks
import argparse
import socks
import socket
import sys
import secrets # https://docs.python.org/3/library/secrets.html

# do not use any other imports/libraries

# took x.y hours (please specify here how much time your solution required)


# parse arguments
parser = argparse.ArgumentParser(description='TorChat client')
parser.add_argument('--myself', required=True, type=str, help='My TorChat ID')
parser.add_argument('--peer', required=True, type=str, help='Peer\'s TorChat ID')
args = parser.parse_args()

# route outgoing connections through Tor
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket

# reads and returns torchat command from the socket
def read_torchat_cmd(incoming_socket:socket):
    # read until newline
    buf = b''
    el = b''
    while el != b'\n' or not el:
        el = incoming_socket.recv(1)
        buf += el

    cmd = str(buf)
    # return command
    return cmd

# prints torchat command and sends it
def send_torchat_cmd(outgoing_socket:socket, cmd):
    if( cmd == "ping"):
        message = "ping " + args.myself + '\n' + own_random
        outgoing_socket.send(bytes(message,'utf-8'))
        print("[+] Sending: ", message)
    pass

# connecting to peer
send_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
send_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
send_socket.connect(("127.0.0.1","11009"))
print("[+] Connecting to peer ", args.peer)

# sending ping
own_random = secrets.randbits(128)
send_torchat_cmd(send_socket, "ping")

# listening for the incoming connection
sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sserv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
sserv.bind(('',8888))
sserv.listen(0)
print("[+] Listening...")

s = ''
address = ''
(s, address) = sserv.accept()

print("[+] Client %s:%s" % (address[0], address[1]))

incoming_authenticated = False
status_received = False
cookie_peer = ""

# the main loop for processing the received commands
while True:
    cmdr = read_torchat_cmd(sserv)

    cmd = cmdr.split(' ')

    if cmd[0]=='ping':
        read_torchat_cmd(sserv)
