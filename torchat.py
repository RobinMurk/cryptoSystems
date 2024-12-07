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

MYSELF = args.myself
PEER = args.peer

# route outgoing connections through Tor
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket

# reads and returns torchat command from the socket
def read_torchat_cmd(incoming_socket):
    # read until newline
    data = b""
    while not data.endswith(b"\n"):
        chunk = incoming_socket.recv(1)
        if not chunk:
            raise ConnectionError("Socket closed by peer")
        data += chunk
    # return command
    cmd = data.decode().strip()
    return cmd

# prints torchat command and sends it
def send_torchat_cmd(outgoing_socket, cmd):
    print(f"[+] Sending: {cmd}")
    outgoing_socket.sendall((cmd + "\n").encode())

# connecting to peer
print(f"[+] Connecting to peer {PEER}")
sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sserv.connect((PEER + ".onion", 11009))

# sending ping
cookie = secrets.randbits(128)
send_torchat_cmd(sserv, f"ping {MYSELF} {cookie}")

# listening for the incoming connection
print("[+] Listening...")
incoming = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

incoming.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
incoming.bind(('', 8888))
incoming.listen(1)
(incoming_socket, address) = incoming.accept()
print("[+] Client %s:%s" % (address[0], address[1]))

incoming_authenticated = False
status_received = False
cookie_peer = ""

# the main loop for processing the received commands
while True:
    cmdr = read_torchat_cmd(incoming_socket)
    print(f"[+] Received: {cmdr}")
    cmd = cmdr.split(' ')

    if cmd[0]=='ping':
        if cmd[1] == PEER:
            cookie_peer = cmd[2]
        else:
            print("[!] Incoming connection authentication failed!")
            break
    elif cmd[0] == 'pong':
        if cmd[1] == str(cookie):
            print("[+] Incoming connection authenticated!")
            incoming_authenticated = True
            send_torchat_cmd(sserv, f"pong {cookie_peer}")
            send_torchat_cmd(sserv, "add_me")
            send_torchat_cmd(sserv, "status available")
            send_torchat_cmd(sserv, f"profile_name Alice")
        else:
            print("[!] Pong verification failed: Cookie mismatch")
            break
    if not incoming_authenticated:
            continue
    
    elif cmd[0] == 'message':
            user_msg = input("[?] Enter message: ")
            send_torchat_cmd(sserv, f"message {user_msg}")
    
    

    