#!/usr/bin/env python3

# sudo apt install python3-socks
import argparse
import socks
import socket
import sys
import secrets # https://docs.python.org/3/library/secrets.html

# do not use any other imports/libraries

# took 5 hours (please specify here how much time your solution required)


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

    # return command
    return buf.decode().strip()

# prints torchat command and sends it
def send_torchat_cmd(outgoing_socket:socket, cmd:str):
    print("[+] Sending: ", cmd)
    message = cmd + '\n'
    outgoing_socket.sendall(message.encode())

#checks if the connection is authenticated
def check_auth():
    if not incoming_authenticated:
        print("[!] Authentication failed, recived message before peer was authenticated")
        sys.exit(1)

SELF_ADDR = args.myself
PEER_ADDR = args.peer

# connecting to peer
send_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
send_socket.connect((PEER_ADDR + ".onion", 11009))
print("[+] Connecting to peer ", PEER_ADDR)

# sending ping
own_random = secrets.randbits(128)
send_torchat_cmd(send_socket, "ping " + SELF_ADDR + " " + str(own_random))

# listening for the incoming connection
sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sserv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
sserv.bind(('',8888))
sserv.listen(1)
print("[+] Listening...")


(s, address) = sserv.accept()

print("[+] Client %s:%s" % (address[0], address[1]))

incoming_authenticated = False
status_received = False
is_available = False
cookie_peer = ""
info_sent = False

# the main loop for processing the received commands
while True:
    cmdr = read_torchat_cmd(s)
    print("[+] Recived: ", cmdr)
    cmd = cmdr.split(' ')

    match cmd[0]:
        case "ping":
            if cmd[1] == PEER_ADDR:
                cookie_peer = cmd[2]
                status_received = True
            else:
                print("[!] Authentication failed, peer addresses do not match!")
                sys.exit(1)
        case "pong":
            if cmd[1] == str(own_random):
                if not status_received:
                    print("[!] Authentication failed, recived pong before ping!")
                    sys.exit(1)
                print("[+] Incoming connection Authenticated!")
                incoming_authenticated = True
                send_torchat_cmd(send_socket, "pong " + cookie_peer)
            else:
                print("[!] Authentication failed, self randoms do not match")
                sys.exit(1)
        case "message":
            check_auth()
            if is_available:
                self_message = input("[?] Enter message: ")
                send_torchat_cmd(send_socket, "message " + self_message)
        case "status":
            check_auth()
            is_available = True if cmd[1] == "available" else False
            if not info_sent:
                send_torchat_cmd(send_socket, "add_me")
                send_torchat_cmd(send_socket, "status available")
                send_torchat_cmd(send_socket, "profile_name PY_TESTNAME")
                info_sent = True

        
        
