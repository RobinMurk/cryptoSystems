#!/usr/bin/env python3

import argparse, hashlib, sys, datetime # do not use any other imports/libraries

# took 0.5 hours (please specify here how much time your solution required)

## Output of running `pow.py --difficulty 26`:
## Nonce 1352027
## Check code for full input
## should solve in ~2.5 sec



def check_hash(hash) -> int:
    remaining = int.from_bytes(hash,byteorder='big') >> (256-DIFFICULTY)
    return 1 if remaining == 0 else 0
    

# parse arguments
parser = argparse.ArgumentParser(description='Proof-of-work solver')
parser.add_argument('--difficulty', default=0, type=int, help='Number of leading zero bits')
args = parser.parse_args()

DIFFICULTY = args.difficulty
nonce = 0
hash = b''
start = datetime.datetime.now()

while True:
    challenge_input = b'Robin Muerk' + nonce.to_bytes(8, byteorder='big')
    hash = hashlib.sha256(hashlib.sha256(challenge_input).digest()).digest()
    if(check_hash(hash)):
        break
    nonce += 1

end = datetime.datetime.now()
sec = (end - start).total_seconds()
Mhash = f"({(nonce / sec)/1000000} Mhash/sec)"
print(f"[+] Solved in {sec} {Mhash}")
print(f"[+] input: {challenge_input.hex()}")
print(f"[+] Solution: {hash.hex()}")
print(f"[+] Nonce: {nonce}")