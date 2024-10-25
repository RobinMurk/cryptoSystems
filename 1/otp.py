#!/usr/bin/env python3
import os, sys       # do not use any other imports/libraries
# took 3-4 hours: this was mainly because i had become a bit rusty during the summer so getting back into coding took more time

def bi(b):  #turns a byte value to an integer value
    i = b[0]
    for value in range(1,len(b)):
        i = i << 8
        i = i | b[value]
    return i

def ib(i, length): #turns an integer value to a byte value
    # i - an integer to encode as bytes
    # length - specifies in how many bytes the integer should be encoded
    b = b''

    for x in range(length):
        bits = [i & 255]
        b = bytes(bits) + b
        i = i >> 8
    return b

def encrypt(pfile, kfile, cfile):
    p_bytes = open(pfile,'rb').read()
    encryption_size = len(p_bytes)

    plain_int = bi(p_bytes) #conversion to integer

    key_bytes = os.urandom(encryption_size)
    key = bi(key_bytes) #key as integer

    encrypted = plain_int ^ key  #XOR

    #writing encrypted to file
    with open(cfile,'wb') as file:
        file.write(ib(encrypted,encryption_size)) #convert back to bytes
        file.close()

    #writing key to file
    with open (kfile,'wb') as file:
        file.write(key_bytes)
        file.close()
    

def decrypt(cfile, kfile, pfile):
    encrypted_text = open(cfile,'rb').read()
    key = open(kfile,'rb').read()
    

    text_to_int = bi(encrypted_text)
    key_to_int = bi(key)
    decrypted_int = text_to_int ^ key_to_int  #XOR
    print("integer:" + str(decrypted_int))

    with open(pfile,'wb') as file:
        file.write(ib(decrypted_int,len(encrypted_text))) #convert back to bytes
        file.close()


def usage():
    print("Usage:")
    print("encrypt <plaintext file> <output key file> <ciphertext output file>")
    print("decrypt <ciphertext file> <key file> <plaintext output file>")
    sys.exit(1)   


if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()