#!/usr/bin/env python3

import sys     # do not use any other imports/libraries
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString

# took 2 hours (please specify here how much time your solution required)


# this will wait until a card is inserted in any reader
channel = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
print("[+] Selected reader:", channel.getReader())

# using T=0 for compatibility and simplicity
try:
    channel.connect(CardConnection.T0_protocol)
except:
    # fallback to T=1 if the reader does not support T=0
    channel.connect(CardConnection.T1_protocol)

# detect and print the EstEID card platform
atr = channel.getATR()
if atr == [0x3B,0xFE,0x18,0x00,0x00,0x80,0x31,0xFE,0x45,0x45,0x73,0x74,0x45,0x49,0x44,0x20,0x76,0x65,0x72,0x20,0x31,0x2E,0x30,0xA8]:
    print("[+] EstEID v3.x on JavaCard")
elif atr == [0x3B,0xFA,0x18,0x00,0x00,0x80,0x31,0xFE,0x45,0xFE,0x65,0x49,0x44,0x20,0x2F,0x20,0x50,0x4B,0x49,0x03]:
    print("[+] EstEID v3.5 (10.2014) cold (eID)")
elif atr == [0x3B,0xDB,0x96,0x00,0x80,0xB1,0xFE,0x45,0x1F,0x83,0x00,0x12,0x23,0x3F,0x53,0x65,0x49,0x44,0x0F,0x90,0x00,0xF1]:
    print("[+] Estonian ID card (2018)")
else:
    print("[-] Unknown card:", toHexString(atr))
    sys.exit(1)

# wrapper
def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)

    # success
    if [sw1,sw2] == [0x90,0x00]:
        return data
    # signals that there is more data to read
    elif sw1 == 0x61:
        #print("[=] More data to read:", sw2)
        return send([0x00, 0xC0, 0x00, 0x00, sw2]) # GET RESPONSE of sw2 bytes
    elif sw1 == 0x6C:
        #print("[=] Resending with Le:", sw2)
        return send(apdu[0:4] + [sw2]) # resend APDU with Le = sw2
    # probably error condition
    else:
        print("Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu)))
        sys.exit(1)

results = dict()
file_ptr = 0
try:
    # reading personal data file
    #Supports only newer 2018 - today cards

    #navigating to personal data file
    #SELECT APPLET
    send([0x00,0xA4,0x04,0x00,0x10] + [0xA0, 0x00, 0x00, 0x00, 0x77,0x01,0x08,0x00,0x07,0x00,0x00,0xFE,0x00,0x00,0x01,0x00])
    #SELECT MASTER FILE
    send([0x00,0xA4,0x00,0x0C])
    #SELECT MF/5000
    send([0x00,0xA4,0x01,0x0C,0x02] + [0x50,0x00])


    #getting all the info from MF/5000/
    for i in range(1,16):
        #SELECT file 5000 + i
        send([0x00,0xA4,0x02,0x0C,0x02] + [0x50,i])
        #Read results
        results[i] = bytes(send([0x00,0xB0,0x00,0x00,0x00])).decode("utf-8")
except:
    print("[-] system error reading personal files")
    exit(1)

table = {
1:'Surname',
2:'First name line 1',
3:'First name line 2',
4:'Sex',
5:'Nationality',
6:'Birth date',
7:'Personal ID code',
8:'Document number',
9:'Expiry date',
10:'Place of birth',
11:'Date of issuance',
12:'Type of residence permit',
13:'Notes line 1',
14:'Notes line 2',
15:'Notes line 3',
16:'Notes line 4',
}

table_2018 = {
1:'Surname',
2:'First name',
3:'Sex',
4:'Citizenship',
5:'Date & place of birth',
6:'Personal ID code',
7:'Document number',
8:'Expiry date',
9:'Date & place of issuance',
10:'Type of residence permit',
11:'Notes line 1',
12:'Notes line 2',
13:'Notes line 3',
14:'Notes line 4',
15:'Notes line 5',
}

# print all enteries from the personal data file
print("[+] Personal data file:")
for i in range(1, 16):
    print(table_2018[i] + ": " + results[i])



print("[+] PIN retry counters:")
try:
    PIN1 = 0
    PIN2 = 0
    PUK = 0
    # reading PIN retry counters from the card
    #Supports only newer 2018 - today cards

    #navigating to MF for PIN1 and PUK
    #SELECT MASTER FILE
    send([0x00,0xA4,0x00,0x0C])
    #sending VERIFY for PIN1 and PUK
    data, sw1, tries = channel.transmit([0x00,0x20,0x00,1])
    PIN1 = tries & 15
    data, sw1, tries = channel.transmit([0x00,0x20,0x00,133])
    PUK = tries & 15
    
    #SELECT MF/ADF2
    send([0x00,0xA4,0x01,0x0C,0x02] + [0xAD,0xF2])
    data, sw1, tries = channel.transmit([0x00,0x20,0x00,2])
    PIN2 = tries & 15

    print("PIN1 tries: ",PIN1)
    print("PIN2 tries: ",PIN2)
    print("PUK tries: ",PUK)
except:
    print("[-] system error PIN tries")
    exit(1)
