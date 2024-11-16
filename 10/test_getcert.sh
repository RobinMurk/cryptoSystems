#!/bin/bash
./esteid_getcert.py --cert auth --out auth.pem
echo 'openssl x509 -in auth.pem -text | grep 'X509v3 Key Usage' -A 1'
openssl x509 -in auth.pem -text | grep 'X509v3 Key Usage' -A 1
echo
./esteid_getcert.py --cert sign --out sign.pem
echo 'openssl x509 -in sign.pem -text | grep 'X509v3 Key Usage' -A 1'
openssl x509 -in sign.pem -text | grep 'X509v3 Key Usage' -A 1
echo
echo 'openssl x509 -in auth.pem -text | grep "CA Issuers"'
openssl x509 -in auth.pem -text | grep "CA Issuers"
echo
echo 'wget "http://c.sk.ee/esteid2018.der.crt" -O ca.der'
wget "http://c.sk.ee/esteid2018.der.crt" -O ca.der
openssl x509 -inform der -in ca.der -outform pem -out ca.pem 
openssl verify -partial_chain -CAfile ca.pem auth.pem
