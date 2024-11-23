#!/bin/bash

rm -f server.pem

echo "Testing facebook.com:"
./tls_getcert.py https://facebook.com/ --certificate server.pem
read
openssl x509 -inform PEM -in server.pem -text | grep 'Subject:'
read

echo "Testing amazon.com:"
./tls_getcert.py https://amazon.com/
echo
read
openssl x509 -inform PEM -in server.pem -text | grep 'Subject:'

echo "Testing live.com:"
./tls_getcert.py https://live.com/
echo
openssl x509 -inform PEM -in server.pem -text | grep 'Subject:'
read


