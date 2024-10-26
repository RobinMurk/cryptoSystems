#!/bin/bash

./ocsp_check.py valid.pem
echo
./ocsp_check.py revoked.pem
echo
