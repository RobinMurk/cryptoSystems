#!/bin/bash

myself=$(sudo cat /var/lib/tor/hidden_service/hostname | sed 's/\.onion$//')
./torchat.py --myself "$myself" --peer sig32evozhhgbpcbxsnsynv7ya53qcja5foockusbjydqpse3rsh5ryd