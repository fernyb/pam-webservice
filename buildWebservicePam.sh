#!/bin/bash

gcc -c -L/usr/local/lib -Wall -o webservice src/webservice.c -ljson-c -lcurl
gcc -shared -o pam_webservice.so webservice -L/usr/local/lib -I/usr/local/include -lcurl -ljson-c

sudo rm /lib/security/pam_webservice.so

sudo mv pam_webservice.so /lib/security/pam_webservice.so

sudo chown root:root /lib/security/pam_webservice.so

rm webservice
