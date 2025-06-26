#!/bin/sh

cd "${0%/*}"

# Create certificates for the proxy server
if [ ! -d "certs" ]; then
    mkdir certs
fi

openssl req \
        -x509 \
        -nodes \
        -days 3650 \
        -newkey rsa:4096 \
        -keyout certs/certificate.key \
        -out certs/certificate.crt \
        -subj "/C=XX/ST=XXX/L=XXXX/O=XXXXX/CN=${PYTHIA_HOSTNAME:-localhost}"
