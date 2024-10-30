#!/bin/bash
# @see https://medium.com/@yakuphanbilgic3/create-self-signed-certificates-and-keys-with-openssl-4064f9165ea3
set -eux -o pipefail

sudo rm -rfv ./tls/
mkdir -p ./tls/

#### CA
openssl genrsa 2048 > ./tls/ca-key.pem

openssl req -new -x509 -nodes -days 365 \
   -key ./tls/ca-key.pem \
   -out ./tls/ca-cert.pem \
   -subj "/C=BR/O=Batch Create/CN=batch-create-ca"

#### LDAP Server
openssl req -newkey rsa:2048 -nodes \
   -keyout ./tls/server-key.pem \
   -out ./tls/server-req.pem \
   -subj "/C=BR/O=Batch Create/CN=batch-create-ldap-server"

openssl x509 -req -days 365 \
   -in ./tls/server-req.pem \
   -out ./tls/server-cert.pem \
   -CA ./tls/ca-cert.pem \
   -CAkey ./tls/ca-key.pem \
   -extfile <(printf "subjectAltName=DNS:localhost,DNS:batch-create-ldap-server")

#### LDAP Server Fullchain
cat ./tls/server-cert.pem ./tls/ca-cert.pem > ./tls/ca-fullchain.pem

#### Bitnami's `bitnami/openldap` docker image runs with user 1001:1001
sudo chown -R 1001:1001 ./tls/*.pem
sudo chgrp -R 1001:1001 ./tls/*.pem
