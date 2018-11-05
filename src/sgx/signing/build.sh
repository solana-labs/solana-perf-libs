#!/bin/bash -e

pwd=$PWD
cd "$(dirname "$0")"

echo --- Build
(
  set -x
  openssl genrsa -out "$pwd"/temp_priv_key.pem -3 3072
  openssl rsa -in "$pwd"/temp_priv_key.pem -pubout -out "$pwd"/temp_pub_key.pem
  make LIBS_PATH="$pwd"/libs OUT="$pwd"/dist PRIV_KEY="$pwd"/temp_priv_key.pem PUB_KEY="$pwd"/temp_pub_key.pem
)
