#!/usr/bin/env bash
set -ex

cd "$(dirname "$0")"

docker build -t solanalabs/sgxsdk .
docker push solanalabs/sgxsdk

