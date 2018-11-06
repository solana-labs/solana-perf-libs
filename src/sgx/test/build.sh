#!/bin/bash -e

pwd=$PWD
cd "$(dirname "$0")"

echo --- Build Enclave Test
(
  set -x
  make LIBS_PATH="$pwd"/libs OUT="$pwd"/dist
)
