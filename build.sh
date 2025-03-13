#!/bin/bash

git submodule update --init

# Mbed-TLS auto-generates some code. This auto-generation needs some
# prerequisites python packages are required.

mkdir -p .venv
python3 -m venv .venv
source .venv/bin/activate

python3 install_prerequisites.py

DEST_DIR="./generated/library"

mkdir -p $DEST_DIR

build_and_copy() {
    local file="$1"
    local src_dir="mbedtls/csources/library"
    make --silent -C "$src_dir" "$file"
    cp "$src_dir/$file" "$DEST_DIR/."
}

build_and_copy error.c
build_and_copy version_features.c
build_and_copy ssl_debug_helpers_generated.c
build_and_copy psa_crypto_driver_wrappers.c
