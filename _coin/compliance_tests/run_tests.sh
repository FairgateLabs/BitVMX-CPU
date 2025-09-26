#!/bin/bash

# Set verify flag if requested
VERIFY_FLAG=""
if [[ "$1" == "--verify" ]]; then
    VERIFY_FLAG="--verify"
fi

NO_MAPPING_FLAG=""
if [[ "$2" == "--no-mapping" ]]; then
    NO_MAPPING_FLAG="--no-mapping"
fi

for f in ./build/*.elf; do
    echo "Running test $(basename "$f")"
    ../../target/release/emulator execute --elf "$f" $VERIFY_FLAG $NO_MAPPING_FLAG
done