#!/bin/bash

# This script builds multiple C files efficiently by reusing a single Docker container.
#
# Usage:
# ./docker-build.sh fibonacci/fibonacci.c another_test/main.c

if [ $# -lt 1 ]; then
    echo "Usage: $0 <path_to_c_file_1> [<path_to_c_file_2> ...]"
    exit 1
fi

CONTAINER_NAME="riscv32-reference-tests-builder"

cleanup() {
    echo "--- Cleaning up container: $CONTAINER_NAME ---"
    # Stop and remove the container. The output is silenced for clean exit.
    docker rm -f "$CONTAINER_NAME" > /dev/null 2>&1
}

trap cleanup EXIT INT TERM

CONTAINER_ID=$(docker run -d -it \
    --name "$CONTAINER_NAME" \
    -v "$CPU/docker-riscv32/":/data \
    -v "$CPU/_coin/reference_tests/":/tests \
    riscv32:latest \
    tail -f /dev/null)

if [ $? -ne 0 ]; then
    echo "!!! ERROR: Failed to start the Docker container. !!!" >&2
    exit 1 # The trap will still run cleanup.
fi

docker exec --workdir /data "$CONTAINER_ID" chmod +x ./riscv32/build.sh

# 4. --- EXECUTE BUILDS IN A LOOP ---
for c_file in "$@"; do
    output=$(docker exec -it --workdir /data "$CONTAINER_ID" qemu-riscv32 riscv32/build/coin_reference_tests/"$1" $2  2>&1)
    # Store the exit code immediately after the command runs.
    exit_code=$?
    echo "$output" >&2
    echo $exit_code
    exit $exit_code
done

echo "--- All reference tests built successfully. ---"
