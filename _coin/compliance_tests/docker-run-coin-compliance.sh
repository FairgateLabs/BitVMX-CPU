#!/bin/bash

# Check if at least two arguments are provided
if [ $# -lt 2 ]; then
    echo "Usage: $0 container_name script_name [arguments]"
    exit 1
fi

# Extract the first and second arguments
container_name="$1"
script_name="$2"

# Collect all remaining arguments (starting from the third)
arguments="${@:3}"

echo "Using $container_name to execute script $script_name with arguments: $arguments"

docker run --rm -it --name riscv-coin \
	  -v "$PWD":/riscv-tests \
	  riscv-coin:latest \
    	  sh -c "chmod +x /riscv-tests/$script_name && /riscv-tests/$script_name $arguments"