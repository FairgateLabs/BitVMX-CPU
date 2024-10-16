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

# Run the Docker container with the provided container name, script, and arguments
docker run -v "$(pwd)":/data -it --name "$container_name" "$container_name":latest \
    sh -c "chmod +x /data/$script_name && /data/$script_name $arguments"

# Remove the Docker container after completion
docker rm "$container_name"