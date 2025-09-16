#!/bin/bash

# This script runs a series of YAML test files through an emulator,
# testing them with incrementing hexadecimal inputs. It logs
# unexpected failures and runs verification steps on success.
# It performs: 1) EMU execution, 2) Verification, 3) Prove/Verify check

# --- Configuration ---
# Path to the emulator executable. Make sure the CPU env var is set.
EMULATOR_CMD="$CPU/target/release/emulator"
LOG_FILE="error.log"

# --- Pre-flight Checks ---
if [[ -z "$CPU" ]]; then
    echo "Error: The \$CPU environment variable is not set. Please set it to the root of your project."
    exit 1
fi

if ! [[ -x "$EMULATOR_CMD" ]]; then
    echo "Error: Emulator not found or is not executable at '$EMULATOR_CMD'"
    exit 1
fi

START_INDEX=0
if [[ "$1" == "-s" || "$1" == "--start-index" ]]; then
    # Check if a value is provided and if it's a non-negative integer.
    if [[ -n "$2" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
        START_INDEX=$2
        shift 2 # Consume the flag and its value from the argument list.
    else
        echo "Error: A valid integer start index must be provided after '$1'." >&2
        exit 1
    fi
fi

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 [-s START_INDEX] <path_to_test_1.yaml> [<path_to_test_2.yaml> ...]"
    exit 1
fi

# New loop to check for existence of all YAML files before starting.
for yaml_file in "$@"; do
    if ! [[ -f "$yaml_file" ]]; then
        echo "Error: YAML file not found: $yaml_file"
        echo "Exiting."
        exit 1
    fi
done

echo "--- Starting Test Run ---"
echo "Logging errors to: $LOG_FILE"
if [ "$START_INDEX" -ne 0 ]; then
    echo "Starting from input index: $START_INDEX"
fi
echo ""

# Iterate through all .yaml files passed as arguments to the script.
for yaml_file in "$@"; do
    echo "[TESTING] $(basename "$yaml_file")"
    input_index=$START_INDEX  # Reset input_index for each YAML file
    
    # Use the YAML file path directly
    PDF_PATH="$yaml_file"
    if [[ ! -f "$PDF_PATH" ]]; then
        echo "  ERROR: YAML file not found at $PDF_PATH"
        echo "YAML: $(basename "$yaml_file") | REASON: File not found" >> "$LOG_FILE"
        continue
    fi
    
    # Extract ELF path from YAML file
    ELF_PATH=$(grep "^elf:" "$PDF_PATH" | sed 's/^elf:[[:space:]]*//' | tr -d '"')
    if [[ -z "$ELF_PATH" ]]; then
        echo "  ERROR: No ELF path found in YAML file"
        echo "YAML: $(basename "$yaml_file") | REASON: Missing ELF path in YAML" >> "$LOG_FILE"
        continue
    fi
    
    # Convert relative path to absolute path based on YAML file location
    if [[ "$ELF_PATH" =~ ^\.\./ ]]; then
        # Relative path - resolve it relative to the YAML file's directory
        YAML_DIR=$(dirname "$yaml_file")
        ELF_PATH="$YAML_DIR/$ELF_PATH"
    fi
    
    # Normalize the path to remove any .. components
    ELF_PATH=$(realpath "$ELF_PATH" 2>/dev/null)
    if [[ ! -f "$ELF_PATH" ]]; then
        echo "  ERROR: ELF file not found at $ELF_PATH"
        echo "YAML: $(basename "$yaml_file") | REASON: ELF file not found at $ELF_PATH" >> "$LOG_FILE"
        continue
    fi

    # Loop indefinitely until we get the "out of bounds" signal (42).
    while true; do
        raw_hex=$(printf "%x" "$input_index")
        if (( ${#raw_hex} % 2 != 0 )); then
            hex_input="0${raw_hex}"
        else
            hex_input="${raw_hex}"
        fi

        echo -n "  - Input: 0x${hex_input} ... "

        # Execute the command and capture its output.
        output=$(RUST_BACKTRACE=full "$EMULATOR_CMD" execute --elf "$ELF_PATH" --input "$hex_input" 2>&1)
        
        # Check for command failure before parsing output
        if [ $? -ne 0 ]; then
            echo "FAIL (Emulator Crashed)"
            echo "YAML: $(basename "$yaml_file") | INPUT: 0x${hex_input} | REASON: Emulator exited with non-zero status" >> "$LOG_FILE"
            echo "--- Crash Output ---" >> "$LOG_FILE"
            echo "$output" >> "$LOG_FILE"
            echo "--------------------" >> "$LOG_FILE"
            # Decide if you want to stop on crash or continue with next input
            # For now, we'll continue with the next file.
            break
        fi

        # Parse the execution result code from the output, e.g., Halt(N, ?)
        halt_code=$(echo "$output" | grep -oP 'Halt\(\K[0-9]+')

        # --- Logic for handling different halt codes ---
        if [[ "$halt_code" == "42" ]]; then
            echo "OK (Finished)"
            break # Exit the inner `while` loop, move to the next ELF file.

        elif [[ "$halt_code" == "0" ]]; then
            echo -n "OK (Running Verification)... "
            verify_output=$(RUST_BACKTRACE=full "$EMULATOR_CMD" execute --elf "$ELF_PATH" --input "$hex_input" --verify 2>&1)
            
            # Check for Bitcoin script verification failures
            if echo "$verify_output" | grep -q "BitcoinScriptVerification"; then
                failure_reason=$(echo "$verify_output" | grep "BitcoinScriptVerification")
                echo "FAIL (Verification)"
                echo "YAML: $(basename "$yaml_file") | INPUT: 0x${hex_input} | REASON: $failure_reason" >> "$LOG_FILE"
            else
                echo -n "OK (Verified, Running Prove/Verify)... "
                
                # Run prove and verify check using prove_verify_elfs.sh with single input
                prove_verify_result=$(./prove_verify_elfs.sh --single-input "$hex_input" "$PDF_PATH" 2>&1)
                prove_verify_exit_code=$?
                
                if [ $prove_verify_exit_code -eq 0 ]; then
                    echo "OK (Prove/Verify Passed)"
                else
                    echo "FAIL (Prove/Verify Failed)"
                    echo "YAML: $(basename "$yaml_file") | INPUT: 0x${hex_input} | REASON: Prove/Verify check failed" >> "$LOG_FILE"
                    echo "--- Prove/Verify Output ---" >> "$LOG_FILE"
                    echo "$prove_verify_result" >> "$LOG_FILE"
                    echo "---------------------------" >> "$LOG_FILE"
                fi
            fi

        else
            # Any other non-zero halt code is an unexpected error.
            echo "FAIL (Unexpected Halt Code: $halt_code)"
            echo "YAML: $(basename "$yaml_file") | INPUT: 0x${hex_input} | REASON: Unexpected Halt Code ($halt_code)" >> "$LOG_FILE"
        fi

        # Increment for the next loop.
        ((input_index++))
    done
    echo "" # Newline for cleaner output between files.
done

echo "--- Test Run Finished ---"
