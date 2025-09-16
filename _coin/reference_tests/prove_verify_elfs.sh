#!/bin/bash

# This script runs a series of YAML test files through an emulator,
# testing them with incrementing hexadecimal inputs. It logs
# unexpected failures and runs verification steps on success.

# --- Configuration ---
# Path to the emulator executable. Make sure the CPU env var is set.
EMULATOR_CMD="$CPU/target/release/emulator"
LOG_FILE="error.log"

# Challenge test configuration
CHECKPOINT_DIR="test-checkpoints"
PROVER_CHECKPOINT_PATH="$CHECKPOINT_DIR/prover"
VERIFIER_CHECKPOINT_PATH="$CHECKPOINT_DIR/verifier"

# Function to run prove/verify test for a single input
run_prove_verify_test() {
    local yaml_file="$1"
    local hex_input="$2"
    
    if [ "$SINGLE_INPUT_MODE" = false ]; then
        echo -n "  - Input: 0x${hex_input} ... "
    fi

    # ProverExecute - capture both output and success/failure
    PROVER_EXECUTE_OUT="$PROVER_CHECKPOINT_PATH/prover_execute.json"
    prover_output=$(RUST_BACKTRACE=full "$CPU/target/release/emulator" prover-execute \
        --pdf "$PDF_PATH" \
        --input "$hex_input" \
        --checkpoint-prover-path "$PROVER_CHECKPOINT_PATH" \
        --command-file "$PROVER_EXECUTE_OUT" 2>&1)
    prover_exit_code=$?
    
    # Check if prover execution failed
    if [ $prover_exit_code -ne 0 ]; then
        if [ "$SINGLE_INPUT_MODE" = true ]; then
            echo "FAILED (Prover execution failed)" >&2
            echo "Error output: $prover_output" >&2
        else
            echo "FAILED (Prover execution failed)"
            echo "Error output: $prover_output"
            echo "YAML: $(basename "$yaml_file") | INPUT: 0x${hex_input} | REASON: Prover execution failed" >> "$LOG_FILE"
        fi
        return 1
    fi

    # Extract halt code from prover output to detect "out of bounds" (42)
    halt_code=$(echo "$prover_output" | grep -oP 'Halt\(\K[0-9]+' | head -1 || echo "")
    
    # Check if we've reached the end of valid inputs (halt code 42)
    if [[ "$halt_code" == "42" ]]; then
        if [ "$SINGLE_INPUT_MODE" = false ]; then
            echo "END (Out of bounds - halt code 42)"
            return 2  # Special return code to break the loop
        else
            echo "Input out of bounds (halt code 42)" >&2
            return 1
        fi
    fi

    LAST_STEP=$(jq -r '.data.last_step' "$PROVER_EXECUTE_OUT")
    LAST_HASH=$(jq -r '.data.last_hash' "$PROVER_EXECUTE_OUT")

    # VerifierCheckExecution - capture output and handle failures
    VERIFIER_CHECK_OUT="$VERIFIER_CHECKPOINT_PATH/verifier_check.json"
    verifier_output=$("$CPU/target/release/emulator" verifier-check-execution \
        --pdf "$PDF_PATH" \
        --input "$hex_input" \
        --checkpoint-verifier-path "$VERIFIER_CHECKPOINT_PATH" \
        --claim-last-step "$LAST_STEP" \
        --claim-last-hash "$LAST_HASH" \
        --force no \
        --command-file "$VERIFIER_CHECK_OUT" 2>&1)
    verifier_exit_code=$?

    # Check if verifier execution failed
    if [ $verifier_exit_code -ne 0 ]; then
        if [ "$SINGLE_INPUT_MODE" = true ]; then
            echo "FAILED (Verifier execution failed)" >&2
        else
            echo "FAILED (Verifier execution failed)"
            echo "YAML: $(basename "$yaml_file") | INPUT: 0x${hex_input} | REASON: Verifier execution failed" >> "$LOG_FILE"
        fi
        return 1
    fi

    V_DECISION=$(jq -r '.data.step' "$VERIFIER_CHECK_OUT")
    
    # --- Logic for handling verifier decision ---
    if [[ "$V_DECISION" == "null" ]] || [[ -z "$V_DECISION" ]]; then
        if [ "$SINGLE_INPUT_MODE" = false ]; then
            echo "OK (Both implementations matched - no challenge needed)"
        fi
        return 0
    else
        if [ "$SINGLE_INPUT_MODE" = true ]; then
            echo "MISMATCH (Challenge needed at step: $V_DECISION)" >&2
        else
            echo "MISMATCH (Challenge needed at step: $V_DECISION)"
            echo "YAML: $(basename "$yaml_file") | INPUT: 0x${hex_input} | REASON: Implementations diverged at step $V_DECISION" >> "$LOG_FILE"
        fi
        return 1
    fi
}

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
SINGLE_INPUT_MODE=false
SINGLE_INPUT_VALUE=""

if [[ "$1" == "-s" || "$1" == "--start-index" ]]; then
    # Check if a value is provided and if it's a non-negative integer.
    if [[ -n "$2" ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
        START_INDEX=$2
        shift 2 # Consume the flag and its value from the argument list.
    else
        echo "Error: A valid integer start index must be provided after '$1'." >&2
        exit 1
    fi
elif [[ "$1" == "--single-input" ]]; then
    # Single input mode for calling from test_elfs.sh
    if [[ -n "$2" ]] && [[ "$2" =~ ^[0-9a-fA-F]+$ ]]; then
        SINGLE_INPUT_MODE=true
        SINGLE_INPUT_VALUE="$2"
        shift 2 # Consume the flag and its value from the argument list.
    else
        echo "Error: A valid hex input must be provided after '$1'." >&2
        exit 1
    fi
fi

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 [-s START_INDEX] [--single-input HEX_INPUT] <path_to_test_1.yaml> [<path_to_test_2.yaml> ...]"
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
if [ "$SINGLE_INPUT_MODE" = true ]; then
    echo "Single input mode: 0x$SINGLE_INPUT_VALUE"
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
    
    # Setup checkpoint directories for this YAML test
    rm -rf "$CHECKPOINT_DIR"
    mkdir -p "$PROVER_CHECKPOINT_PATH" "$VERIFIER_CHECKPOINT_PATH"

    # Handle single input mode or normal loop mode
    if [ "$SINGLE_INPUT_MODE" = true ]; then
        # Single input mode - run only once with the specified input
        hex_input="$SINGLE_INPUT_VALUE"
        run_prove_verify_test "$yaml_file" "$hex_input"
    else
        # Normal loop mode - run until halt code 42
        # Loop indefinitely until we get the "out of bounds" signal (42).
        while true; do
            raw_hex=$(printf "%x" "$input_index")
            if (( ${#raw_hex} % 2 != 0 )); then
                hex_input="0${raw_hex}"
            else
                hex_input="${raw_hex}"
            fi

            echo -n "  - Input: 0x${hex_input} ... "

            # Run the prove/verify test
            result=$(run_prove_verify_test "$yaml_file" "$hex_input")
            exit_code=$?
            
            if [ $exit_code -eq 2 ]; then
                # Special case: halt code 42 (out of bounds)  
                echo "$result"
                break
            elif [ $exit_code -ne 0 ]; then
                # Other failures - continue to next input
                ((input_index++))
                continue
            fi

            # Increment for the next loop.
            ((input_index++))
        done
    fi
    echo "" # Newline for cleaner output between files.
done

echo "--- Test Run Finished ---"
