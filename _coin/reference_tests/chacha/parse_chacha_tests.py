#!/usr/bin/env python3
"""
ChaCha20 Test Vector Parser

This script parses ChaCha20 test vectors from a tests.c file and generates 
a C header file with test vectors in a format similar to other crypto test suites.

Usage:
    python parse_chacha_tests.py -o test_vectors.h tests.c
"""

import re
import argparse
import os
from typing import List, Dict, Any

def parse_c_array(array_str: str) -> List[int]:
    """Parse a C array literal into a Python list of integers."""
    # Remove braces, newlines, tabs, and extra whitespace
    clean_str = array_str.strip('{}').replace('\n', '').replace('\t', '').replace(' ', '')
    
    # Handle trailing commas
    clean_str = clean_str.rstrip(',')
    
    if not clean_str:
        return []
    
    # Split by commas
    values = clean_str.split(',')
    result = []
    for val in values:
        val = val.strip()
        if val:
            # Handle hex values (0x...) and decimal values
            if val.startswith('0x'):
                result.append(int(val, 16))
            else:
                result.append(int(val))
    return result

def extract_test_vectors(file_path: str) -> List[Dict[str, Any]]:
    """Extract ChaCha20 cipher test vectors from the tests.c file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    test_vectors = []
    
    # Find cipher test suites using a simpler approach
    # Look for suite("...Cipher Test Vector...") and extract content until next suite or end
    suite_starts = []
    for match in re.finditer(r'suite\("([^"]*Cipher Test Vector[^"]*)"', content):
        if 'Chunked' not in match.group(1):  # Skip chunked tests
            suite_starts.append((match.group(1), match.start()))
    
    for i, (suite_name, start_pos) in enumerate(suite_starts):
        print(f"Processing suite: {suite_name}")
        
        # Find the end of this suite (next suite or end of file)
        if i + 1 < len(suite_starts):
            end_pos = suite_starts[i + 1][1]
        else:
            # Look for the next suite() call or end of file
            next_suite = re.search(r'suite\(', content[start_pos + 100:])
            if next_suite:
                end_pos = start_pos + 100 + next_suite.start()
            else:
                end_pos = len(content)
        
        suite_content = content[start_pos:end_pos]
        
        # Extract variables from the suite
        vector = {'suite_name': suite_name}
        
        # Extract key (handle multi-line arrays)
        key_match = re.search(r'key256_t\s+key\s*=\s*\{([^}]+)\}', suite_content, re.DOTALL)
        if key_match:
            try:
                vector['key'] = parse_c_array('{' + key_match.group(1) + '}')
            except Exception as e:
                print(f"  Error parsing key: {e}")
                continue
        
        # Extract nonce (handle multi-line arrays)
        nonce_match = re.search(r'nonce96_t\s+nonce\s*=\s*\{([^}]+)\}', suite_content, re.DOTALL)
        if nonce_match:
            try:
                vector['nonce'] = parse_c_array('{' + nonce_match.group(1) + '}')
            except Exception as e:
                print(f"  Error parsing nonce: {e}")
                continue
        
        # Extract count
        count_match = re.search(r'uint32_t\s+count\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)', suite_content)
        if count_match:
            count_val = count_match.group(1)
            try:
                if count_val.startswith('0x'):
                    vector['count'] = int(count_val, 16)
                else:
                    vector['count'] = int(count_val)
            except Exception as e:
                print(f"  Error parsing count: {e}")
                continue
        
        # Extract plaintext (data) - handle multi-line arrays
        data_match = re.search(r'uint8_t\s+data\[[^\]]*\]\s*=\s*\{([^}]+)\}', suite_content, re.DOTALL)
        if data_match:
            try:
                vector['plaintext'] = parse_c_array('{' + data_match.group(1) + '}')
            except Exception as e:
                print(f"  Error parsing plaintext: {e}")
                continue
        
        # Extract ciphertext - handle multi-line arrays
        cipher_match = re.search(r'uint8_t\s+ciphertext\[[^\]]*\]\s*=\s*\{([^}]+)\}', suite_content, re.DOTALL)
        if cipher_match:
            try:
                vector['ciphertext'] = parse_c_array('{' + cipher_match.group(1) + '}')
            except Exception as e:
                print(f"  Error parsing ciphertext: {e}")
                continue
        
        # Debug: Print what we found
        print(f"  Found fields: {list(vector.keys())}")
        
        # Only add vectors that have all required fields for cipher tests
        if ('key' in vector and 'nonce' in vector and 'count' in vector and 
            'plaintext' in vector and 'ciphertext' in vector):
            test_vectors.append(vector)
            print(f"  ✓ Added test vector")
        else:
            print(f"  ✗ Missing required fields")
    
    return test_vectors

def generate_c_header(test_vectors: List[Dict[str, Any]]) -> str:
    """Generate the C header file content from cipher test vectors."""
    header_content = []
    header_content.append("/* This file is automatically generated. Do not edit. */")
    header_content.append("/* ChaCha20 cipher test vectors extracted from tests.c */\n")
    
    header_content.append("#ifndef CHACHA20_TEST_VECTORS_H")
    header_content.append("#define CHACHA20_TEST_VECTORS_H")
    header_content.append("\n#include <stdint.h>")
    header_content.append("#include <stddef.h>\n")
    
    # Define the test vector structure for cipher tests
    header_content.append("typedef struct {")
    header_content.append("    const char *suite_name;")
    header_content.append("    const uint8_t key[32];")
    header_content.append("    const uint8_t nonce[12];")
    header_content.append("    const uint32_t count;")
    header_content.append("    const uint8_t *plaintext;")
    header_content.append("    const size_t plaintext_len;")
    header_content.append("    const uint8_t *expected_ciphertext;")
    header_content.append("    const size_t ciphertext_len;")
    header_content.append("} ChaCha20TestVector;\n")
    
    # Generate all data arrays
    for i, vector in enumerate(test_vectors):
        # Generate plaintext array
        plaintext_hex = ", ".join([f"0x{byte:02x}" for byte in vector['plaintext']])
        header_content.append(f"static const uint8_t plaintext_{i}[] = {{{plaintext_hex}}};")
        
        # Generate ciphertext array
        ciphertext_hex = ", ".join([f"0x{byte:02x}" for byte in vector['ciphertext']])
        header_content.append(f"static const uint8_t ciphertext_{i}[] = {{{ciphertext_hex}}};")
    
    # Generate the main test vector array
    header_content.append("\nstatic const ChaCha20TestVector chacha20_test_vectors[] = {")
    
    for i, vector in enumerate(test_vectors):
        # Format key and nonce
        key_hex = ", ".join([f"0x{byte:02x}" for byte in vector['key']])
        nonce_hex = ", ".join([f"0x{byte:02x}" for byte in vector['nonce']])
        
        header_content.append(f"    {{")
        header_content.append(f"        \"{vector['suite_name']}\",")
        header_content.append(f"        {{{key_hex}}},")
        header_content.append(f"        {{{nonce_hex}}},")
        header_content.append(f"        {vector['count']},")
        header_content.append(f"        plaintext_{i}, sizeof(plaintext_{i}),")
        header_content.append(f"        ciphertext_{i}, sizeof(ciphertext_{i})")
        header_content.append("    },")
    
    header_content.append("};")
    header_content.append(f"\nstatic const size_t num_chacha20_test_vectors = {len(test_vectors)};\n")
    header_content.append("#endif // CHACHA20_TEST_VECTORS_H")
    
    return "\n".join(header_content)

def main():
    """Main function to parse command-line arguments and run the script."""
    parser = argparse.ArgumentParser(
        description="Parse ChaCha20 test vectors from tests.c and generate C header file.",
        epilog="Example: python %(prog)s -o test_vectors.h tests.c"
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        dest="output_file",
        help="The path for the output .h file."
    )
    parser.add_argument(
        "input_file",
        help="The input tests.c file to parse."
    )
    
    args = parser.parse_args()
    
    try:
        print(f"Parsing {args.input_file}...")
        test_vectors = extract_test_vectors(args.input_file)
        
        if not test_vectors:
            print("No test vectors were successfully parsed.")
            return
        
        print(f"Found {len(test_vectors)} test vectors:")
        for vector in test_vectors:
            print(f"  - {vector['suite_name']}")
        
        c_header_content = generate_c_header(test_vectors)
        
        with open(args.output_file, 'w') as f:
            f.write(c_header_content)
        
        print(f"Successfully created {args.output_file}.")
        
    except FileNotFoundError:
        print(f"Error: File {args.input_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
