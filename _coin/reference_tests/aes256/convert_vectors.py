TESTS=0
def parse_hex_array(hexstr):
    return ', '.join(f'0x{hexstr[i:i+2]}' for i in range(0, len(hexstr), 2))

def convert_var_pt(filepath):
    global TESTS
    with open(filepath, 'r') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('//')]

    key_line = lines.pop(0)
    assert key_line.lower().startswith('key =')
    key = f"{{{parse_hex_array(key_line.split('=')[1])}}}"

    result = []
    for line in lines:
        pt, ct = line.split()
        pt = f"{{{parse_hex_array(pt)}}}"
        ct = f"{{{parse_hex_array(ct)}}}"
        result.append(f"    {{\n        {key},\n        {pt},\n        {ct}\n    }},")
        TESTS+=1

    print('\n'.join(result))

def convert_var_key(filepath):
    global TESTS
    with open(filepath, 'r') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('//')]

    pt_line = lines.pop(0)

    assert pt_line.lower().startswith('plaintext =')
    pt = f"{{{parse_hex_array(pt_line.split('=')[1])}}}"

    result = []
    i = 0
    while i + 2 < len(lines):
        key_part1 = lines[i]
        key_part2 = lines[i + 1]
        ct_line = lines[i + 2]
        full_key = key_part1 + key_part2
        key = f"{{{parse_hex_array(full_key)}}}"
        ct = f"{{{parse_hex_array(ct_line)}}}"
        result.append(f"    {{\n        {key},\n        {pt},\n        {ct}\n    }},")
        i += 3
        TESTS+=1


    print('\n'.join(result))

convert_var_key("test_vectors_var_key.txt")
convert_var_pt("test_vectors_var_pt.txt")

print("GEN TESTS: " + str(TESTS))
