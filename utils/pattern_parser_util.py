def parse_pattern(pattern_str: str) -> tuple:
    parts = pattern_str.split()
    pattern = b''
    wildcard = b''
    for part in parts:
        if part == "??":
            pattern += b'\x00'
            wildcard += b'\x01'
        else:
            pattern += bytes([int(part, 16)])
            wildcard += b'\x00'
    return pattern, wildcard
