def gnu_hash(name):
    h = 5381
    for c in name:
        h = (h << 5) + h + ord(c)
    return h & 0xFFFFFFFF

def read_uleb128(buffer, offset):
    val = 0
    shift = 0
    while True:
        byte = buffer[offset]
        offset += 1
        val |= (byte & 0x7f) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return val, offset

def read_sleb128(buffer, offset):
    val = 0
    shift = 0
    byte = 0
    while True:
        byte = buffer[offset]
        offset += 1
        val |= (byte & 0x7f) << shift
        shift += 7
        if not (byte & 0x80):
            break
    if (byte & 0x40) and (shift < 64):
        val |= - (1 << shift)
    return val, offset