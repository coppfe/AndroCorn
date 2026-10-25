from enum import IntEnum
from typing import Tuple

class ArgKind(IntEnum):
    VOID = -1    # V
    BOOLEAN = 0  # Z
    BYTE = 1     # B
    CHAR = 2     # C
    SHORT = 3    # S
    INT = 4      # I
    LONG = 5     # J
    FLOAT = 6    # F
    DOUBLE = 7   # D
    OBJECT = 8   # L...;, [...]

_PRIMITIVE_MAP = {
    'Z': ArgKind.BOOLEAN,
    'B': ArgKind.BYTE,
    'C': ArgKind.CHAR,
    'S': ArgKind.SHORT,
    'I': ArgKind.INT,
    'J': ArgKind.LONG,
    'F': ArgKind.FLOAT,
    'D': ArgKind.DOUBLE,
}

def parse_signature(sig: str) -> Tuple[Tuple[ArgKind, ...], ArgKind]:
    assert sig.startswith('('), f"Invalid signature: {sig}"
    end = sig.index(')')
    params_str = sig[1:end]
    ret_str = sig[end + 1:]

    args = []
    i = 0
    n = len(params_str)
    while i < n:
        c = params_str[i]
        if c in _PRIMITIVE_MAP:
            args.append(_PRIMITIVE_MAP[c])
        elif c == '[':
            while i < n and params_str[i] == '[':
                i += 1
            if i < n and params_str[i] == 'L':
                i = params_str.index(';', i)
            args.append(ArgKind.OBJECT)
        elif c == 'L':
            i = params_str.index(';', i)
            args.append(ArgKind.OBJECT)
        else:
            raise ValueError(f"Unknown type '{c}' in signature '{sig}'")
        i += 1

    if ret_str == 'V':
        ret_kind = ArgKind.VOID
    elif ret_str in _PRIMITIVE_MAP:
        ret_kind = _PRIMITIVE_MAP[ret_str]
    elif ret_str.startswith(('L', '[')):
        ret_kind = ArgKind.OBJECT
    else:
        raise ValueError(f"Unknown return type '{ret_str}' in signature '{sig}'")

    return tuple(args), ret_kind