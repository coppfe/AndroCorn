import re

def simple_demangle(mangled):
    if not mangled.startswith("_Z"):
        return mangled
    
    body = re.sub(r'^_Z[LN]?', '', mangled)
    
    result = []
    pos = 0
    while pos < len(body):
        match = re.match(r'(\d+)', body[pos:])
        if not match:
            break
            
        length = int(match.group(1))
        start = pos + len(match.group(1))
        end = start + length
        
        segment = body[start:end]
        result.append(segment)
        
        pos = end
        if pos < len(body) and body[pos] == 'E':
            pos += 1
            break

    return "::".join(result) if result else mangled