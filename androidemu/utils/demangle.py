from cpp_demangle import demangle

def simple_demangle(mangled):
    try:
        return demangle(mangled)
    except ValueError:
        return mangled