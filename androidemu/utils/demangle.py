try:
    from cpp_demangle import demangle as _demangle
except ImportError:
    _demangle = None


def simple_demangle(name: str) -> str:
    if _demangle:
        try:
            return _demangle(name)
        except Exception:
            pass

    return name