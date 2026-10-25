from array import array as _pyarray

import struct

from .constants import JNI_PRIM_ELEMENT

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..class_def import JavaClassDef

# Internal methods

def _is_zero_arg_init(pyclazz) -> bool:
    cached = pyclazz.__dict__.get("_can_init_no_args")
    if cached is not None:
        return cached

    init = pyclazz.__init__
    if init is object.__init__:
        can_init = True
    else:
        func = getattr(init, "__func__", init)
        code = getattr(func, "__code__", None)
        if code is not None:
            num_defaults = len(func.__defaults__) if func.__defaults__ else 0
            req_pos_args = code.co_argcount - num_defaults
            kwdefaults = func.__kwdefaults__ or {}
            req_kwonly_args = code.co_kwonlyargcount - len(kwdefaults)
            can_init = (req_pos_args <= 1 and req_kwonly_args == 0)
        else:
            raise ValueError("Not a valid Python Function.")

    try:
        pyclazz._can_init_no_args = can_init
    except (TypeError, AttributeError):
        pass

    return can_init

# External Methods

def pack_elements(kind: str, values) -> bytes:
    """Python items -> the bytes of a native array. Integers are masked to their width, so signed and unsigned items both work."""
    _, wfmt, size = JNI_PRIM_ELEMENT[kind]
    if kind == "Z":
        values = [1 if v else 0 for v in values]
    elif kind in "CSIJ":
        mask = (1 << (8 * size)) - 1
        values = [int(v) & mask for v in values]
    else:
        values = [float(v) for v in values]
    try:
        return struct.pack(f"<{len(values)}{wfmt}", *values)
    except OverflowError:  # a float outside of the float32 range: +-inf, as a Java (float) cast gives
        inf = float("inf")
        return struct.pack(f"<{len(values)}f", *[v if abs(v) <= 3.4028234663852886e38 else (inf if v > 0 else -inf) for v in values])


def unpack_elements(kind: str, data: bytes) -> list:
    """The bytes of a native array -> Python items with Java semantics (signed short/int/long, unsigned char, boolean 0/1)."""
    rfmt, _, size = JNI_PRIM_ELEMENT[kind]
    values = list(struct.unpack(f"<{len(data) // size}{rfmt}", data))
    if kind == "Z":
        values = [1 if v else 0 for v in values]
    return values


def assign_region(pyobj, start: int, values: list) -> None:
    """array[start:start+len(values)] = values, IN PLACE, whatever the array keeps its items in."""
    items = pyobj.get_py_items()
    end = start + len(values)
    if isinstance(items, _pyarray):
        items[start:end] = _pyarray(items.typecode, values)
        return
    if isinstance(items, (bytes, tuple)):  # immutable backing store: swap it, keep the Java object
        items = list(items)
        pyobj.pyobject = items
    items[start:end] = values


def jint(v: int) -> int:
    """A jint / jsize argument as a signed 32 bit number (the upper register bits are not meaningful)."""
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v

def allocate_py_instance(pyclazz: 'JavaClassDef'):
    """
    Creates the Python object behind a Java instance WITHOUT running any Java constructor.

    ``NewObject*`` does ``pyclazz()`` and then calls the mocked ``<init>``. ``AllocObject``
    must do only the first half (JNI spec: the object is allocated "without invoking any of
    the object's constructors"), so the mocked ``<init>`` is never touched here - native code
    runs it later itself (``CallNonvirtual<Void>Method*`` / ``Call<Void>Method*``).

    The Python-level ``__init__`` is the mock's default-state initializer, not a Java
    constructor, so it is still run when it can be called without arguments (the same state
    a ``NewObject`` instance has before ``<init>`` runs). Mocks whose ``__init__`` requires
    arguments are allocated "raw" through ``__new__`` instead of failing.

    The signature is inspected instead of catching ``TypeError`` so that a real ``TypeError``
    raised inside a mock's ``__init__`` is not silently swallowed.
    """
    if _is_zero_arg_init(pyclazz):
        return pyclazz()
    return pyclazz.__new__(pyclazz)
