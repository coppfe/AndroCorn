from .jvm_id_conter import *

from typing import Any

class JavaFieldDef:

    """
    Java Field Definition

    :param name: Name
    :param signature: Signature
    :param is_static: Is static
    :param static_value: Static value
    :param ignore: Ignore
    """

    def __init__(self, name: str, signature: str, is_static: bool, static_value: Any = None, ignore: bool = False):
        self.jvm_id         : int       = next_field_id()
        self.name           : str       = name
        self.signature      : str       = signature
        self.is_static      : bool      = is_static
        self.static_value   : Any       = static_value
        self.ignore         : bool      = ignore

        if self.is_static and self.static_value is None:
            raise ValueError('Static value may not be None for a static field.')
