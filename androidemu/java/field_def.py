from .jvm.id_counter import *
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator

class JavaFieldDef:
    """
    Java Field Definition with Dynamic Resolution support.
    """

    def __init__(
        self,
        name: str,
        signature: str,
        is_static: bool,
        static_value: Any = None,
        getter: Optional[Callable[['Emulator', Any], Any]] = None,
        ignore: bool = False
    ):
        self.jvm_id: int = next_field_id()
        self.name: str = name
        self.signature: str = signature
        self.is_static: bool = is_static
        self.ignore: bool = ignore
        self._static_value: Any = static_value
        self._getter: Optional[Callable] = getter

        if self.is_static and self._static_value is None and self._getter is None:
            raise ValueError(f"Field '{name}' is static but has neither static_value nor getter.")

    def get_value(self, emu: 'Emulator', instance: Any = None) -> Any:
        if self._getter is not None:
            return self._getter(emu, instance) if not self.is_static else self._getter(emu)

        if self.is_static:
            if callable(self._static_value):
                return self._static_value(emu)
            return self._static_value

        if instance is not None:
            return getattr(instance, self.name, None)

        return None

    def set_value(self, emu: 'Emulator', value: Any, instance: Any = None) -> None:
        if self.is_static:
            self._static_value = value
        elif instance is not None:
            setattr(instance, self.name, value)

def java_field_def(name: str, signature: str, is_static: bool = True):
    def decorator(func):
        return JavaFieldDef(
            name=name,
            signature=signature,
            is_static=is_static,
            getter=func
        )
    return decorator