import logging
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from .module import Module

logger = logging.getLogger(__name__)

class SymbolResolution:
    __slots__ = ("address", "tls_offset", "is_ifunc", "is_weak", "found")

    def __init__(
        self,
        address: int = 0,
        tls_offset: int = 0,
        is_ifunc: bool = False,
        is_weak: bool = False,
        found: bool = False,
    ):
        self.address = address
        self.tls_offset = tls_offset
        self.is_ifunc = is_ifunc
        self.is_weak = is_weak
        self.found = found


class SymbolResolver:

    def __init__(self, symbol_hooks: Dict[str, int]):
        self.symbol_hooks = symbol_hooks
        # sym_name -> SymbolResolution
        self._cache: Dict[str, SymbolResolution] = {}

    def invalidate_cache(self) -> None:
        self._cache.clear()

    def resolve(
        self,
        symbol_name: str,
        caller_module: Optional['Module'] = None,
        all_modules: Optional[List['Module']] = None,
    ) -> SymbolResolution:
        if not symbol_name:
            return SymbolResolution()

        if symbol_name in self.symbol_hooks:
            return SymbolResolution(
                address=self.symbol_hooks[symbol_name],
                found=True
            )

        if symbol_name in self._cache:
            return self._cache[symbol_name]

        if caller_module:
            res = self._lookup_in_dependencies(symbol_name, caller_module)
            if res.found:
                self._cache[symbol_name] = res
                return res

        if all_modules:
            for mod in all_modules:
                addr = mod.find_symbol(symbol_name)
                if addr is not None:
                    tls_off = getattr(mod, 'tls_offset', 0)
                    res = SymbolResolution(
                        address=addr,
                        tls_offset=tls_off,
                        found=True
                    )
                    self._cache[symbol_name] = res
                    return res

        return SymbolResolution(found=False)

    def _lookup_in_dependencies(self, sym_name: str, root_mod: 'Module') -> SymbolResolution:
        queue = [root_mod]
        visited = set()

        while queue:
            mod = queue.pop(0)
            if mod in visited:
                continue
            visited.add(mod)

            addr = mod.find_symbol(sym_name)
            if addr is not None:
                return SymbolResolution(
                    address=addr,
                    tls_offset=getattr(mod, 'tls_offset', 0),
                    found=True
                )

            for dep in mod.needed:
                if dep not in visited:
                    queue.append(dep)

        return SymbolResolution(found=False)