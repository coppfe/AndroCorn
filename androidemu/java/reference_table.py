from typing import Dict, Optional, Set
from .jni.reference import jobject

class ReferenceTable:
    def __init__(self, start: int = 1, max_entries: int = 1024):
        self._start = start
        self._max_entries = max_entries
        self._next_id = start
        self._free_ids: Set[int] = set()
        
        # id -> jobject
        self._table: Dict[int, jobject] = {}
        # id(jobject) -> ref_id
        self._obj_to_id: Dict[int, int] = {}

    def add(self, obj: jobject) -> int:
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        if len(self._table) >= self._max_entries:
            raise RuntimeError(f"ReferenceTable overflow (limit: {self._max_entries})")

        if self._free_ids:
            ref_id = self._free_ids.pop()
        else:
            ref_id = self._next_id
            self._next_id += 1

        self._table[ref_id] = obj
        self._obj_to_id[id(obj)] = ref_id
        return ref_id

    def set(self, idx: int, newobj: jobject) -> None:
        if not isinstance(newobj, jobject):
            raise ValueError('Expected a jobject.')
        if idx not in self._table:
            raise KeyError(f'Invalid reference index {idx}')
        
        old_obj = self._table[idx]
        self._obj_to_id.pop(id(old_obj), None)
        
        self._table[idx] = newobj
        self._obj_to_id[id(newobj)] = idx

    def remove(self, obj: jobject) -> bool:
        ref_id = self._obj_to_id.pop(id(obj), None)
        if ref_id is None:
            return False
        self._table.pop(ref_id, None)
        self._free_ids.add(ref_id)
        return True

    def remove_by_id(self, idx: int) -> bool:
        obj = self._table.pop(idx, None)
        if obj is None:
            return False
        self._obj_to_id.pop(id(obj), None)
        self._free_ids.add(idx)
        return True

    def get(self, idx: int) -> Optional[jobject]:
        return self._table.get(idx)

    def in_range(self, idx: int) -> bool:
        return self._start <= idx < self._start + self._max_entries

    def clear(self) -> None:
        self._table.clear()
        self._obj_to_id.clear()
        self._free_ids.clear()
        self._next_id = self._start