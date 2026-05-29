from typing import Any

class GlobalContextMachine(dict):
    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __getattr__(self, name: str) -> Any:
        return self.get(name, None)