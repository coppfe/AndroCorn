class Snapshot:
    __slots__ = ("cpu_context", "memory_pages", "brk_ptr", "generation")

    def __init__(self, cpu_context, memory_pages: dict, brk_ptr: int, generation: int):
        self.cpu_context = cpu_context
        self.memory_pages = memory_pages  # addr -> bytes
        self.brk_ptr = brk_ptr
        self.generation = generation