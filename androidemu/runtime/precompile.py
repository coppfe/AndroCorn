import inspect
from functools import wraps

from ..const.emu_const import ARCH_ARM32

from ..types.numbers import NumType
from ..types.alias import DynType
from ..types import alias

TRANSFORMERS = {
    NumType.S32: lambda r: ((r & 0xffffffff) - 0x100000000 if (r & 0x80000000) else (r & 0xffffffff)),
    NumType.U32: lambda r: (r & 0xffffffff),
    NumType.S64: lambda r: ((r & 0xffffffffffffffff) - 0x10000000000000000 if (r & 0x8000000000000000) else (r & 0xffffffffffffffff)),
    NumType.U64: lambda r: (r & 0xffffffffffffffff),
    NumType.PTR: lambda r: r,
}

def define(func: callable):
    sig = inspect.signature(func)
    
    annotations_chain = []
    
    for name, param in sig.parameters.items():
        if name in ('self', 'mu', 'uc', 'emu'):
            continue
            
        annotation = param.annotation

        if isinstance(annotation, str):
            annotation = getattr(NumType, annotation.upper(), None)
            
        annotations_chain.append(annotation)
        
    arg_count = len(annotations_chain)

    @wraps(func)
    def magic_wrapper(*args, **kwargs):
        prefix_len = len(args) - arg_count
        prefix = args[:prefix_len]
        emu_args = args[prefix_len:]
        

        runtime_default = NumType.S32 if alias._current_arch == ARCH_ARM32 else NumType.S64
        
        transformed_args = []
        for i in range(arg_count):
            anno = annotations_chain[i]
            val = emu_args[i]
            
            if anno is None or not isinstance(anno, (NumType, DynType)):
                current_type = runtime_default
            elif isinstance(anno, DynType):
                current_type = anno._get_current()
            else:
                current_type = anno
                
            transformer = TRANSFORMERS.get(current_type, TRANSFORMERS[runtime_default])
            transformed_args.append(transformer(val))
        
        result = func(*prefix, *transformed_args, **kwargs)

        return result
        
    return magic_wrapper