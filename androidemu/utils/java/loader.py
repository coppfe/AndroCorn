import importlib
import inspect
import logging
from pathlib import Path
from typing import TYPE_CHECKING
from androidemu.java.class_def import JavaClassDef

if TYPE_CHECKING:
    from androidemu.java.classloader import JavaClassLoader

logger = logging.getLogger("androidemu.loader")


def _register_from_module(class_loader: 'JavaClassLoader', mod, mod_name: str) -> None:
    for _, clz in inspect.getmembers(mod, inspect.isclass):
        if getattr(clz, '__module__', None) == mod_name and isinstance(clz, JavaClassDef):
            if not class_loader.find_class_by_name(clz.jvm_name):
                class_loader.add_class(clz)


def load_mocks(
    class_loader: 'JavaClassLoader',
    dir_name: str = "android",
    base_package: str = "androidemu.java.classes"
) -> None:
    pkg_name = f"{base_package}.{dir_name}".rstrip(".") if dir_name else base_package

    try:
        module = importlib.import_module(pkg_name)
    except Exception as e:
        logger.error(f"[-] Failed to import package '{pkg_name}': {e}")
        return

    mod_file = getattr(module, "__file__", None)
    if mod_file and not mod_file.endswith("__init__.py"):
        _register_from_module(class_loader, module, pkg_name)
        return

    package_dirs = []
    if hasattr(module, "__path__"):
        package_dirs = [Path(p).resolve() for p in module.__path__]
    elif mod_file:
        package_dirs = [Path(mod_file).resolve().parent]
    else:
        logger.error(f"[-] Cannot determine path for package '{pkg_name}'")
        return

    for package_dir in package_dirs:
        for py_file in package_dir.rglob("*.py"):
            if py_file.name == "__init__.py" or "registry" in py_file.parts:
                continue

            rel_parts = py_file.relative_to(package_dir).with_suffix("").parts
            sub_mod_name = f"{pkg_name}.{'.'.join(rel_parts)}"

            try:
                m = importlib.import_module(sub_mod_name)
                _register_from_module(class_loader, m, sub_mod_name)
            except Exception as e:
                logger.warning(f"[-] Failed to load mock module '{sub_mod_name}': {e}")