from typing import TYPE_CHECKING, Callable

from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.classes.java.lang.string import String

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator
    from androidemu.data.models.system import BuildInfo


def _b_str(extractor: Callable[['BuildInfo'], str]) -> Callable[['Emulator'], String]:
    return lambda emu: String(extractor(emu.config.pkg.device.build))


def _b_int(extractor: Callable[['BuildInfo'], int]) -> Callable[['Emulator'], int]:
    return lambda emu: extractor(emu.config.pkg.device.build)


class Build_VERSION(metaclass=JavaClassDef, jvm_name='android/os/Build$VERSION',
                    jvm_fields=[
                        JavaFieldDef(
                            'SDK_INT', 
                            'I', 
                            True, 
                            _b_int(lambda b: b.sdk_int)
                        ),
                        JavaFieldDef(
                            'RELEASE', 
                            'Ljava/lang/String;', 
                            True, 
                            _b_str(lambda b: b.release)
                        ),
                        JavaFieldDef(
                            'SECURITY_PATCH', 
                            'Ljava/lang/String;', 
                            True, 
                            _b_str(lambda b: b.security_patch)
                        ),
                        JavaFieldDef(
                            'INCREMENTAL', 
                            'Ljava/lang/String;', 
                            True, 
                            _b_str(lambda b: b.fingerprint.split(":")[-1].split("/")[0])
                        ),
                        JavaFieldDef(
                            'CODENAME', 
                            'Ljava/lang/String;', 
                            True, 
                            lambda emu: String("REL")
                        ),
                    ]):
    def __init__(self) -> None:
        pass


class Build(metaclass=JavaClassDef, jvm_name='android/os/Build',
            jvm_fields=[
                JavaFieldDef('BRAND', 'Ljava/lang/String;', True, _b_str(lambda b: b.brand)),
                JavaFieldDef('MANUFACTURER', 'Ljava/lang/String;', True, _b_str(lambda b: b.manufacturer)),
                JavaFieldDef('MODEL', 'Ljava/lang/String;', True, _b_str(lambda b: b.model)),
                JavaFieldDef('DEVICE', 'Ljava/lang/String;', True, _b_str(lambda b: b.device)),
                JavaFieldDef('PRODUCT', 'Ljava/lang/String;', True, _b_str(lambda b: b.product)),
                JavaFieldDef('BOARD', 'Ljava/lang/String;', True, _b_str(lambda b: b.board)),
                JavaFieldDef('HARDWARE', 'Ljava/lang/String;', True, _b_str(lambda b: b.hardware)),
                JavaFieldDef('BOOTLOADER', 'Ljava/lang/String;', True, _b_str(lambda b: b.bootloader)),
                JavaFieldDef('FINGERPRINT', 'Ljava/lang/String;', True, _b_str(lambda b: b.fingerprint)),
                JavaFieldDef('CPU_ABI', 'Ljava/lang/String;', True, _b_str(lambda b: b.abi)),
                JavaFieldDef(
                    'CPU_ABI2', 
                    'Ljava/lang/String;', 
                    True, 
                    _b_str(lambda b: b.supported_abis[1] if len(b.supported_abis) > 1 else "")
                ),
                JavaFieldDef(
                    'ID', 
                    'Ljava/lang/String;', 
                    True, 
                    _b_str(lambda b: b.fingerprint.split(":")[1].split("/")[1] if ":" in b.fingerprint else "RKQ1.200826.002")
                ),
                JavaFieldDef('DISPLAY', 'Ljava/lang/String;', True, _b_str(lambda b: b.fingerprint.split(":")[1].split("/")[1] if ":" in b.fingerprint else "RKQ1.200826.002")),
                JavaFieldDef('SERIAL', 'Ljava/lang/String;', True, lambda emu: String("unknown")),
                JavaFieldDef('TAGS', 'Ljava/lang/String;', True, lambda emu: String("release-keys")),
                JavaFieldDef('TYPE', 'Ljava/lang/String;', True, lambda emu: String("user")),
                JavaFieldDef('USER', 'Ljava/lang/String;', True, lambda emu: String("builder")),
                JavaFieldDef('HOST', 'Ljava/lang/String;', True, lambda emu: String("build-host")),
            ]):
    def __init__(self) -> None:
        pass