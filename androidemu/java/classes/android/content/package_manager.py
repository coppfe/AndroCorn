import logging
from typing import TYPE_CHECKING, Optional

from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def
from ...java.lang.string import String
from ...java.lang.array import ObjectArray, ByteArray

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator

logger = logging.getLogger("androidemu.pm")


class Signature(metaclass=JavaClassDef, jvm_name='android/content/pm/Signature'):
    def __init__(self, sign_hex: str = ""):
        self.__sign_hex = sign_hex

    @java_method_def(name='toByteArray', signature='()[B', native=False)
    def toByteArray(self, emu: 'Emulator') -> ByteArray:
        if self.__sign_hex:
            try:
                bs = bytes.fromhex(self.__sign_hex)
                return ByteArray(bytearray(bs))
            except ValueError:
                pass
        return ByteArray(bytearray(b"\x30\x82\x01\x00"))

    @java_method_def(name='toCharsString', signature='()Ljava/lang/String;', native=False)
    def toCharsString(self, emu: 'Emulator') -> String:
        return String(self.__sign_hex)

    @java_method_def(name='hashCode', signature='()I', native=False)
    def hashCode(self, emu: 'Emulator') -> int:
        if self.__sign_hex:
            import zlib
            return zlib.crc32(self.__sign_hex.encode()) & 0x7FFFFFFF
        return 0


class ApplicationInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/ApplicationInfo', 
                     jvm_fields=[
                         JavaFieldDef('sourceDir', 'Ljava/lang/String;', False),
                         JavaFieldDef('publicSourceDir', 'Ljava/lang/String;', False),
                         JavaFieldDef('dataDir', 'Ljava/lang/String;', False),
                         JavaFieldDef('nativeLibraryDir', 'Ljava/lang/String;', False),
                         JavaFieldDef('flags', 'I', False),
                     ]):
    def __init__(self, pyPkgName: str):
        self.sourceDir = String(f"/data/app/{pyPkgName}-1/base.apk")
        self.publicSourceDir = self.sourceDir
        self.dataDir = String(f"/data/data/{pyPkgName}")
        self.nativeLibraryDir = String(f"/data/data/{pyPkgName}/lib")
        self.flags = 0x30e8bf46


class SigningInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/SigningInfo',
                  jvm_fields=[
                      JavaFieldDef('mSignatures', '[Landroid/content/pm/Signature;', False)
                  ]):
    def __init__(self, signatures: ObjectArray):
        self.mSignatures = signatures

    @java_method_def(name='hasMultipleSigners', signature='()Z', native=False)
    def hasMultipleSigners(self, emu: 'Emulator') -> bool:
        return False

    @java_method_def(name='getApkContentsSigners', signature='()[Landroid/content/pm/Signature;', native=False)
    def getApkContentsSigners(self, emu: 'Emulator') -> ObjectArray:
        return self.mSignatures

    @java_method_def(name='getSigningCertificateHistory', signature='()[Landroid/content/pm/Signature;', native=False)
    def getSigningCertificateHistory(self, emu: 'Emulator') -> ObjectArray:
        return self.mSignatures


class PackageInfo(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageInfo', 
                  jvm_fields=[
                      JavaFieldDef('packageName', 'Ljava/lang/String;', False),
                      JavaFieldDef('applicationInfo', 'Landroid/content/pm/ApplicationInfo;', False),
                      JavaFieldDef('firstInstallTime', 'J', False),
                      JavaFieldDef('lastUpdateTime', 'J', False),
                      JavaFieldDef('signatures', '[Landroid/content/pm/Signature;', False),
                      JavaFieldDef('signingInfo', 'Landroid/content/pm/SigningInfo;', False),
                      JavaFieldDef('versionCode', 'I', False),
                      JavaFieldDef('versionName', 'Ljava/lang/String;', False),
                  ]):
    
    def __init__(self, pyPkgName: str, sign_hex: Optional[str], version_code: int, 
                 version_name: str, first_install_time: int, last_update_time: int):
        
        self.packageName = String(pyPkgName)
        self.applicationInfo = ApplicationInfo(pyPkgName)
        self.versionCode = version_code
        self.versionName = String(version_name)
        self.firstInstallTime = first_install_time
        self.lastUpdateTime = last_update_time

        if sign_hex:
            sig_list = [Signature(sign_hex)]
        else:
            raise AttributeError("Library requested PackageInfo of apk but there is no sign_hex option in config.")

        self.signatures = ObjectArray(sig_list)
        self.signingInfo = SigningInfo(self.signatures)


class PackageManager(metaclass=JavaClassDef, jvm_name='android/content/pm/PackageManager', 
                     jvm_fields=[
                         JavaFieldDef('GET_SIGNATURES', 'I', True, 64),
                         JavaFieldDef('GET_SIGNING_CERTIFICATES', 'I', True, 134217728),
                     ]):
    
    GET_SIGNATURES = 64
    GET_SIGNING_CERTIFICATES = 134217728

    def __init__(self, pyPkgName: str):
        self.__pyPkgName = pyPkgName

    @java_method_def(name='getPackageInfo', args_list=["jstring", "jint"], 
                     signature='(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;', native=False)
    def getPackageInfo(self, emu: 'Emulator', package_name: String, flags: int) -> PackageInfo:
        req_pkg = package_name.get_py_string() if package_name else self.__pyPkgName
        
        pkg_cfg = emu.config.pkg
        
        sign_hex = pkg_cfg.sign_hex
        version_code = pkg_cfg.version_code
        version_name = pkg_cfg.version_name
        first_install = pkg_cfg.first_install_time
        last_update = pkg_cfg.last_update_time

        return PackageInfo(
            pyPkgName=req_pkg,
            sign_hex=sign_hex,
            version_code=version_code,
            version_name=version_name,
            first_install_time=first_install,
            last_update_time=last_update
        )

    @java_method_def(name='checkPermission', args_list=["jstring", "jstring"], 
                     signature='(Ljava/lang/String;Ljava/lang/String;)I', native=False)
    def checkPermission(self, emu: 'Emulator', perm: String, pkg: String) -> int:
        return 0  # PERMISSION_GRANTED