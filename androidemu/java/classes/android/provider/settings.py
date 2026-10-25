from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def
from androidemu.java.jvm.constants import JAVA_NULL
from ...java.lang.string import String

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator

logger = logging.getLogger("androidemu.settings")


class _SettingsProviderHelper:
    DEFAULTS: Dict[str, Any] = {
        "adb_enabled": 0,
        "development_settings_enabled": 0,
        "install_non_market_apps": 0,
        "package_verifier_enable": 1,
        "http_proxy": None,
        "accessibility_enabled": 0,
        "mock_location": 0,
        "usb_mass_storage_enabled": 0,
        "data_roaming": 0,
        "device_provisioned": 1,
        "location_mode": 3,  # HIGH_ACCURACY
    }

    @classmethod
    def get_setting_raw(cls, emu: Emulator, key: str) -> Optional[Any]:
        secure_cfg = getattr(emu.config.pkg.device, "secure", None)
        
        if secure_cfg is not None:
            if isinstance(secure_cfg, dict) and key in secure_cfg:
                return secure_cfg[key]
            elif hasattr(secure_cfg, key):
                return getattr(secure_cfg, key)

        if key in cls.DEFAULTS:
            return cls.DEFAULTS[key]

        logger.debug("[SettingsProvider] Query for unconfigured setting: %r (returning None)", key)
        return None

    @classmethod
    def get_as_string(cls, emu: Emulator, key: str) -> Any:
        val = cls.get_setting_raw(emu, key)
        if val is None:
            return JAVA_NULL
        return String(str(val))

    @classmethod
    def get_as_int(cls, emu: Emulator, key: str, default: int) -> int:
        val = cls.get_setting_raw(emu, key)
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    @classmethod
    def get_as_long(cls, emu: Emulator, key: str, default: int) -> int:
        val = cls.get_setting_raw(emu, key)
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    @classmethod
    def get_as_float(cls, emu: Emulator, key: str, default: float) -> float:
        val = cls.get_setting_raw(emu, key)
        if val is None:
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default


class Secure(metaclass=JavaClassDef, jvm_name='android/provider/Settings$Secure',
             jvm_fields=[
                 JavaFieldDef('ANDROID_ID', 'Ljava/lang/String;', True, String("android_id")),
                 JavaFieldDef('ADB_ENABLED', 'Ljava/lang/String;', True, String("adb_enabled")),
                 JavaFieldDef('DEVELOPMENT_SETTINGS_ENABLED', 'Ljava/lang/String;', True, String("development_settings_enabled")),
             ]):

    def __init__(self) -> None:
        pass

    @staticmethod
    @java_method_def(
        name='getString',
        args_list=["jobject", "jstring"],
        signature='(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;',
        native=False
    )
    def getString(emu: Emulator, resolver: Any, name: Optional[String]) -> Any:
        if not name:
            return JAVA_NULL
        return _SettingsProviderHelper.get_as_string(emu, name.get_py_string())

    @staticmethod
    @java_method_def(
        name='getInt',
        args_list=["jobject", "jstring", "jint"],
        signature='(Landroid/content/ContentResolver;Ljava/lang/String;I)I',
        native=False
    )
    def getIntWithDefault(emu: Emulator, resolver: Any, name: Optional[String], default: int) -> int:
        if not name:
            return default
        return _SettingsProviderHelper.get_as_int(emu, name.get_py_string(), default)

    @staticmethod
    @java_method_def(
        name='getInt',
        args_list=["jobject", "jstring"],
        signature='(Landroid/content/ContentResolver;Ljava/lang/String;)I',
        native=False
    )
    def getInt(emu: Emulator, resolver: Any, name: Optional[String]) -> int:
        return Secure.getIntWithDefault(emu, resolver, name, 0)

    @staticmethod
    @java_method_def(
        name='getLong',
        args_list=["jobject", "jstring", "jlong"],
        signature='(Landroid/content/ContentResolver;Ljava/lang/String;J)J',
        native=False
    )
    def getLongWithDefault(emu: Emulator, resolver: Any, name: Optional[String], default: int) -> int:
        if not name:
            return default
        return _SettingsProviderHelper.get_as_long(emu, name.get_py_string(), default)

    @staticmethod
    @java_method_def(
        name='getLong',
        args_list=["jobject", "jstring"],
        signature='(Landroid/content/ContentResolver;Ljava/lang/String;)J',
        native=False
    )
    def getLong(emu: Emulator, resolver: Any, name: Optional[String]) -> int:
        return Secure.getLongWithDefault(emu, resolver, name, 0)

    @staticmethod
    @java_method_def(
        name='getFloat',
        args_list=["jobject", "jstring", "jfloat"],
        signature='(Landroid/content/ContentResolver;Ljava/lang/String;F)F',
        native=False
    )
    def getFloatWithDefault(emu: Emulator, resolver: Any, name: Optional[String], default: float) -> float:
        if not name:
            return default
        return _SettingsProviderHelper.get_as_float(emu, name.get_py_string(), default)


class Global(metaclass=JavaClassDef, jvm_name='android/provider/Settings$Global',
             jvm_fields=[
                 JavaFieldDef('ADB_ENABLED', 'Ljava/lang/String;', True, String("adb_enabled")),
                 JavaFieldDef('DEVELOPMENT_SETTINGS_ENABLED', 'Ljava/lang/String;', True, String("development_settings_enabled")),
                 JavaFieldDef('DEVICE_PROVISIONED', 'Ljava/lang/String;', True, String("device_provisioned")),
                 JavaFieldDef('HTTP_PROXY', 'Ljava/lang/String;', True, String("http_proxy")),
             ]):
    def __init__(self) -> None:
        pass

    @staticmethod
    @java_method_def(name='getString', args_list=["jobject", "jstring"], signature='(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getString(emu: Emulator, resolver: Any, name: Optional[String]) -> Any:
        return Secure.getString(emu, resolver, name)

    @staticmethod
    @java_method_def(name='getInt', args_list=["jobject", "jstring", "jint"], signature='(Landroid/content/ContentResolver;Ljava/lang/String;I)I', native=False)
    def getIntWithDefault(emu: Emulator, resolver: Any, name: Optional[String], default: int) -> int:
        return Secure.getIntWithDefault(emu, resolver, name, default)

    @staticmethod
    @java_method_def(name='getInt', args_list=["jobject", "jstring"], signature='(Landroid/content/ContentResolver;Ljava/lang/String;)I', native=False)
    def getInt(emu: Emulator, resolver: Any, name: Optional[String]) -> int:
        return Secure.getInt(emu, resolver, name)


class System(metaclass=JavaClassDef, jvm_name='android/provider/Settings$System'):

    def __init__(self) -> None:
        pass

    @staticmethod
    @java_method_def(name='getString', args_list=["jobject", "jstring"], signature='(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getString(emu: Emulator, resolver: Any, name: Optional[String]) -> Any:
        return Secure.getString(emu, resolver, name)

    @staticmethod
    @java_method_def(name='getInt', args_list=["jobject", "jstring", "jint"], signature='(Landroid/content/ContentResolver;Ljava/lang/String;I)I', native=False)
    def getIntWithDefault(emu: Emulator, resolver: Any, name: Optional[String], default: int) -> int:
        return Secure.getIntWithDefault(emu, resolver, name, default)


class Settings(metaclass=JavaClassDef, jvm_name='android/provider/Settings'):
    def __init__(self) -> None:
        pass