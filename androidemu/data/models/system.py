from dataclasses import dataclass, field
import random


@dataclass
class BatteryInfo:
    level: int = 85
    temperature: int = 295  # 29.5 C
    status: int = 2         # 2 = Charging, 3 = Discharging
    plugged: int = 1        # 1 = AC, 2 = USB
    voltage: int = 4120     # mV
    present: bool = True
    health: int = 2         # 2 = Good


@dataclass
class TelephonyInfo:
    imei: str = "864234041234567"
    imsi: str = "250011234567890"
    phone_number: str = "+79991112233"
    sim_operator: str = "25001"
    sim_operator_name: str = "MegaFon"
    network_operator: str = "25001"
    network_operator_name: str = "MegaFon"
    country_iso: str = "ru"
    network_type: int = 13  # 13 = LTE


@dataclass
class BuildInfo:
    brand: str = "Xiaomi"
    manufacturer: str = "Xiaomi"
    model: str = "M2007J3SG"
    device: str = "apollo"
    product: str = "apollo_eea"
    board: str = "kona"
    hardware: str = "qcom"
    bootloader: str = "unknown"
    fingerprint: str = "Xiaomi/apollo_eea/apollo:11/RKQ1.200826.002/V12.5.3.0.RJDEUXM:user/release-keys"
    
    sdk_int: int = 30
    release: str = "11"
    security_patch: str = "2021-06-01"
    abi: str = "arm64-v8a"
    supported_abis: list = field(default_factory=lambda: ["arm64-v8a", "armeabi-v7a", "armeabi"])


@dataclass
class SettingsSecure:
    android_id: str = field(default_factory=lambda: ''.join(random.choice('0123456789abcdef') for _ in range(16)))
    gaid: str = "550e8400-e29b-41d4-a716-446655440000"  # Google Advertising ID
    development_settings_enabled: int = 0
    adb_enabled: int = 0