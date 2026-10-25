import logging
import warnings

from typing import TYPE_CHECKING

from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.classes.java.lang.string import String
from androidemu.java.classes.java.lang.array import ByteArray

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator

logger = logging.getLogger("androidemu.crypto")


class Key(metaclass=JavaClassDef, jvm_name='java/security/Key'):
    def __init__(self, raw_encoded: bytes = b"", algorithm: str = "RSA") -> None:
        self.raw_encoded = raw_encoded
        self.algorithm = algorithm

    @java_method_def(name='getAlgorithm', signature='()Ljava/lang/String;', native=False)
    def getAlgorithm(self, emu: 'Emulator') -> 'String':
        return String(self.algorithm)

    @java_method_def(name='getFormat', signature='()Ljava/lang/String;', native=False)
    def getFormat(self, emu: 'Emulator') -> 'String':
        return String("X.509")

    @java_method_def(name='getEncoded', signature='()[B', native=False)
    def getEncoded(self, emu: 'Emulator') -> 'ByteArray':
        return ByteArray(bytearray(self.raw_encoded))


class PublicKey(Key, metaclass=JavaClassDef, jvm_name='java/security/PublicKey', jvm_super=Key):
    def __init__(self, raw_encoded: bytes = b"", algorithm: str = "RSA") -> None:
        super().__init__(raw_encoded=raw_encoded, algorithm=algorithm)

class Certificate(metaclass=JavaClassDef, jvm_name='java/security/cert/Certificate'):
    def __init__(self, raw_data: bytes = b"") -> None:
        self.raw_data = raw_data
        self._public_key = self._extract_public_key(raw_data)

    def _extract_public_key(self, raw_data: bytes) -> 'PublicKey':
        if raw_data:
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                
                cert = x509.load_der_x509_certificate(raw_data)
                pub_key = cert.public_key()
                spki_der = pub_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                logger.info("[Certificate] Extracted real SubjectPublicKeyInfo (%d bytes)", len(spki_der))
                return PublicKey(raw_encoded=spki_der)
            except Exception as e:
                warnings.warn(
                                "Could not initialize public key. "
                                "Next steps of emulation may break logic. "
                                "Install the 'cryptography' module for maximum accuracy.",
                                UserWarning,
                                stacklevel=2
                            )

        return PublicKey(raw_encoded=raw_data[:256] if raw_data else b"\x30\x82\x01\x00")

    @java_method_def(name='getPublicKey', signature='()Ljava/security/PublicKey;', native=False)
    def getPublicKey(self, emu: 'Emulator') -> PublicKey:
        logger.debug("[Certificate] getPublicKey() requested")
        return self._public_key

    @java_method_def(name='getEncoded', signature='()[B', native=False)
    def getEncoded(self, emu: 'Emulator') -> ByteArray:
        return ByteArray(bytearray(self.raw_data))

    @java_method_def(name='getType', signature='()Ljava/lang/String;', native=False)
    def getType(self, emu: 'Emulator') -> String:
        return String("X.509")


class X509Certificate(Certificate, metaclass=JavaClassDef, jvm_name='java/security/cert/X509Certificate', jvm_super=Certificate):
    def __init__(self, raw_data: bytes = b"") -> None:
        super().__init__(raw_data)