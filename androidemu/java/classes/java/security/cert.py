from __future__ import annotations

import warnings
import logging
from typing import TYPE_CHECKING, Any, Optional

from androidemu.java.class_def import JavaClassDef
from androidemu.java.method_def import java_method_def
from androidemu.java.jvm.constants import JAVA_NULL
from ..lang.object import Object
from ..lang.string import String
from ..lang.array import ByteArray

if TYPE_CHECKING:
    from androidemu.core.emulator import Emulator

logger = logging.getLogger("androidemu.cert")

class Principal(Object, metaclass=JavaClassDef, jvm_name='java/security/Principal', jvm_super=Object):

    def __init__(self, name: str = "") -> None:
        super().__init__()
        self.principal_name: str = name

    @java_method_def(name='getName', signature='()Ljava/lang/String;', native=False)
    def getName(self, emu: Emulator) -> String:
        return String(self.principal_name)

    @java_method_def(name='toString', signature='()Ljava/lang/String;', native=False)
    def toString(self, emu: Emulator) -> String:
        return String(self.principal_name)


class X500Principal(Principal, metaclass=JavaClassDef, jvm_name='javax/security/auth/x500/X500Principal', jvm_super=Principal):

    def __init__(self, name: str = "", encoded_der: bytes = b"") -> None:
        super().__init__(name=name)
        self.encoded_der: bytes = encoded_der

    @java_method_def(name='<init>', args_list=["jstring"], signature='(Ljava/lang/String;)V', native=False)
    def ctor_str(self, emu: Emulator, name_str: String) -> None:
        self.principal_name = name_str.get_py_string() if name_str else ""
        self.encoded_der = self.principal_name.encode("utf-8")

    @java_method_def(name='<init>', args_list=["jobject"], signature='([B)V', native=False)
    def ctor_bytes(self, emu: Emulator, b_arr: ByteArray) -> None:
        if b_arr and b_arr != JAVA_NULL:
            self.encoded_der = bytes(b_arr.get_py_items())
            self.principal_name = self.encoded_der.decode("utf-8", errors="ignore")
        else:
            self.encoded_der = b""
            self.principal_name = ""

    @java_method_def(name='getEncoded', signature='()[B', native=False)
    def getEncoded(self, emu: Emulator) -> ByteArray:
        return ByteArray(bytearray(self.encoded_der))

    @java_method_def(name='getName', args_list=["jstring"], signature='(Ljava/lang/String;)Ljava/lang/String;', native=False)
    def getNameFormat(self, emu: Emulator, format_str: String) -> String:
        # RFC1779, RFC2253 or CANONICAL
        return String(self.principal_name)


class Key(Object, metaclass=JavaClassDef, jvm_name='java/security/Key', jvm_super=Object):

    def __init__(self, raw_encoded: bytes = b"", algorithm: str = "RSA") -> None:
        super().__init__()
        self.raw_encoded: bytes = raw_encoded
        self.algorithm: str = algorithm

    @java_method_def(name='getAlgorithm', signature='()Ljava/lang/String;', native=False)
    def getAlgorithm(self, emu: Emulator) -> String:
        return String(self.algorithm)

    @java_method_def(name='getFormat', signature='()Ljava/lang/String;', native=False)
    def getFormat(self, emu: Emulator) -> String:
        return String("X.509")

    @java_method_def(name='getEncoded', signature='()[B', native=False)
    def getEncoded(self, emu: Emulator) -> ByteArray:
        return ByteArray(bytearray(self.raw_encoded))


class PublicKey(Key, metaclass=JavaClassDef, jvm_name='java/security/PublicKey', jvm_super=Key):

    def __init__(self, raw_encoded: bytes = b"", algorithm: str = "RSA") -> None:
        super().__init__(raw_encoded=raw_encoded, algorithm=algorithm)


class Certificate(Object, metaclass=JavaClassDef, jvm_name='java/security/cert/Certificate', jvm_super=Object):

    def __init__(self, raw_data: bytes = b"") -> None:
        super().__init__()
        self.raw_data: bytes = raw_data
        self._parsed_cert = None
        self._public_key: Optional[PublicKey] = None
        
        if self.raw_data:
            self._init_crypto_metadata()

    def _init_crypto_metadata(self) -> None:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            self._parsed_cert = x509.load_der_x509_certificate(self.raw_data)
            pub_key = self._parsed_cert.public_key()
            spki_der = pub_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            key_name = pub_key.__class__.__name__
            if "RSA" in key_name:
                algo = "RSA"
            elif "EllipticCurve" in key_name or "EC" in key_name:
                algo = "EC"
            elif "DSA" in key_name:
                algo = "DSA"
            else:
                algo = "RSA"

            logger.info("[Certificate] Successfully parsed X.509. Key: %s, SPKI: %d bytes", algo, len(spki_der))
            self._public_key = PublicKey(raw_encoded=spki_der, algorithm=algo)

        except Exception as err:
            # logger.debug("[Certificate] Fallback parser triggered: %s", err)
            warnings.warn(
                "Could not initialize cryptography metadata. "
                "Next steps of emulation may break logic. "
                "Install the 'cryptography' module for maximum accuracy.",
                UserWarning,
                stacklevel=2
            )
            self._public_key = PublicKey(raw_encoded=self.raw_data[:256] if self.raw_data else b"", algorithm="RSA")

    @java_method_def(name='getPublicKey', signature='()Ljava/security/PublicKey;', native=False)
    def getPublicKey(self, emu: Emulator) -> Any:
        if self._public_key is None:
            self._init_crypto_metadata()
        return self._public_key if self._public_key is not None else JAVA_NULL

    @java_method_def(name='getEncoded', signature='()[B', native=False)
    def getEncoded(self, emu: Emulator) -> ByteArray:
        return ByteArray(bytearray(self.raw_data))

    @java_method_def(name='getType', signature='()Ljava/lang/String;', native=False)
    def getType(self, emu: Emulator) -> String:
        return String("X.509")


class X509Certificate(Certificate, metaclass=JavaClassDef, jvm_name='java/security/cert/X509Certificate', jvm_super=Certificate):

    def __init__(self, raw_data: bytes = b"") -> None:
        super().__init__(raw_data=raw_data)
        self._subject_principal: Optional[Principal] = None
        self._issuer_principal: Optional[Principal] = None
        self._subject_x500: Optional[X500Principal] = None
        self._issuer_x500: Optional[X500Principal] = None
        self._serial_bytes: bytes = b"\x01"

        if self.raw_data:
            self._init_x509_fields()

    def _init_x509_fields(self) -> None:
        sub_str = "CN=Unknown"
        iss_str = "CN=Unknown"
        sub_der = b""
        iss_der = b""

        if self._parsed_cert is not None:
            try:
                sub_str = self._parsed_cert.subject.rfc4514_string()
                iss_str = self._parsed_cert.issuer.rfc4514_string()
                sub_der = self._parsed_cert.subject.public_bytes()
                iss_der = self._parsed_cert.issuer.public_bytes()
                self._serial_bytes = self._parsed_cert.serial_number.to_bytes(
                    (self._parsed_cert.serial_number.bit_length() + 7) // 8, 
                    byteorder="big"
                )
            except Exception as e:
                logger.debug("[X509Certificate] Metadata extraction warning: %s", e)

        self._subject_principal = Principal(sub_str)
        self._issuer_principal = Principal(iss_str)
        self._subject_x500 = X500Principal(name=sub_str, encoded_der=sub_der)
        self._issuer_x500 = X500Principal(name=iss_str, encoded_der=iss_der)

    def _ensure_initialized(self) -> None:
        if self._subject_principal is None:
            self._init_x509_fields()

    @java_method_def(name='getSubjectDN', signature='()Ljava/security/Principal;', native=False)
    def getSubjectDN(self, emu: Emulator) -> Any:
        self._ensure_initialized()
        return self._subject_principal if self._subject_principal is not None else JAVA_NULL

    @java_method_def(name='getIssuerDN', signature='()Ljava/security/Principal;', native=False)
    def getIssuerDN(self, emu: Emulator) -> Any:
        self._ensure_initialized()
        return self._issuer_principal if self._issuer_principal is not None else JAVA_NULL

    @java_method_def(name='getSubjectX500Principal', signature='()Ljavax/security/auth/x500/X500Principal;', native=False)
    def getSubjectX500Principal(self, emu: Emulator) -> Any:
        self._ensure_initialized()
        return self._subject_x500 if self._subject_x500 is not None else JAVA_NULL

    @java_method_def(name='getIssuerX500Principal', signature='()Ljavax/security/auth/x500/X500Principal;', native=False)
    def getIssuerX500Principal(self, emu: Emulator) -> Any:
        self._ensure_initialized()
        return self._issuer_x500 if self._issuer_x500 is not None else JAVA_NULL

    @java_method_def(name='checkValidity', signature='()V', native=False)
    def checkValidity(self, emu: Emulator) -> None:
        pass # Raising error in real android but... we not real android
             # TODO

    @java_method_def(name='getSigAlgName', signature='()Ljava/lang/String;', native=False)
    def getSigAlgName(self, emu: Emulator) -> String:
        return String("SHA256withRSA")

class CertificateFactory(Object, metaclass=JavaClassDef, jvm_name='java/security/cert/CertificateFactory', jvm_super=Object):

    def __init__(self, cert_type: str = "X.509") -> None:
        super().__init__()
        self.cert_type: str = cert_type

    @staticmethod
    @java_method_def(
        name='getInstance',
        args_list=["jstring"],
        signature='(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;',
        native=False
    )
    def getInstance(emu: Emulator, type_str: String) -> CertificateFactory:
        py_type = type_str.get_py_string() if type_str else "X.509"
        logger.debug("[CertificateFactory] getInstance(%s)", py_type)
        return CertificateFactory(cert_type=py_type)

    @java_method_def(
        name='generateCertificate',
        args_list=["jobject"],
        signature='(Ljava/io/InputStream;)Ljava/security/cert/Certificate;',
        native=False
    )
    def generateCertificate(self, emu: Emulator, input_stream: Any) -> Any:
        raw_bytes = b""
        
        if input_stream and input_stream != JAVA_NULL:
            if hasattr(input_stream, "_buf"):
                raw_bytes = bytes(input_stream._buf)
            elif hasattr(input_stream, "read_buf"):
                buf = bytearray()
                while True:
                    b = input_stream.read_one(emu)
                    if b == -1:
                        break
                    buf.append(b)
                raw_bytes = bytes(buf)

        if not raw_bytes:
            logger.warning("[CertificateFactory] generateCertificate received empty stream!")
            return JAVA_NULL

        logger.info("[CertificateFactory] Materialized X.509 Certificate (%d bytes)", len(raw_bytes))
        return X509Certificate(raw_data=raw_bytes)

class KeyStore(Object, metaclass=JavaClassDef, jvm_name='java/security/KeyStore', jvm_super=Object):
    def __init__(self, store_type: str = "BKS") -> None:
        super().__init__()
        self.store_type: str = store_type
        self.entries: dict[str, Certificate] = {}

    @staticmethod
    @java_method_def(
        name='getInstance',
        args_list=["jstring"],
        signature='(Ljava/lang/String;)Ljava/security/KeyStore;',
        native=False
    )
    def getInstance(emu: Emulator, type_str: String) -> KeyStore:
        py_type = type_str.get_py_string() if type_str else "BKS"
        logger.debug("[KeyStore] getInstance(%s)", py_type)
        return KeyStore(store_type=py_type)

    @java_method_def(
        name='load',
        args_list=["jobject", "jobject"],
        signature='(Ljava/io/InputStream;[C)V',
        native=False
    )
    def load(self, emu: Emulator, stream: Any, password: Any) -> None:
        logger.debug("[KeyStore] load() called successfully")

    @java_method_def(
        name='setCertificateEntry',
        args_list=["jstring", "jobject"],
        signature='(Ljava/lang/String;Ljava/security/cert/Certificate;)V',
        native=False
    )
    def setCertificateEntry(self, emu: Emulator, alias: String, cert: Certificate) -> None:
        alias_str = alias.get_py_string() if alias and alias != JAVA_NULL else "default"
        logger.info("[KeyStore] Registered cert entry for alias '%s'", alias_str)
        self.entries[alias_str] = cert

    @java_method_def(
        name='getCertificate',
        args_list=["jstring"],
        signature='(Ljava/lang/String;)Ljava/security/cert/Certificate;',
        native=False
    )
    def getCertificate(self, emu: Emulator, alias: String) -> Any:
        alias_str = alias.get_py_string() if alias and alias != JAVA_NULL else "default"
        return self.entries.get(alias_str, JAVA_NULL)