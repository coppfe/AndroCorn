from dataclasses import dataclass, field
from typing import List


@dataclass
class CPUInfo:
    cores: int = 8
    arch: str = "aarch64"
    implementer: int = 0x51
    architecture: int = 8
    variant: int = 0x2
    part: int = 0x205
    revision: int = 1
    bogomips: float = 38.40
    hardware: str = "qcom"
    features: List[str] = field(
        default_factory=lambda: ["fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32"]
    )


@dataclass
class GPUInfo:
    vendor: str = "Qualcomm"
    renderer: str = "Adreno (TM) 640"
    version: str = "OpenGL ES 3.2 V@0490.0 (GIT@83bb17b, I66dc9c0d38) (Date:12/26/20)"
    gl_extensions: List[str] = field(default_factory=lambda: [
        "GL_OES_EGL_image", "GL_OES_depth24", "GL_ARM_rgba8"
    ])