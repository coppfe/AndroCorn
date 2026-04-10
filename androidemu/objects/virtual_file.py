import os
import logging

from typing import TYPE_CHECKING

from ..utils.generators.vfs_content import ContentGenerator

if TYPE_CHECKING:
    from ..emulator import Emulator

logging.getLogger(__name__)

class VirtualFile:

    def __init__(self, emulator: 'Emulator', name, file_descriptor, name_in_system, is_virtual = False):
        self.name: str = name
        self.name_in_system: str = name_in_system
        self.descriptor: int = file_descriptor
        self.is_virtual: bool = is_virtual

        self.offset: int = 0

        self.__emulator: 'Emulator' = emulator

        if is_virtual:
            self.__content_generator: 'ContentGenerator' = ContentGenerator(emulator)

    def read(self, buf_addr, count):
        try:
            if self.is_virtual:
                _, content = self.__content_generator.prepare_path(self.name, self.name_in_system, fd=self.descriptor, count=count)
                if isinstance(content, str):
                    data = content.encode('utf-8')
                elif isinstance(content, bytes):
                    data = content
                elif isinstance(content, list):
                    data = b''.join(content)
                else:
                    data = b''
            else:
                data = os.read(self.descriptor, count)

            readable_data = data[:count]
            actual_size = len(readable_data)

            if actual_size > 0:
                self.__emulator.mu.mem_write(buf_addr, readable_data)

            return actual_size

        except (OSError, TypeError, ValueError) as e:
            logging.error("Read error on fd %d (%s): %s", self.descriptor, self.name, e)
            return -1
        
    def write(self, data):
        if self.is_virtual:
            return len(data)
        try:
            r = os.write(self.descriptor, data)
        except OSError as e:
            logging.warning(f"Write error on fd {self.descriptor} ({self.name}): {e}")
            return -1
        return r