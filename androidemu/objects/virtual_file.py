import os
import logging

from typing import TYPE_CHECKING

from .vdstat import VirtualDeviceStat

if TYPE_CHECKING:
    from ..emulator import Emulator

logging.getLogger(__name__)

class VirtualFile:
    def __init__(self, emulator: 'Emulator', name, host_fd, name_in_system, is_virtual=False):
        self.__emulator: 'Emulator' = emulator

        self.offset: int = 0
        self.ref_count = 1 

        self.name: str = name
        self.name_in_system: str = name_in_system
        self.descriptor: int = host_fd 
        
        self.is_virtual: bool = is_virtual

        self.__buffer = bytearray()

        if is_virtual:
            from ..utils.generators.vfs_content import ContentGenerator
            self.__content_generator = ContentGenerator(emulator)

    def read(self, buf_addr, count):
        try:
            if self.is_virtual:
                if len(self.__buffer) > 0:
                    data = self.__buffer[self.offset : self.offset + count]
                    self.offset += len(data)
                
                else:
                    _, content = self.__content_generator.prepare_path(
                        self.name, self.name_in_system, fd=self.descriptor, count=count
                    )
                    if isinstance(content, str): data = content.encode('utf-8')
                    elif isinstance(content, bytes): data = content
                    else: data = b''
                    
                    data = data[self.offset : self.offset + count]
                    self.offset += len(data)
            else:
                os.lseek(self.descriptor, self.offset, os.SEEK_SET)
                data = os.read(self.descriptor, count)
                self.offset += len(data)

            readable_data = data
            actual_size = len(readable_data)

            if actual_size > 0:
                self.__emulator.mu.mem_write(buf_addr, readable_data)

            return actual_size

        except Exception as e:
            logging.error("Read error on fd %d (%s): %s", self.descriptor, self.name, e)
            return -1
        
    def write(self, data):
        if self.is_virtual:
            end_pos = self.offset + len(data)
            if end_pos > len(self.__buffer):
                self.__buffer.extend(b'\x00' * (end_pos - len(self.__buffer)))
            
            self.__buffer[self.offset:end_pos] = data
            self.offset += len(data)
            
            logging.debug("VFS: Virtual write to %s, size %d, new total size %d", 
                          self.name, len(data), len(self.__buffer))
            return len(data)
            
        try:
            os.lseek(self.descriptor, self.offset, os.SEEK_SET)
            r = os.write(self.descriptor, data)
            if r != -1:
                self.offset += r
        except OSError as e:
            logging.warning("Write error on fd %d (%s): %s", self.descriptor, self.name, e)
            return -1
        return r
    
    def close(self):
        self.ref_count -= 1
        if self.ref_count <= 0:
            if not self.is_virtual and self.descriptor > 2:
                try:
                    os.close(self.descriptor)
                    logging.debug("VFS: Physically closed host FD %d", self.descriptor)
                except OSError:
                    pass
            return True
        return False

    def seek(self, offset, whence):
        if whence == 0: # SEEK_SET
            self.offset = offset
        elif whence == 1: # SEEK_CUR
            self.offset += offset
        elif whence == 2: # SEEK_END
            size = len(self.__buffer)
            self.offset = size + offset
        return self.offset
    
    def get_size(self):
        if self.is_virtual:
            return len(self.__buffer)
        else:
            return os.fstat(self.descriptor).st_size