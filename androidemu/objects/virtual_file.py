import os
import logging

from typing import TYPE_CHECKING

from ..const.linux import *

from ..utils import misc_utils

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
        self.symlink_target: str = None
        
        self.__buffer = bytearray()

        if is_virtual:
            from ..utils.generators.vfs_content import ContentGenerator
            self.__content_generator = ContentGenerator(emulator)
    
    @staticmethod
    def open(emulator: 'Emulator', filename: str, file_path: str, flags: int,  is_virtual: bool = False):
        if is_virtual:
            guest_fd = emulator.pcb.virtual_files.add_virtual_fd(filename, file_path)
            logging.debug("open virtual [%s] GuestFD:%d", filename, guest_fd)
            return guest_fd
        
        original_flags = flags
        access_mode = original_flags & 3
        real_flags = {0: os.O_RDONLY, 1: os.O_WRONLY, 2: os.O_RDWR}.get(access_mode, os.O_RDONLY)

        if (original_flags & 0o100):      real_flags |= os.O_CREAT
        if (original_flags & 0o2000):     real_flags |= os.O_APPEND
        if (original_flags & 0o40000):    real_flags |= getattr(os, 'O_DIRECTORY', 0)
        if (original_flags & 0o10000000): real_flags |= getattr(os, 'O_PATH', 0)

        try:
            host_fd = misc_utils.my_open(file_path, real_flags)
        except PermissionError:
            return -EISDIR if os.path.isdir(file_path) else -EACCES
        except FileNotFoundError:
            return -ENOENT
        
        guest_fd = emulator.pcb.virtual_files.add_fd(filename, file_path, host_fd)
        logging.debug("open [%s] HostFD:%d -> GuestFD:%d", filename, host_fd, guest_fd)

        return guest_fd

    def read(self, buf_addr, count):
        try:
            if self.is_virtual:
                if len(self.__buffer) > 0:
                    data = self.__buffer[self.offset : self.offset + count]
                    self.offset += len(data)
                else:
                    content = self.__content_generator.generate(
                        self.name, fd=self.descriptor, count=count
                    )
                    data = content.encode('utf-8') if isinstance(content, str) else (content if isinstance(content, bytes) else b'')
                    data = data[self.offset : self.offset + count]
                    self.offset += len(data)
            else:
                if not os.isatty(self.descriptor):
                    try:
                        os.lseek(self.descriptor, self.offset, os.SEEK_SET)
                    except OSError:
                        pass
                
                data = os.read(self.descriptor, count)
                self.offset += len(data)

            actual_size = len(data)
            if actual_size > 0:
                self.__emulator.mu.mem_write(buf_addr, data)

            return actual_size

        except Exception as e:
            logging.error("Read error on fd %d (%s): %s", self.descriptor, self.name, e)
            return -EPERM
        
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
            if not os.isatty(self.descriptor):
                try:
                    os.lseek(self.descriptor, self.offset, os.SEEK_SET)
                except OSError:
                    pass
            
            r = os.write(self.descriptor, data)
            if r != -1:
                self.offset += r
        except OSError as e:
            logging.warning("Write error on fd %d (%s): %s", self.descriptor, self.name, e)
            return -EPERM
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