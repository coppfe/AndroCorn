from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def
from ...java.io.file import FileDescriptor
from ...java.lang.array import Array
from androidemu.kernel.fs.nodes.devices import VirtualPipe, PipeReadNode, PipeWriteNode

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu import Emulator

class ParcelFileDescriptorArray(Array, metaclass=JavaClassDef, jvm_name="[Landroid/os/ParcelFileDescriptor;", jvm_super=Array):
    def __init__(self, item_list):
        super().__init__(item_list)


class ParcelFileDescriptor(metaclass=JavaClassDef, jvm_name='android/os/ParcelFileDescriptor',
                           jvm_fields=[
                               JavaFieldDef('mFd', 'Ljava/io/FileDescriptor;', False),
                           ]):
    def __init__(self, fd: int = -1):
        self.mFd = FileDescriptor(fd)

    @java_method_def(name='<init>', args_list=['jobject'], signature='(Ljava/io/FileDescriptor;)V', native=False)
    def init_fd(self, emu, fd_obj):
        self.mFd = fd_obj

    @staticmethod
    @java_method_def(
        name='createPipe',
        signature='()[Landroid/os/ParcelFileDescriptor;',
        native=False
    )
    def createPipe(emu: 'Emulator'):
        pipe = VirtualPipe()
        fd_read = emu.vfs.create_fd_for_node(PipeReadNode(pipe))
        fd_write = emu.vfs.create_fd_for_node(PipeWriteNode(pipe))

        pfd_read = ParcelFileDescriptor(fd_read)
        pfd_write = ParcelFileDescriptor(fd_write)

        return ParcelFileDescriptorArray([pfd_read, pfd_write])

    @staticmethod
    @java_method_def(
        name='createReliablePipe',
        signature='()[Landroid/os/ParcelFileDescriptor;',
        native=False
    )
    def createReliablePipe(emu):
        return ParcelFileDescriptor.createPipe(emu)

    @java_method_def(name='getFd', signature='()I', native=False)
    def getFd(self, emu):
        return self.mFd.descriptor if self.mFd else -1

    @java_method_def(name='getFileDescriptor', signature='()Ljava/io/FileDescriptor;', native=False)
    def getFileDescriptor(self, emu):
        return self.mFd

    @staticmethod
    @java_method_def(name='fromFd', args_list=['jint'], signature='(I)Landroid/os/ParcelFileDescriptor;', native=False)
    def fromFd(emu, fd: int):
        return ParcelFileDescriptor(fd)

    @staticmethod
    @java_method_def(name='adoptFd', args_list=['jint'], signature='(I)Landroid/os/ParcelFileDescriptor;', native=False)
    def adoptFd(emu, fd: int):
        return ParcelFileDescriptor(fd)

    @java_method_def(name='detachFd', signature='()I', native=False)
    def detachFd(self, emu):
        fd = self.mFd.descriptor if self.mFd else -1
        if self.mFd:
            self.mFd.descriptor = -1
        return fd

    @java_method_def(name='close', signature='()V', native=False)
    def close(self, emu):
        if self.mFd:
            self.mFd.descriptor = -1