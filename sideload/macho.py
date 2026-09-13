# sideload/macho.py
"""
Port từ sideload/macho.d — Mach-O parsing + fat binary.
"""

import struct
import enum
from typing import List, Optional

from sideload.codesign import EmbeddedSignature


# ===========================================================================
# Constants (Mach-O)
# ===========================================================================
LC_SEGMENT         = 0x1
LC_SEGMENT_64      = 0x19
LC_CODE_SIGNATURE  = 0x1d

MH_MAGIC    = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf
MH_EXECUTE  = 0x2

FAT_MAGIC    = 0xcafebabe
FAT_CIGAM    = 0xbebafeca
FAT_MAGIC_64 = 0xcafebabf
FAT_CIGAM_64 = 0xbfbafeca

CPU_ARCH_ABI64   = 0x1000000
CPU_TYPE_X86     = 7
CPU_TYPE_X86_64  = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_ARM     = 12
CPU_TYPE_ARM64   = CPU_TYPE_ARM | CPU_ARCH_ABI64
CPU_TYPE_POWERPC = 18

PAGE_SIZE_LOG2 = 14
PAGE_SIZE      = 1 << PAGE_SIZE_LOG2  # 16384

MACH_HEADER_64_SIZE        = 32
MACH_HEADER_SIZE           = 28
LINKEDIT_DATA_COMMAND_SIZE = 16
FAT_HEADER_SIZE            = 8
FAT_ARCH_SIZE              = 20


# ===========================================================================
# Helpers
# ===========================================================================
def page_ceil(val: int) -> int:
    return (val + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def page_floor(val: int) -> int:
    return val & ~(PAGE_SIZE - 1)


# ===========================================================================
# Architecture
# ===========================================================================
class Architecture(enum.IntEnum):
    all     = 0
    armv7   = CPU_TYPE_ARM
    aarch64 = CPU_TYPE_ARM64
    x86_64  = CPU_TYPE_X86_64


# ===========================================================================
# Exceptions
# ===========================================================================
class InvalidMachOException(Exception):
    def __init__(self, issue: str):
        super().__init__(f"The executable cannot be loaded: {issue}")


class SegmentAllocationFailedException(Exception):
    def __init__(self):
        super().__init__("Cannot allocate a code signature segment in the binary")


# ===========================================================================
# MachO
# ===========================================================================
class MachO:
    def __init__(self, data, headersize, cputype, cpusubtype,
                 ncmds, sizeofcmds, filetype, flags=0):
        self.headersize  = headersize
        self.cputype     = cputype
        self.cpusubtype  = cpusubtype
        self.ncmds       = ncmds
        self.sizeofcmds  = sizeofcmds
        self.filetype    = filetype
        self.flags       = flags

        self.data     = bytearray(data)
        self.commands: List[int] = []

        self.exec_seg_base    = 0
        self.exec_seg_limit   = 0
        self.linkedit_command: Optional[int] = None

        loc = headersize
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, loc)

            if cmd == LC_SEGMENT_64:
                segname = bytes(self.data[loc + 8: loc + 24]).rstrip(b"\x00")
                # segment_command_64: fileoff tại +40, filesize tại +48
                fileoff, filesize = struct.unpack_from("<QQ", self.data, loc + 40)
                if segname.startswith(b"__TEXT"):
                    self.exec_seg_base  = fileoff
                    self.exec_seg_limit = fileoff + filesize
                elif segname.startswith(b"__LINKEDIT"):
                    self.linkedit_command = loc

            elif cmd == LC_SEGMENT:
                segname = bytes(self.data[loc + 8: loc + 24]).rstrip(b"\x00")
                # segment_command: fileoff tại +32, filesize tại +36
                fileoff, filesize = struct.unpack_from("<II", self.data, loc + 32)
                if segname.startswith(b"__TEXT"):
                    self.exec_seg_base  = fileoff
                    self.exec_seg_limit = fileoff + filesize
                elif segname.startswith(b"__LINKEDIT"):
                    self.linkedit_command = loc

            self.commands.append(loc)
            loc += cmdsize

    # -----------------------------------------------------------------------
    @staticmethod
    def parse(data: bytes, arch: Architecture = Architecture.all) -> List["MachO"]:
        magic = struct.unpack_from("<I", data, 0)[0]

        if magic == FAT_CIGAM:
            nfat_arch = struct.unpack_from(">I", data, 4)[0]
            fat_archs = []
            for i in range(nfat_arch):
                off = FAT_HEADER_SIZE + i * FAT_ARCH_SIZE
                cputype, cpusubtype, foff, fsize, align_ = struct.unpack_from(
                    ">iiIII", data, off
                )
                fat_archs.append((cputype, cpusubtype, foff, fsize, align_))

            machos: List[MachO] = []
            for cputype, _, foff, fsize, _ in fat_archs:
                sub = MachO.parse(data[foff: foff + fsize])
                if arch != Architecture.all and sub[0].cputype == arch:
                    return sub
                if arch == Architecture.all:
                    machos.extend(sub)

            if arch != Architecture.all:
                raise InvalidMachOException(
                    f"Right architecture not found ({arch.name} wanted)"
                )
            return machos

        elif magic == MH_MAGIC_64:
            # mach_header_64:
            #   magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
            (_, cputype, cpusubtype, filetype, ncmds, sizeofcmds,
             flags, _reserved) = struct.unpack_from("<IiiIIIII", data, 0)

            if arch != Architecture.all and cputype != arch:
                raise InvalidMachOException(
                    f"Not in the right architecture "
                    f"({arch.name} wanted, got {cputype:#x})"
                )
            return [MachO(data, MACH_HEADER_64_SIZE, cputype, cpusubtype,
                          ncmds, sizeofcmds, filetype, flags)]

        elif magic == MH_MAGIC:
            # mach_header:
            #   magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
            (_, cputype, cpusubtype, filetype, ncmds, sizeofcmds,
             flags) = struct.unpack_from("<IiiIIII", data, 0)

            if arch != Architecture.all and cputype != arch:
                raise InvalidMachOException(
                    f"Not in the right architecture "
                    f"({arch.name} wanted, got {cputype:#x})"
                )
            return [MachO(data, MACH_HEADER_SIZE, cputype, cpusubtype,
                          ncmds, sizeofcmds, filetype, flags)]

        raise InvalidMachOException(f"magic: {magic:x}")

    # -----------------------------------------------------------------------
    def exec_flags(self, entitlements: dict) -> int:
        flags = _compute_entitlements_exec_seg_flags(entitlements)
        if self.filetype == MH_EXECUTE:
            flags |= CS_EXECSEG_MAIN_BINARY
        return flags

    # -----------------------------------------------------------------------
    def code_signature_offset(self) -> int:
        for loc in self.commands:
            cmd, _ = struct.unpack_from("<II", self.data, loc)
            if cmd == LC_CODE_SIGNATURE:
                dataoff, _ = struct.unpack_from("<II", self.data, loc + 8)
                return dataoff
        return len(self.data)

    # -----------------------------------------------------------------------
    def replace_code_signature(self, sig) -> bool:
        if isinstance(sig, EmbeddedSignature):
            sig = sig.encode()

        section_size = page_ceil(len(sig))

        code_sig_loc = None
        for loc in self.commands:
            cmd, _ = struct.unpack_from("<II", self.data, loc)
            if cmd == LC_CODE_SIGNATURE:
                code_sig_loc = loc
                break

        if code_sig_loc is None:
            end_commands_location = self.headersize + self.sizeofcmds

            if page_floor(end_commands_location + LINKEDIT_DATA_COMMAND_SIZE) \
                    > end_commands_location:
                raise SegmentAllocationFailedException()

            code_sig_loc = end_commands_location
            needed = end_commands_location + LINKEDIT_DATA_COMMAND_SIZE
            if len(self.data) < needed:
                self.data.extend(b"\x00" * (needed - len(self.data)))

            struct.pack_into(
                "<IIII", self.data, code_sig_loc,
                LC_CODE_SIGNATURE,
                LINKEDIT_DATA_COMMAND_SIZE,
                len(self.data),
                0,
            )
            self.commands.append(code_sig_loc)
            self.sizeofcmds += LINKEDIT_DATA_COMMAND_SIZE
            self.ncmds      += 1

        dataoff, datasize = struct.unpack_from("<II", self.data, code_sig_loc + 8)

        # ---- Chữ ký mới nhỏ hơn hoặc bằng chỗ đã cấp: ghi đè tại chỗ ----
        if len(sig) <= datasize:
            self.data[dataoff: dataoff + len(sig)] = sig
            pad = datasize - len(sig)
            if pad > 0:
                self.data[dataoff + len(sig): dataoff + datasize] = b"\x00" * pad
            return False

        # ---- Chữ ký mới lớn hơn: phải mở rộng __LINKEDIT ----
        if dataoff + datasize != len(self.data):
            raise InvalidMachOException(
                "Code signature is not at the end of the file"
            )

        self.data = self.data[:dataoff]

        extra_vm_size   = section_size - page_floor(datasize)
        extra_file_size = len(sig) - datasize

        if self.linkedit_command is not None:
            cmd, _ = struct.unpack_from("<II", self.data, self.linkedit_command)

            if cmd == LC_SEGMENT_64:
                # segment_command_64:
                #   +0  cmd, +4 cmdsize, +8 segname[16],
                #   +24 vmaddr(Q), +32 vmsize(Q), +40 fileoff(Q), +48 filesize(Q)
                vmsize, = struct.unpack_from(
                    "<Q", self.data, self.linkedit_command + 32
                )
                filesize, = struct.unpack_from(
                    "<Q", self.data, self.linkedit_command + 48
                )
                struct.pack_into(
                    "<Q", self.data, self.linkedit_command + 32,
                    vmsize + extra_vm_size,
                )
                struct.pack_into(
                    "<Q", self.data, self.linkedit_command + 48,
                    filesize + extra_file_size,
                )

            else:  # LC_SEGMENT (32-bit)
                # segment_command:
                #   +0  cmd, +4 cmdsize, +8 segname[16],
                #   +24 vmaddr(I), +28 vmsize(I), +32 fileoff(I), +36 filesize(I)
                vmsize, = struct.unpack_from(
                    "<I", self.data, self.linkedit_command + 28
                )
                filesize, = struct.unpack_from(
                    "<I", self.data, self.linkedit_command + 36
                )
                struct.pack_into(
                    "<I", self.data, self.linkedit_command + 28,
                    vmsize + extra_vm_size,
                )
                struct.pack_into(
                    "<I", self.data, self.linkedit_command + 36,
                    filesize + extra_file_size,
                )

        new_dataoff = len(self.data)
        struct.pack_into(
            "<II", self.data, code_sig_loc + 8,
            new_dataoff, len(sig),
        )

        self.data.extend(sig)
        self.update_header()
        return True

    # -----------------------------------------------------------------------
    def update_header(self) -> None:
        if self.cputype & CPU_ARCH_ABI64:
            struct.pack_into(
                "<IiiIIIII", self.data, 0,
                MH_MAGIC_64,
                self.cputype,
                self.cpusubtype,
                self.filetype,
                self.ncmds,
                self.sizeofcmds,
                self.flags,
                0,  # reserved
            )
        else:
            struct.pack_into(
                "<IiiIIII", self.data, 0,
                MH_MAGIC,
                self.cputype,
                self.cpusubtype,
                self.filetype,
                self.ncmds,
                self.sizeofcmds,
                self.flags,
            )


# ===========================================================================
# make_mach_o
# ===========================================================================
def make_mach_o(machos: List[MachO]) -> bytes:
    n = len(machos)
    if n == 0:
        return b""
    if n == 1:
        m = machos[0]
        m.update_header()
        return bytes(m.data)

    fat_header = struct.pack(">II", FAT_MAGIC, n)

    data_offset = page_ceil(FAT_HEADER_SIZE + n * FAT_ARCH_SIZE)

    fat_archs  = bytearray()
    macho_data = bytearray()

    for i, m in enumerate(machos):
        m.update_header()

        fat_archs += struct.pack(
            ">iiIII",
            m.cputype,
            m.cpusubtype,
            data_offset,
            len(m.data),
            PAGE_SIZE_LOG2,
        )
        data_offset += page_ceil(len(m.data))

        macho_data.extend(m.data)
        # Chỉ pad giữa các slice, không pad slice cuối cùng
        if i != n - 1:
            pad = page_ceil(len(macho_data)) - len(macho_data)
            if pad > 0:
                macho_data.extend(b"\x00" * pad)

    out = bytearray(fat_header + bytes(fat_archs))
    pad = page_ceil(len(out)) - len(out)
    if pad > 0:
        out.extend(b"\x00" * pad)

    out.extend(macho_data)
    return bytes(out)


# ===========================================================================
# Exec flags
# ===========================================================================
CS_EXECSEG_MAIN_BINARY      = 0x1
CS_EXECSEG_ALLOW_UNSIGNED   = 0x10
CS_EXECSEG_DEBUGGER         = 0x20
CS_EXECSEG_JIT              = 0x40
CS_EXECSEG_SKIP_LV          = 0x80
CS_EXECSEG_CAN_LOAD_CDHASH  = 0x100
CS_EXECSEG_CAN_EXEC_CDHASH  = 0x200


def _compute_entitlements_exec_seg_flags(entitlements: dict) -> int:
    flags = 0

    def _bool(key: str) -> bool:
        v = entitlements.get(key)
        return bool(v) if isinstance(v, bool) else False

    if _bool("get-task-allow"):
        flags |= CS_EXECSEG_ALLOW_UNSIGNED
    if _bool("run-unsigned-code"):
        flags |= CS_EXECSEG_ALLOW_UNSIGNED
    if _bool("com.apple.private.cs.debugger"):
        flags |= CS_EXECSEG_DEBUGGER
    if _bool("dynamic-codesigning"):
        flags |= CS_EXECSEG_JIT
    if _bool("com.apple.private.skip-library-validation"):
        flags |= CS_EXECSEG_SKIP_LV
    if _bool("com.apple.private.amfi.can-load-cdhash"):
        flags |= CS_EXECSEG_CAN_LOAD_CDHASH
    if _bool("com.apple.private.amfi.can-execute-cdhash"):
        flags |= CS_EXECSEG_CAN_EXEC_CDHASH

    return flags
