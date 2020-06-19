#!/usr/bin/env python3

"""
This file is part of GyroidOS

This program is free software; you can redistribute it and/or modify it
under the terms and conditions of the GNU General Public License,
version 2 (GPL 2), as published by the Free Software Foundation.

This program is distributed in the hope it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, see <http://www.gnu.org/licenses/>

The full GNU General Public License is included in this distribution in
the file called "COPYING".
"""


"""
This script instruments an aarch64 Linux ELF binary.

The instrumentation hooks every available syscall
and calls a hooking function instead of
executing the syscall. It's the hooking function's
responsibility to execute/emulate/do whatever with the syscall.

The hooking function is not part of this script. It is
part of an additional shared library, which is added
as a dependency to the instrumented binary,

To put it more simply, this script can be thought as of a
way to deliver a benign infection of aarch64 syscalls (a user-space rootkit).
The actual infection doesn't matter. It can be supplied in the form of
a shared library.

The instrumentation algorithm works for all kinds
of aarch64 Linux ELF binaries:
- executables (pie and non-pie)
- shared libraries (most importantly, e.g., libc)
- stripped and non-stripped

Known limitations are:
- There is no support for PAC (pointer authentication) which is
  a new security extension in ARMv8.3-A
- There is no support for BTI-hardened binaries.
- We assume that the ELF binary is/will be processed
  by the dynamic linker (ld.so). To put it more simply,
  binaries which don't have .got/.plt are not supported.
- Binaries bigger than 4GB, are currently unsupported. This is a
  limitation imposed by the ARM64 instruction set (PC-relative jumps
  can jump only at most 4 GB at a time).
- Some binaries, whose base image is bigger than 128 MB, can be problematic.
  The reason is the same as the above.

Theoretically, all of the above limitations can be overcome with additional effort.
However, those limitations are rather corner cases and not the standard.
They are expected to be practically irrelevant (depending on the use case).
"""

import os
import lief
import stat
from typing import List
from .common import p32 as p32
from .common import p64 as p64
from .common import log as log
from .common import chunker as chunker


class asm:
    """a tiny aarch64 assembler"""

    @staticmethod
    def adrp_x16(pc: int, dest: int) -> List[int]:
        """
        Assemble the PC-relative instruction:
        adrp x16, dest_address

        Works only if:
        |pc - dest| < 4GB

        Full specification:
        ARMv8 Architecture Reference Manual: C6.2.11
        """
        d = ((dest - dest % 0x1000) - (pc - pc % 0x1000)) // 0x1000
        if d < 0:
            d = bin((1 << 21) + d)[2:]
        else:
            d = bin(d)[2:].zfill(21)
        assert len(d) == 21
        opcode = "1"
        opcode += d[19] + d[20]
        opcode += "10000"
        opcode += d[:19]
        opcode += "10000"
        assert len(opcode) == 32
        opcode = p32(int(opcode, 2))
        return [b for b in opcode]

    @staticmethod
    def add_x16_x16(imm: int) -> List[int]:
        """
        Assemble the instruction:
        add x16, x16, #imm

        Works only if 0 <= imm < 0x1000

        Full specification:
        ARMv8 Architecture Reference Manual: C6.2.4
        """
        assert 0 <= imm < 0x1000
        opcode = "1001000100"
        opcode += bin(imm)[2:].zfill(12)
        opcode += "1000010000"
        assert len(opcode) == 32
        opcode = p32(int(opcode, 2))
        return [b for b in opcode]

    @staticmethod
    def bl(pc: int, dest: int) -> List[int]:
        """
        Assemble the PC-relative instruction:
        bl dest

        This is a function call (branch-link).

        Works only if |pc - dest| <= 128 MB

        Full specification:
        ARMv8 Architecture Reference Manual: C6.2.23
        """
        assert abs(pc - dest) <= 128 * 1024 * 1024
        imm = (dest - pc) // 4
        if imm < 0:
            imm = bin((1 << 26) + imm)[2:]
        else:
            imm = bin(imm)[2:].zfill(26)
        assert len(imm) == 26
        opcode = "100101"
        opcode += imm
        assert len(opcode) == 32
        opcode = p32(int(opcode, 2))
        return [b for b in opcode]

    @staticmethod
    def b(pc: int, dest: int) -> List[int]:
        """
        Assemble the PC-relative instruction:
        b dest

        This is an unconditional branch.

        Works only if |pc - dest| <= 128 MB

        Full specification:
        ARMv8 Architecture Reference Manual: C6.2.23
        """
        assert abs(pc - dest) <= 128 * 1024 * 1024
        imm = (dest - pc) // 4
        if imm < 0:
            imm = bin((1 << 26) + imm)[2:]
        else:
            imm = bin(imm)[2:].zfill(26)
        assert len(imm) == 26
        opcode = "000101"
        opcode += imm
        assert len(opcode) == 32
        opcode = p32(int(opcode, 2))
        return [b for b in opcode]


def instrument(binary_file: str, output_file: str,
               hooking_library: str, hooking_function: str) -> None:
    binary = lief.parse(binary_file)

    # Before manipulating the binary, we must count how many
    # syscall instructions are there.
    # We need this to know how much additional memory
    # we will need to allocate.
    # In aarch64 all instructions are 4-bytes long.
    # Also, every instruction begin must always be 4-byte aligned;
    # otherwise the CPU generates PC-misalignment exception.
    # Therefore we can use a simple linear disassembler for aarch64.
    bin_code, total = binary.get_section(".text").content, 0
    for x in chunker(bin_code, 4, 0x00):
        if x[0] == 0x01 and x[1] == 0x00 and \
                x[2] == 0x00 and x[3] == 0xd4:
            total += 1

    # the hooking library which exports the hooking_function
    # must be added as a dependency to the binary.
    # This will instruct the program loader where to find the
    # hooking_function when it needs to be resolved via the GOT.
    binary.add_library(hooking_library)

    # We cannot extend the original .text section
    # without breaking the offsets to the data sections.
    # Thus we create a completely new .text section which will
    # contain the PLT entry for our imported hooking_symbol.
    # We also mark the section as loadable so LIEF will create
    # a segment that contains the section.
    sec_plt = lief.ELF.Section(".hooking.plt")
    sec_plt.content = [0x00] * (0x200 + (total * 6 * 4))
    sec_plt.alignment = 0x1000
    sec_plt.type = lief.ELF.SECTION_TYPES.PROGBITS
    sec_plt.flags = binary.get_section(".text").flags
    sec_plt = binary.add(sec_plt, loaded=True)
    seg_plt = binary.segment_from_virtual_address(sec_plt.virtual_address)
    seg_plt.add(lief.ELF.SEGMENT_FLAGS.R)
    seg_plt.add(lief.ELF.SEGMENT_FLAGS.X)

    # We cannot extend the original GOT without breaking the .data section.
    # Thus we create a completely new GOT section which will contain only 1 entry.
    # This entry will store the resolved address for the hooking_function.
    # We also mark the section as loadable. So LIEF will create a segment
    # that contains the section.
    sec_got = lief.ELF.Section(".hooking.got")
    sec_got.content = [0x00] * 0x1000  # temporary dummy content
    sec_got.alignment = 0x1000
    sec_got.type = lief.ELF.SECTION_TYPES.PROGBITS
    sec_got.flags = binary.get_section(".got").flags
    sec_got = binary.add(sec_got, loaded=True)
    seg_got = binary.segment_from_virtual_address(sec_got.virtual_address)
    seg_got.add(lief.ELF.SEGMENT_FLAGS.R)
    seg_got.add(lief.ELF.SEGMENT_FLAGS.W)

    # Now after we have created the .hooking.plt
    # and .hooking.got sections/segments, we want to
    # fill them with content.
    #
    # The .hooking.plt will contain a stub for the hooking_function.
    # This stub will invoke the dynamic linker to resolve
    # the imported hooking_function from the hooking_library.
    # Upon resolving the imported symbol, the dynamic linker
    # will write the hooking_function's address inside our
    # .hooking.got entry.
    #
    # So overall we need:
    # (1) a new symbol for the imported hooking_function
    # (2) a relocation for the new symbol which is located inside .hooking.got
    # (3) a code stub inside .hooking.plt that will invoke the dynamic linker
    #     to lazily resolve the above relocation

    # (1) Creating the new symbol
    symbol = lief.ELF.Symbol()
    symbol.name = hooking_function
    symbol.value = seg_plt.virtual_address
    symbol.imported = True
    symbol.type = lief.ELF.SYMBOL_TYPES.FUNC
    symbol.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL

    # (2) Creating the relocation
    relocation = lief.ELF.Relocation(seg_got.virtual_address,
                                     type=lief.ELF.RELOCATION_AARCH64.JUMP_SLOT,
                                     is_rela=True)
    relocation.symbol = symbol
    binary.add_pltgot_relocation(relocation)

    # We will create another relocation to the same symbol, but
    # in the next .hooking.got slot (8 bytes after the above).
    # We will need this relocation to stalk the dynamic loader
    # and track its activity. This helps us to understand if the dynamic
    # loader has already resolved the upper relocation or not yet
    # and needs to do it lazily.
    #
    # This is a tricky part which is explained below.
    relocation = lief.ELF.Relocation(seg_got.virtual_address + 8,
                                     type=lief.ELF.RELOCATION_AARCH64.JUMP_SLOT,
                                     is_rela=True)
    relocation.symbol = symbol
    binary.add_pltgot_relocation(relocation)

    # After we have added everything needed to the binary
    # (new sections/segments/symbols/relocations), we will rebuild it.
    # This is needed because due to the new elements LIEF
    # will update some section/segment addresses.
    # Before proceeding we need to make sure that we are working
    # with the correct addresses of the sections/segments.
    file_name = "{}-instrumented".format(os.path.basename(binary_file))
    file_tmp_loc = os.path.join("/", "tmp", file_name)
    if os.path.isfile(file_tmp_loc):
        os.remove(file_tmp_loc)
    binary.write(file_tmp_loc)

    # After we have rebuild the binary, we get the fresh versions
    # of the sections and segments we are interested in.
    binary = lief.parse(file_tmp_loc)
    sec_got = binary.get_section(".hooking.got")
    seg_got = binary.segment_from_virtual_address(sec_got.virtual_address)
    sec_plt = binary.get_section(".hooking.plt")
    seg_plt = binary.segment_from_virtual_address(sec_plt.virtual_address)
    sec_real_plt = binary.get_section(".plt")
    try:
        sec_real_got = binary.get_section(".got.plt")
    except:
        sec_real_got = binary.get_section(".got")

    # Find the index at which the new JUMP_SLOT relocation was inserted inside the
    # .rela.plt list of relocations.
    #
    # With this index we can later tell the dynamic linker
    # exactly which symbol it needs to resolve and where to write its address.
    # Put more simply: the dynamic linker gets an index inside the .rela.plt relocation list,
    # fetches .rela.plt[index], reads it, sees the assigned symbol, resolves it, sees the
    # set_got.virtual address and then writes the resolved address.
    index = 0
    for x in binary.pltgot_relocations:
        if x.has_symbol and \
                x.symbol.name == hooking_function and \
                x.address == seg_got.virtual_address:
            break
        index += 1

    # (3) Creating the .hooking.plt entry.
    #
    #   .hooking.got looks like this:
    # ------------------------
    # |  resolved_address    |
    # ------------------------
    # |          1           |
    # ------------------------
    #       ... 0x00 ...
    #   3 cases to disntiguish
    #
    #
    #
    #   .hooking.plt looks like this:
    # --------------------------
    #
    #
    #
    data = [b for b in p64(0)]
    data += [b for b in p64(1)]
    data += [0x00] * (0x1000 - len(data))
    sec_got.content = data

    code_hooking_plt = [
        # adrp x16, (.hooking.got)
        asm.adrp_x16(pc=seg_plt.virtual_address,
                     dest=seg_got.virtual_address)[0],
        asm.adrp_x16(pc=seg_plt.virtual_address,
                     dest=seg_got.virtual_address)[1],
        asm.adrp_x16(pc=seg_plt.virtual_address,
                     dest=seg_got.virtual_address)[2],
        asm.adrp_x16(pc=seg_plt.virtual_address,
                     dest=seg_got.virtual_address)[3],

        # ldr x17, [x16, 8]
        0x11, 0x82, 0x40, 0xf8,

        # ldr x16, [x16]
        0x10, 0x02, 0x40, 0xf9,

        # sub x16, x16, x17
        0x10, 0x02, 0x11, 0xcb,

        # cmp x16, 0
        0x1f, 0x02, 0x00, 0xf1,

        # b.GE, +16
        0x8a, 0x00, 0x00, 0x54,

        # adrp x16, (.PLTGOT + n * 8)
        asm.adrp_x16(pc=seg_plt.virtual_address + 6 * 4,
                     dest=sec_real_got.virtual_address + (index + 3) * 8)[0],
        asm.adrp_x16(pc=seg_plt.virtual_address + 6 * 4,
                     dest=sec_real_got.virtual_address + (index + 3) * 8)[1],
        asm.adrp_x16(pc=seg_plt.virtual_address + 6 * 4,
                     dest=sec_real_got.virtual_address + (index + 3) * 8)[2],
        asm.adrp_x16(pc=seg_plt.virtual_address + 6 * 4,
                     dest=sec_real_got.virtual_address + (index + 3) * 8)[3],

        # add x16, x16, (.PLTGOT + n * 8) % 0x1000
        asm.add_x16_x16(imm=(sec_real_got.virtual_address + (index + 3) * 8) %
                            0x1000)[0],
        asm.add_x16_x16(imm=(sec_real_got.virtual_address + (index + 3) * 8) %
                            0x1000)[1],
        asm.add_x16_x16(imm=(sec_real_got.virtual_address + (index + 3) * 8) %
                            0x1000)[2],
        asm.add_x16_x16(imm=(sec_real_got.virtual_address + (index + 3) * 8) %
                            0x1000)[3],

        # b ld.so_resolver
        asm.b(pc=seg_plt.virtual_address + 8 * 4,
              dest=sec_real_plt.virtual_address)[0],
        asm.b(pc=seg_plt.virtual_address + 8 * 4,
              dest=sec_real_plt.virtual_address)[1],
        asm.b(pc=seg_plt.virtual_address + 8 * 4,
              dest=sec_real_plt.virtual_address)[2],
        asm.b(pc=seg_plt.virtual_address + 8 * 4,
              dest=sec_real_plt.virtual_address)[3],

        # adrp x16, .hooking.got
        asm.adrp_x16(pc=seg_plt.virtual_address + 9 * 4,
                     dest=seg_got.virtual_address)[0],
        asm.adrp_x16(pc=seg_plt.virtual_address + 9 * 4,
                     dest=seg_got.virtual_address)[1],
        asm.adrp_x16(pc=seg_plt.virtual_address + 9 * 4,
                     dest=seg_got.virtual_address)[2],
        asm.adrp_x16(pc=seg_plt.virtual_address + 9 * 4,
                     dest=seg_got.virtual_address)[3],

        # ldr x17, [x16]
        0x11, 0x02, 0x40, 0xf9,

        # br x17
        0x20, 0x02, 0x1f, 0xd6
    ]

    code_registers_backup = [
        # stp x1, x2, [sp, -0x10]!
        0xe1,
        0x0b,
        0xbf,
        0xa9,

        # stp x3, x4, [sp, -0x10]!
        0xe3,
        0x13,
        0xbf,
        0xa9,

        # stp x5, x6, [sp, -0x10]!
        0xe5,
        0x1b,
        0xbf,
        0xa9,

        # stp x7, x8, [sp, -0x10]!
        0xe7,
        0x23,
        0xbf,
        0xa9,

        # stp x9, x10, [sp, -0x10]!
        0xe9,
        0x2b,
        0xbf,
        0xa9,

        # stp x11, x12, [sp, -0x10]!
        0xeb,
        0x33,
        0xbf,
        0xa9,

        # stp x13, x14, [sp, -0x10]!
        0xed,
        0x3b,
        0xbf,
        0xa9,

        # stp x15, x16, [sp, -0x10]!
        0xef,
        0x43,
        0xbf,
        0xa9,

        # stp x17, x18, [sp, -0x10]!
        0xf1,
        0x4b,
        0xbf,
        0xa9,

        # stp x19, x20, [sp, -0x10]!
        0xf3,
        0x53,
        0xbf,
        0xa9,

        # stp x21, x22, [sp, -0x10]!
        0xf5,
        0x5b,
        0xbf,
        0xa9,

        # stp x23, x24, [sp, -0x10]!
        0xf7,
        0x63,
        0xbf,
        0xa9,

        # stp x25, x26, [sp, -0x10]!
        0xf9,
        0x6b,
        0xbf,
        0xa9,

        # stp x27, x28, [sp, -0x10]!
        0xfb,
        0x73,
        0xbf,
        0xa9,

        # str x29, [sp, -0x10]!
        0xfd,
        0x0f,
        0x1f,
        0xf8,

        # ret
        0xc0,
        0x03,
        0x5f,
        0xd6
    ]

    code_registers_restore = [
        # ldr x29, [sp], 0x10
        0xfd,
        0x07,
        0x41,
        0xf8,

        # ldp x27, x28, [sp], 0x10
        0xfb,
        0x73,
        0xc1,
        0xa8,

        # ldp x25, x26, [sp], 0x10
        0xf9,
        0x6b,
        0xc1,
        0xa8,

        # ldp x23, x24, [sp], 0x10
        0xf7,
        0x63,
        0xc1,
        0xa8,

        # ldp x21, x22, [sp], 0x10
        0xf5,
        0x5b,
        0xc1,
        0xa8,

        # ldp x19, x20, [sp], 0x10
        0xf3,
        0x53,
        0xc1,
        0xa8,

        # ldp x17, x18, [sp], 0x10
        0xf1,
        0x4b,
        0xc1,
        0xa8,

        # ldp x15, x16, [sp], 0x10
        0xef,
        0x43,
        0xc1,
        0xa8,

        # ldp x13, x14, [sp], 0x10
        0xed,
        0x3b,
        0xc1,
        0xa8,

        # ldp x11, x12, [sp], 0x10
        0xeb,
        0x33,
        0xc1,
        0xa8,

        # ldp x9, x10, [sp], 0x10
        0xe9,
        0x2b,
        0xc1,
        0xa8,

        # ldp x7, x8, [sp], 0x10
        0xe7,
        0x23,
        0xc1,
        0xa8,

        # ldp x5, x6, [sp], 0x10
        0xe5,
        0x1b,
        0xc1,
        0xa8,

        # ldp x3, x4, [sp], 0x10
        0xe3,
        0x13,
        0xc1,
        0xa8,

        # ldp x1, x2, [sp], 0x10
        0xe1,
        0x0b,
        0xc1,
        0xa8,

        # ret
        0xc0,
        0x03,
        0x5f,
        0xd6
    ]

    code_plt = code_hooking_plt + \
               code_registers_backup + \
               code_registers_restore
    tab_code = []
    tab_base_addr = seg_plt.virtual_address + len(code_plt)
    registers_backup_addr = seg_plt.virtual_address + len(code_hooking_plt)
    registers_restore_addr = seg_plt.virtual_address + \
                             len(code_hooking_plt + code_registers_backup)

    def tab_addr(idx: int) -> int:
        """
        return the address of the
        idx-th branch table entry
        """
        return tab_base_addr + idx * (6 * 4)

    def tab_entry(idx: int, call_site: int):
        """
        Create a new entry for the branch_table.
        Each branch table entry consists of the instructions:

        str x30, [sp, -0x8]!
        bl registers_backup
        bl hooking_plt (place of the plt for hooking_function)
        bl registers_restore
        ldr x30, [sp], 0x8
        b call_site
        """
        this_addr = tab_addr(idx)
        entry = [
            # str x30, [sp, -0x10]!
            0xfe,
            0x0f,
            0x1f,
            0xf8,

            # bl registers_backup
            asm.bl(pc=this_addr + 4, dest=registers_backup_addr)[0],
            asm.bl(pc=this_addr + 4, dest=registers_backup_addr)[1],
            asm.bl(pc=this_addr + 4, dest=registers_backup_addr)[2],
            asm.bl(pc=this_addr + 4, dest=registers_backup_addr)[3],

            # bl hooking_plt
            asm.bl(pc=this_addr + 2 * 4, dest=seg_plt.virtual_address)[0],
            asm.bl(pc=this_addr + 2 * 4, dest=seg_plt.virtual_address)[1],
            asm.bl(pc=this_addr + 2 * 4, dest=seg_plt.virtual_address)[2],
            asm.bl(pc=this_addr + 2 * 4, dest=seg_plt.virtual_address)[3],

            # bl registers_restore
            asm.bl(pc=this_addr + 3 * 4, dest=registers_restore_addr)[0],
            asm.bl(pc=this_addr + 3 * 4, dest=registers_restore_addr)[1],
            asm.bl(pc=this_addr + 3 * 4, dest=registers_restore_addr)[2],
            asm.bl(pc=this_addr + 3 * 4, dest=registers_restore_addr)[3],

            # ldr x30, [sp], 0x10
            0xfe,
            0x07,
            0x41,
            0xf8,

            # b call_site
            asm.b(pc=this_addr + 5 * 4, dest=call_site + 4)[0],
            asm.b(pc=this_addr + 5 * 4, dest=call_site + 4)[1],
            asm.b(pc=this_addr + 5 * 4, dest=call_site + 4)[2],
            asm.b(pc=this_addr + 5 * 4, dest=call_site + 4)[3],
        ]
        return entry

    # Analysis and rewriting phase:
    # Find all svc 0 instructions and replace them with
    # a PC-relative branch to the branch table.
    #
    # The i-th svc 0 instruction is branched to
    # the i-th table entry.
    #
    # The i-th table entry:
    # - backups all registers,
    # - invokes our hooking function
    # - restores all registers
    # - jumps back to call_site_of(i-th svc 0) + 4
    #
    # The analysis works as follows:
    # - we get all the bytes of the .text section and iterate over
    #   all of them in pairs of 4. An aarch64 instruction is always 4 bytes.
    # - when we find a "svc 0" instruction, we patch it.
    sec_text = binary.get_section(".text")
    assert len(sec_text.content) % 4 == 0
    code, pc, idx, total = sec_text.content, sec_text.virtual_address, 0, 0
    for x in chunker(code, 4, 0x00):
        # if the current instruction is "svc 0" == 0x010000d4
        if x[0] == 0x01 and x[1] == 0x00 and x[2] == 0x00 and x[3] == 0xd4:
            branch = asm.b(pc=pc, dest=tab_addr(idx=total))
            code[idx + 0], code[idx + 1] = branch[0], branch[1]
            code[idx + 2], code[idx + 3] = branch[2], branch[3]
            tab_code += tab_entry(idx=total, call_site=pc)
            total += 1
        pc, idx = pc + 4, idx + 4
    sec_plt.content = code_plt + tab_code
    sec_text.content = code
    log.success("Patched {} syscalls in total".format(total))

    # Build and save the final binary we instrumented.
    if os.path.isfile(output_file):
        os.remove(output_file)
    binary.write(output_file)
    os.chmod(output_file, os.stat(output_file).st_mode | stat.S_IEXEC)
    log.info("Saved {}".format(output_file))
