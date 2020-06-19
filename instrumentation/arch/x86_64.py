import os
import lief
import stat
import bisect
import capstone
from .common import *
from typing import List
from typing import Dict


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


class asm:
    """a tiny x86_64 assembler"""

    _reg_map = {
        "rax": 0, "rcx": 1, "rdx": 2, "rbx": 3,
        "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
        "r8": 0, "r9": 1, "r10": 2, "r11": 3,
        "r12": 4, "r13": 5, "r14": 6, "r15": 7
    }

    @staticmethod
    def call_rax() -> List[int]:
        """
        Assemble a x86_64 indirect call (pc-relative) instruction.

        call rax

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 3-122, Vol. 2A
        """
        return [0xff, 0xd0]

    @staticmethod
    def call(pc: int, dest: int) -> List[int]:
        """
        Assemble a x86_64 short call (pc-relative) instruction.

        call dest

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 3-122, Vol. 2A

        :param pc: program address where this instruction will be put
        :param dest: the target address that will be called
        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        # assemble `call dst`
        opcode = p8(0xe8)
        delta = dest - pc - 5
        opcode += p32(delta, signed=True)
        assert len(opcode) == 5

        return [b for b in opcode]

    @staticmethod
    def jump(pc: int, dest: int) -> List[int]:
        """
        Assemble a x86_64 near jump (pc-relative) instruction.

        jmp dest

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 3-488, Vol. 2A

        :param pc: program address where this instruction will be put
        :param dest: the target address that will be jumped on
        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """

        # assemble `jmp dest`
        opcode = p8(0xe9)
        delta = dest - pc - 5
        opcode += p32(delta, signed=True)
        assert len(opcode) == 5

        return [b for b in opcode]

    @staticmethod
    def jump_short(pc: int, dest: int) -> List[int]:
        """
        Assemble a x86_64 near short 2-bytes long pc-relative jump instruction.

        jmp dest

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 3-488, Vol. 2A

        :param pc: program address where this instruction will be put
        :param dest: the target address that will be jumped on
        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        opcode = p8(0xeb)
        delta = dest - pc - 2
        assert abs(delta) <= 127
        opcode += p8(delta, signed=True)
        assert len(opcode) == 2

        return [b for b in opcode]

    @staticmethod
    def jump_indirect(pc: int, dest: int) -> List[int]:
        """
        Assemble a x86_64 near indirect jump (pc-relative) instruction.

        jmp [dest]

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 3-488, Vol. 2A

        :param pc: program address where this instruction will be put
        :param dest: the target address that will be jumped on (absolute)
        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        # assemble `jmp [dest]`
        opcode = p8(0xff) + p8(0x25)
        delta = dest - pc - 6
        opcode += p32(delta, signed=True)
        assert len(opcode) == 6

        return [b for b in opcode]

    @staticmethod
    def jump_rsp(offset: int) -> List[int]:
        """

        :param offset:
        :return:
        """
        opcode = p8(0xff)
        opcode += p8(0xa4)
        opcode += p8(0x24)
        opcode += p32(offset, signed=True)
        assert len(opcode) == 7

        return [b for b in opcode]

    @staticmethod
    def push_const(value: int) -> List[int]:
        """
        Assemble a x86_64 `push value` instruction.

        push value

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 4-511, Vol. 2B

        :param value: the value that will be pushed on the stack
        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        # assemble `push value`
        opcode = p8(0x68)
        opcode += p32(value, signed=True)
        assert len(opcode) == 5

        return [b for b in opcode]

    @staticmethod
    def push_reg(name: str) -> List[int]:
        """
        Assemble a x86_64 `push reg` instruction.

        push reg (e.g. rax)

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 4-511, Vol. 2B

        :param name: The name of the register which should be pushed on
        the stack. Only 64-bit integer registers are supported (e.g. rax)
        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """

        # assemble `push reg`
        name = name.lower()
        if is_int(name[1:]) and (8 <= int(name[1:]) <= 15):
            opcode = p16(0x4150 + asm._reg_map[name], endianness=Endian.BIG)
        else:
            opcode = p8(0x50 + asm._reg_map[name])

        return [b for b in opcode]

    @staticmethod
    def pop_reg(name: str) -> List[int]:
        """
        Assemble a x86_64 `pop reg` instruction.

        pop reg (e.g. rax)

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 4-511, Vol. 2B

        :param name: The name of the register which should be pushed on
        the stack. Only 64-bit integer registers are supported (e.g. rax)
        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """

        # assemble `pop reg`
        name = name.lower()
        if is_int(name[1:]) and (8 <= int(name[1:]) <= 15):
            opcode = p16(0x4158 + asm._reg_map[name], endianness=Endian.BIG)
        else:
            opcode = p8(0x58 + asm._reg_map[name])

        return [b for b in opcode]

    @staticmethod
    def popfq() -> List[int]:
        """
        Assemble a x86_64 'popfq' instruction.

        This is the reverse instruction of 'popfq'

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 4-394, Vol. 2B

        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        return [0x9d]

    @staticmethod
    def pushfq() -> List[int]:
        """
        Assemble a x86_64 'pushfq' instruction.

        In 64-bit mode, i.e. on x86_64, the instruction’s default
        operation is to decrement the stack pointer (RSP) by 8 and
        pushes RFLAGS on the stack.

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 4-516, Vol. 2B

        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        return [0x9c]

    @staticmethod
    def nop() -> List[int]:
        """
        Assemble a x86_64 1-byte 'nop' instruction.

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 4-163, Vol. 2B

        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        return [0x90]

    @staticmethod
    def ret() -> List[int]:
        """
        Assemble a x86_64 'ret' instruction.

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 4-553, Vol. 2B

        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        return [0xc3]

    @staticmethod
    def mov_mem_rsp_rbx(offset: int) -> List[int]:
        """
        Assemble a x86_64 mov qword [rsp + offset] rbx instruction.

        Intel® 64 and IA-32 Architectures Software Developer’s Manual
        p 4-35, Vol. 2B

        :return: the assembled instruction as a list of bytes,
        where each byte is represented as an integer
        """
        opcode = p8(0x48)
        opcode += p8(0x89)
        opcode += p8(0x9c)
        opcode += p8(0x24)
        opcode += p32(offset, signed=True)
        return [b for b in opcode]


class syscall:
    """
    This class describes a patch for the
    syscall instruction at the given address.

    There are 3 kinds of patches:
    1. Carved
    2. Padding trampoline
    3. NOP sledded
    """

    class TYPE:
        CARVED = 0
        PADDING_TRAMP = 1
        NOP_SLEDDED = 2

    # counters for statistics
    CNT_TOTAL = 0
    CNT_CARVED = 0
    CNT_PADDING_TRAMP = 0
    CNT_NOP_SLEDDED = 0

    def __init__(self, address: int, offset: int, type: int,
                 prev_insn: capstone.CsInsn = None,
                 trampoline_chain: List[int] = None,
                 func_name: str = None):
        # assert structural invariants
        assert (type == syscall.TYPE.CARVED or
                type == syscall.TYPE.PADDING_TRAMP or
                type == syscall.TYPE.NOP_SLEDDED)
        assert address >= 0
        assert offset >= 0
        if type == syscall.TYPE.CARVED:
            assert prev_insn is not None
        if type == syscall.TYPE.PADDING_TRAMP:
            assert trampoline_chain is not None
        if type == syscall.TYPE.NOP_SLEDDED:
            assert func_name is not None

        # update statistics counters
        syscall.CNT_TOTAL += 1
        if type == syscall.TYPE.CARVED:
            syscall.CNT_CARVED += 1
        elif type == syscall.TYPE.PADDING_TRAMP:
            syscall.CNT_PADDING_TRAMP += 1
        elif type == syscall.TYPE.NOP_SLEDDED:
            syscall.CNT_NOP_SLEDDED += 1

        # create object
        self.type = type
        self.offset = offset
        self.address = address
        self.prev_insn = prev_insn
        self.func_name = func_name
        self.base_address = address - offset
        self.trampoline_chain = trampoline_chain

        # logging
        if type == syscall.TYPE.CARVED:
            log.debug("CARVED syscall @ {} with prev insn: {} {}".format(
                int2hex(address), prev_insn.mnemonic, prev_insn.op_str
            ))
        elif type == syscall.TYPE.PADDING_TRAMP:
            str_chain = "[{}]".format(", ".join(int2hex(x) for x in trampoline_chain))
            log.debug("PADDING_TRAMP syscall @ {} with trampoline chain {}".format(
                int2hex(address), str_chain
            ))
        elif type == syscall.TYPE.NOP_SLEDDED:
            log.debug("NOP_SLEDDED syscall @ {} in {}".format(
                int2hex(address), func_name
            ))


def is_syscall(insn: capstone.CsInsn) -> bool:
    """
    Check if the instruction is a syscall
    :param insn: The instruction that will be checked
    :return: True if the instruction is a syscall, False otherwise
    """
    ret = insn.id == capstone.x86.X86_INS_SYSCALL
    ret |= insn.id == capstone.x86.X86_INS_SYSENTER
    return ret


def instrument(binary_file: str, output_file: str,
               hooking_library: str, hooking_function: str,
               analysis_only: bool, enabled_nop_sled: bool) -> None:
    binary: lief.ELF.Binary = lief.parse(binary_file)
    sec_text = binary.get_section(".text")
    bin_code = bytes(sec_text.content)

    def in_text(addr: int):
        """Check if the given address lies in the text section"""
        return sec_text.virtual_address <= addr <= sec_text.virtual_address + sec_text.size

    caps: capstone.Cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    caps.detail = True

    # Go over the symbol table and extract all **unique** functions,
    # i.e. if two functions start at the same address, we treat them as one.
    # Save all unique functions as triples (start_addr, length, name)
    funcs = []
    used: Dict[int, bool] = {}
    for sym in binary.symbols:
        if (sym.type == lief.ELF.SYMBOL_TYPES.FUNC or
            sym.type == lief.ELF.SYMBOL_TYPES.GNU_IFUNC) \
                and in_text(sym.value) and sym.value not in used:
            used[sym.value] = True
            if "clone" == sym.name or "print" in sym.name or "fxstat" == sym.name \
            or "brk" in sym.name or "malloc" in sym.name or "read" == sym.name \
            or "write" == sym.name or "getuid" in sym.name or "getpid" in sym.name \
            or "setitimer" in sym.name or "readlink" in sym.name or "lstat" == sym.name \
            or "fcntl" in sym.name or "dup2" in sym.name or "open" == sym.name \
            or "close" == sym.name or "chmod" == sym.name or "execve" == sym.name or "chdir" == sym.name:
                log.debug("Skipping: " + sym.name)
                continue
            funcs.append((sym.value, sym.size, sym.name))
    funcs.sort(key=lambda entry: entry[0])
    log.info("Found {} unique functions".format(len(funcs)))

    # Analysis I: find all padding bytes between functions
    # that can be used as padding trampolines.
    #
    # We separate the padding bytes in two categories:
    # 1. long jump trampolines with length >= 5 B
    # 2. short jump trampolines with 2 B <= lenght <= 4 B
    #
    # The length is determined by the fact that a long jump
    # on x86_64 is 5 bytes long and a short jump is only 2 bytes long.
    #
    # If a given padding slot is greater than 5 and
    # respectively greater than 2 bytes, we cut it into pieces 5 or 2 byte pieces
    # so that we have more available trampoline slots.
    #
    # Also, if a padding is longer than 15B, then something is wrong
    # (essentially the padding is added to make the code 16B aligned).
    # A padding longer than 15B is most likely because of incorrect sizes of
    # the function symbols inside the ELF (e.g. some functions have
    # size 0 and we can't calculate where the function really ends).
    # Wrong sizes happen mostly because of bugs in binutils or
    # manually tampering with the ELF.
    #
    # So, if we observe padding longer than 15B, we skip it.
    # This is a conservative, but sound heuristic.
    #
    long_tramps, short_tramps = [], []
    for prev, cur in pairwise(funcs):
        end = prev[0] + prev[1]
        delta = cur[0] - end
        if prev[1] == 0:
            log.debug("skipped malformed padding {}B @ {} [{} - {}] - {} has size 0".format(
                delta, int2hex(end), prev[2], cur[2], prev[2]
            ))
            continue
        if delta > 15:
            log.debug("skipped malformed padding {}B @ {} [{} - {}] - too long".format(
                delta, int2hex(end), prev[2], cur[2]
            ))
            continue

        if delta >= 5:
            n = delta // 5
            for i in range(0, n):
                long_tramps.append(end + i * 5)
            log.debug("padding {}B @ {} [{} - {}] = {} long jump trampolines".format(
                delta, int2hex(end), prev[2], cur[2], n
            ))
            delta -= n * 5
            end += n * 5

        if 2 <= delta < 5:
            n = delta // 2
            for i in range(0, n):
                short_tramps.append(end + i * 2)
            log.debug("padding {}B @ {} [{} - {}] = {} short jump trampolines".format(
                delta, int2hex(end), prev[2], cur[2], n
            ))

    short_tramps.sort()
    long_tramps.sort()
    log.info("Found {} long jump padding trampoline slots".format(len(long_tramps)))
    log.info("Found {} short jump padding trampoline slots".format(len(short_tramps)))

    # Analysis II: find all syscall instructions and generate patches for each one of them
    #
    # Using a linear disassembly find all syscall instructions and
    # separate them in 3 patch categories:
    # - CARVED: these instructions can be safely carved out into the jump table
    # - PADDING_TRAMP: these instructions cannot be carved out,
    #                  but we can redirect them to a trampoline chain of padding bytes
    # - NOP_SLEDDED: can neither be carved, nor redirect to a padding trampoline.
    #                 Fallback to a nop-sled on 0x0
    # For the linear disassembly, we use the functions' start addresses

    def can_be_carved(insn: capstone.CsInsn) -> bool:
        """
        Check if the given instruction can be safely carved out, i.e.
        its address can be safely changed without braking programming semantics.

        :param insn:
        :return: True if the instruction can be carved out, otherwise return False.
        """
        if insn is None:
            return False

        # if the instruction is less than 3 B there is nothing we can do
        # we cannot carve it because it could be a target of another branch
        if insn.size < 3:
            return False

        # we can fix all pc-relative instructions.
        # however, for now, we restrict ourselves only to
        # lea and jump/call instructions
        can_be_fixed = insn.id == capstone.x86.X86_INS_LEA
        can_be_fixed |= capstone.x86.X86_GRP_BRANCH_RELATIVE in insn.groups
        if can_be_fixed:
            return True

        # all other pc relative instructions we reject.
        # this constraint can be relaxed in the future
        # we just need to add support for translating other
        # pc-relative instructions.
        # the translation happens in the tab_entry function below.
        bad = capstone.x86.X86_REG_IP in insn.regs_read
        bad |= capstone.x86.X86_REG_RIP in insn.regs_read
        bad |= capstone.x86.X86_REG_EIP in insn.regs_read
        return not bad

    def short_trampoline_for(addr: int, up: bool = False) -> int:
        """
        Return the index of short_jump padding slot that is closest to
        the given address and is at most 127 Bytes away.
        If no such short_jump padding slot exists, return -1.
        :param addr:
        :param up: If True, search for short_jump padding slots in
        addresses lower than the given one. If False, search toward higher
        addresses instead.
        :return: index in the short_tramps list, or -1
        """
        if up:
            # we are searching for the next short jump trampoline
            # in upwards direction (toward lower addresses)
            lower_bound = bisect.bisect_right(short_tramps, addr)
            if lower_bound:
                delta_low = addr - short_tramps[lower_bound - 1]
                return -1 if delta_low >= 128 else (lower_bound - 1)
        else:
            # we are searching for the next available short jump trampoline
            # in downwards direction (toward higher addresses)
            upper_bound = bisect.bisect_left(short_tramps, addr)
            if upper_bound:
                delta_up = short_tramps[upper_bound] - addr
                return -1 if delta_up >= 128 else upper_bound
        return -1

    def long_trampoline_for(addr: int) -> int:
        """
        Search for a long_jump padding trampoline slot that is as close
        as possible to the given address and is in the range of +-127 Bytes.
        If no such padding trampoline slot exists, return -1.
        :param addr:
        :return: index of the matched trampoline, -1 otherwise
        """
        # find rightmost padding trampoline address less than or eq to addr.
        # it must be close enough for a short jump, i.e. at most 127 bytes away
        delta_low, lower_bound = -1, bisect.bisect_right(long_tramps, addr)
        if lower_bound:
            delta_low = addr - long_tramps[lower_bound - 1]
            delta_low = -1 if delta_low >= 128 else delta_low

        # find leftmost padding trampoline address greater than or eq to addr
        # it must be close enough for a short jump, i.e. at most 127 bytes away
        delta_up, upper_bound = -1, bisect.bisect_left(long_tramps, addr)
        if upper_bound != len(long_tramps):
            delta_up = long_tramps[upper_bound] - addr
            delta_up = -1 if delta_up >= 128 else delta_up

        # pick the trampoline which is closer
        if delta_up > delta_low > 0:
            return lower_bound - 1
        if delta_low > delta_up > 0:
            return upper_bound
        if delta_low > 0:
            return lower_bound - 1
        if delta_up > 0:
            return upper_bound
        return -1

    syscalls: List[syscall] = []
    for (func_addr, func_size, func_name) in funcs:
        offset = func_addr - sec_text.virtual_address

        prev = None
        for insn in caps.disasm(bin_code[offset:offset + func_size], offset=func_addr):
            if not is_syscall(insn):
                prev = insn
                continue

            if can_be_carved(prev):
                syscalls.append(syscall(
                    address=insn.address,
                    offset=(insn.address - sec_text.virtual_address),
                    type=syscall.TYPE.CARVED,
                    prev_insn=prev
                ))
                prev = insn
                continue

            # try to find a direct, suitable long trampoline
            trampoline = long_trampoline_for(insn.address)
            if trampoline > 0:
                syscalls.append(syscall(
                    address=insn.address,
                    offset=(insn.address - sec_text.virtual_address),
                    type=syscall.TYPE.PADDING_TRAMP,
                    trampoline_chain=[long_tramps[trampoline]]
                ))
                long_tramps = long_tramps[0:trampoline] + long_tramps[trampoline + 1:]
                prev = insn
                continue

            # if we didn't find a direct suitable long trampoline
            # we will try to build a chain of shorter trampolines
            # that eventually lands on a long jump trampoline.
            # if that fails too, we fall back to a nop-sledded syscall

            # try to build a chain of short jumps in upwards direction first,
            # i.e. towards lower addresses
            addr, success, chain = insn.address, False, []
            while True:
                short_trampoline = short_trampoline_for(addr, up=True)
                if short_trampoline < 0:
                    success = False
                    break

                addr = short_tramps[short_trampoline] - 1
                chain.append(short_trampoline)
                long_trampoline = long_trampoline_for(addr)
                if long_trampoline > 0:
                    chain.append(long_trampoline)
                    success = True
                    break

            if not success:
                # we didn't succeed in the up direction
                # try in the down direction now, i.e. towards higher addresses
                addr, success, chain = insn.address, False, []
                while True:
                    short_trampoline = short_trampoline_for(addr, up=False)
                    if short_trampoline < 0:
                        success = False
                        break

                    addr = short_tramps[short_trampoline] + 1
                    chain.append(short_trampoline)
                    long_trampoline = long_trampoline_for(addr)
                    if long_trampoline > 0:
                        chain.append(long_trampoline)
                        success = True
                        break

            # if we successfully built a chain either in the up or in the down
            # direction, remove the used padding slots from the respective lists
            # and create the syscall patch
            if success:
                long_trampoline = chain.pop()
                chain_addresses = [long_tramps[long_trampoline]]
                long_tramps = long_tramps[0:long_trampoline] + long_tramps[long_trampoline + 1:]
                while chain:
                    short_trampoline = chain.pop()
                    chain_addresses.append(short_tramps[short_trampoline])
                    short_tramps = short_tramps[0:short_trampoline] + short_tramps[short_trampoline + 1:]
                chain_addresses.reverse()
                syscalls.append(syscall(
                    address=insn.address,
                    offset=(insn.address - sec_text.virtual_address),
                    type=syscall.TYPE.PADDING_TRAMP,
                    trampoline_chain=chain_addresses
                ))
            else:
                # fallback to a nop sled
                syscalls.append(syscall(
                    address=insn.address,
                    offset=(insn.address - sec_text.virtual_address),
                    type=syscall.TYPE.NOP_SLEDDED,
                    func_name=func_name
                ))
            prev = insn

    log.info("Total syscalls found: {}".format(syscall.CNT_TOTAL))
    if syscall.CNT_TOTAL == 0:
        return

    log.info("\tCan be carved out: {}, i.e. {}%".format(
        syscall.CNT_CARVED, round((100.0 * syscall.CNT_CARVED) / syscall.CNT_TOTAL, 3)
    ))
    log.info("\tCan be redirected to a padding trampoline chain: {}, i.e. {}%".format(
        syscall.CNT_PADDING_TRAMP, round((100.0 * syscall.CNT_PADDING_TRAMP) / syscall.CNT_TOTAL, 3)
    ))
    log.info("\tCan be rescued with a call-rax-nop-sled: {}, i.e. {}%".format(
        syscall.CNT_NOP_SLEDDED, round((100.0 * syscall.CNT_NOP_SLEDDED) / syscall.CNT_TOTAL, 3)
    ))
    cnt = 0
    for sc in syscalls:
        if sc.type == syscall.TYPE.NOP_SLEDDED:
            cnt += 1
            log.info("\t\t{}. In function {} @ addr {}".format(
                cnt, sc.func_name, int2hex(sc.address)
            ))
    enabled_nop_sled &= (syscall.CNT_NOP_SLEDDED > 0)

    if analysis_only:
        log.info("Analysis finished")
        return

    log.info("Started patching...")

    # the hooking library which exports the hooking_function
    # must be added as a dependency to the binary.
    # This will instruct the program loader where to find the
    # hooking_function when it needs to be resolved via the GOT.
    binary.add_library(hooking_library)

    # We cannot extend the original .text section
    # without breaking the offsets to the data sections.
    # Thus we create a completely new .text section which will
    # contain the PLT entry for our imported hooking_symbol,
    # and also the jump table.
    #
    # We explicitly create a new Segment and a new Section
    # and connect them manually. We don't rely on LIEF to automatically create
    # a new segment for the section. LIEF has a bug for non-PIE
    # binaries. It overlaps distinct segments which leads to segfaults.
    # See issues:
    # https://github.com/lief-project/LIEF/issues/98
    # https://github.com/lief-project/LIEF/issues/143
    seg_plt = lief.ELF.Segment()
    seg_plt.type = lief.ELF.SEGMENT_TYPES.LOAD
    seg_plt.add(lief.ELF.SEGMENT_FLAGS.R)
    seg_plt.add(lief.ELF.SEGMENT_FLAGS.X)
    seg_plt = binary.add(seg_plt)

    sec_plt = lief.ELF.Section()
    sec_plt.name = ".hooking.plt"
    sec_plt.flags = binary.get_section(".text").flags
    sec_plt.alignment = 0x1000
    sec_plt.type = lief.ELF.SECTION_TYPES.PROGBITS
    sec_plt = binary.add(sec_plt, loaded=True)

    content = [0x00] * (0x200 + len(syscalls) * 10 * 5)
    sec_plt.content = content
    seg_plt.content = content
    seg_plt.physical_size = sec_plt.size
    seg_plt.virtual_size = sec_plt.size
    seg_plt.file_offset = sec_plt.offset
    seg_plt.virtual_address = sec_plt.virtual_address

    # We cannot extend the original GOT without breaking the .data section.
    # Thus we create a completely new GOT section which will contain only 1 entry.
    # This entry will store the resolved address for the hooking_function.
    #
    # We explicitly create a new Segment and a new Section
    # and connect them manually. We don't rely on LIEF to automatically create
    # a new segment for the section. LIEF has a bug for non-PIE
    # binaries. It overlaps distinct segments which leads to segfaults.
    # See issues:
    # https://github.com/lief-project/LIEF/issues/98
    # https://github.com/lief-project/LIEF/issues/143
    seg_got = lief.ELF.Segment()
    seg_got.type = lief.ELF.SEGMENT_TYPES.LOAD
    seg_got.add(lief.ELF.SEGMENT_FLAGS.R)
    seg_got.add(lief.ELF.SEGMENT_FLAGS.W)
    seg_got = binary.add(seg_got)

    sec_got = lief.ELF.Section()
    sec_got.name = ".hooking.got"
    sec_got.flags = binary.get_section(".got").flags
    sec_got.alignment = 0x1000
    sec_got.type = lief.ELF.SECTION_TYPES.PROGBITS
    sec_got = binary.add(sec_got, loaded=True)

    content = [0x00] * 0x1000   # temporary dummy content
    sec_got.content = content
    seg_got.content = content
    seg_got.physical_size = sec_got.size
    seg_got.virtual_size = sec_got.size
    seg_got.file_offset = sec_got.offset
    seg_got.virtual_address = sec_got.virtual_address

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
                                     type=lief.ELF.RELOCATION_X86_64.JUMP_SLOT,
                                     is_rela=True)
    relocation.symbol = symbol
    binary.add_pltgot_relocation(relocation)

    # If there are NOP_SLEDDED patches, we also need
    # to add the nop-sled's section and segment at address 0x000000
    if enabled_nop_sled:
        sec_sled = lief.ELF.Section(".hooking.sled")
        content = [0x00] * 0x1000
        sec_sled.content = content
        sec_sled.alignment = 0x1000
        sec_sled.type = lief.ELF.SECTION_TYPES.PROGBITS
        sec_sled.flags = binary.get_section(".text").flags
        sec_sled.virtual_address = 0x0000
        sec_sled = binary.add(sec_sled, loaded=True)
        seg_sled = binary.segment_from_virtual_address(sec_sled.virtual_address)
        sec_sled.virtual_address = 0x0000
        seg_sled.virtual_address = 0x0000
        seg_sled.add(lief.ELF.SEGMENT_FLAGS.R)
        seg_sled.add(lief.ELF.SEGMENT_FLAGS.X)

    # Find the index at which the new JUMP_SLOT relocation was inserted inside the
    # .rela.plt list of relocations.
    #
    # With this index we can later tell the dynamic linker
    # exactly which symbol it needs to resolve and where to write its address.
    # Put more simply: the dynamic linker gets an index inside the .rela.plt relocation list,
    # fetches .rela.plt[index], reads it, sees the assigned symbol, resolves it, sees the
    # sec_got.virtual address and then writes the resolved address.
    index = 0
    for x in binary.pltgot_relocations:
        if x.has_symbol and \
                x.symbol.name == hooking_function and \
                x.address == seg_got.virtual_address:
            break
        index += 1

    log.info("Building additional GOT and PLT entries...")
    # (3) Creating the .hooking.plt entry.
    #
    #   .hooking.got looks like this:
    # ------------------------
    # |  resolved_address    |
    # ------------------------
    #       ... 0x00 ...
    #
    #
    #   .hooking.plt looks like this:
    # --------------------------
    # |   hooking_function plt  |
    # --------------------------
    # |     register_backup()   |
    # --------------------------
    # |    register_restore()   |
    # --------------------------
    # |       jump_tab[0]       |
    # |       jump_tab[1]       |
    #           .....
    # |       jump_tab[n-1]     |
    # --------------------------
    #
    #
    #
    sec_text = binary.get_section(".text")
    sec_real_plt = binary.get_section(".plt")
    data = [b for b in p64(seg_plt.virtual_address + 6)]
    data += [0x00] * (0x1000 - len(data))
    sec_got.content = data
    seg_got.content = data

    code_hooking_plt = asm.jump_indirect(pc=seg_plt.virtual_address,
                                         dest=seg_got.virtual_address)
    code_hooking_plt += asm.push_const(index)
    code_hooking_plt += asm.jump(pc=seg_plt.virtual_address + len(code_hooking_plt),
                                 dest=sec_real_plt.virtual_address)

    backuped_regs = [
        "rbx", "rcx", "rdx", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13",
        "r14", "r15", "rbp"
    ]
    assert len(backuped_regs) % 2 == 0
    code_registers_backup = []
    for reg in backuped_regs:
        code_registers_backup += asm.push_reg(reg)
    code_registers_backup += asm.pushfq()
    code_registers_backup += asm.jump_rsp(offset=(len(backuped_regs) + 1) * 8)

    code_registers_restore = asm.pop_reg("rbx")
    code_registers_restore += asm.mov_mem_rsp_rbx(offset=((len(backuped_regs) + 1) * 8))
    code_registers_restore += asm.popfq()
    for reg in reversed(backuped_regs):
        code_registers_restore += asm.pop_reg(reg)
    code_registers_restore += asm.ret()

    code_plt = code_hooking_plt + \
               code_registers_backup + \
               code_registers_restore
    code_hook_addr = seg_plt.virtual_address
    code_registers_backup_addr = seg_plt.virtual_address + len(code_hooking_plt)
    code_registers_restore_addr = code_registers_backup_addr + len(code_registers_backup)

    tab_code = []
    tab_start_addr = code_registers_restore_addr + len(code_registers_restore)

    def tab_entry(pc: int, site: int, sc: syscall = None) -> List[int]:
        """
        carved (adjusted) instruction
        call register_backup
        call sym.imp.hook
        call register_restore
        jmp syscall site
        nop padding

        :param sc:
        :param site:
        :param pc:
        :return:
        """

        assert pc >= 0
        assert site >= 0

        entry = []

        if sc is not None:
            # adjust pc-relative instructions
            should_fix = sc.prev_insn.id == capstone.x86.X86_INS_LEA
            should_fix |= capstone.x86.X86_GRP_BRANCH_RELATIVE in sc.prev_insn.groups
            should_fix &= sc.prev_insn.disp_size > 0
            if should_fix:
                s = sc.offset - sc.prev_insn.size
                d = s + sc.prev_insn.disp
                t = pc + len(entry) - sec_text.virtual_address
                r = d - t
                entry += [b for b in sc.prev_insn.bytes[0:sc.prev_insn.disp_offset]]
                entry += [b for b in p32(r, signed=True)]
            else:
                entry += [b for b in sc.prev_insn.bytes]

        entry += asm.call(pc=(pc + len(entry)),
                          dest=code_registers_backup_addr)
        entry += asm.call(pc=(pc + len(entry)),
                          dest=code_hook_addr)
        entry += asm.call(pc=(pc + len(entry)),
                          dest=code_registers_restore_addr)
        entry += asm.jump(pc=(pc + len(entry)),
                          dest=site)
        return entry

    # Build the code for the jump table.
    # For this, we need to iterate over all syscall patches
    #
    # While iterating, we simultaneously build the jump table and apply every patch.
    log.info("Applying syscall patches...")
    code = binary.get_section(".text").content
    for sc in syscalls:
        if sc.type == syscall.TYPE.CARVED:
            log.debug("Applying CARVED patch @ {}...".format(
                int2hex(sec_text.virtual_address + sc.offset)
            ))
            x = sc.offset - sc.prev_insn.size
            patch = asm.nop() * (sc.prev_insn.size - 3)
            patch += asm.jump(pc=sec_text.virtual_address + sc.offset - 3,
                              dest=tab_start_addr + len(tab_code))
            log.debug("Before patch = [{}] = [{}]".format(
                ", ".join([int2hex(t) for t in code[x:x + len(patch)]]),
                "; ".join([sc.prev_insn.mnemonic + " " + sc.prev_insn.op_str, "syscall"])
            ))
            for i in range(len(patch)):
                code[x + i] = patch[i]
            log.debug("After patch = [{}] = [{}]".format(
                ", ".join([int2hex(t) for t in code[x:x + len(patch)]]),
                "; ".join(["nop"] * (sc.prev_insn.size - 3) + ["jmp ..."])
            ))
            tab_code += tab_entry(pc=tab_start_addr + len(tab_code),
                                  site=sec_text.virtual_address + sc.offset + 2,
                                  sc=sc)
            log.debug("-----")

        if sc.type == syscall.TYPE.PADDING_TRAMP:
            chain = [sc.offset] + [x - sc.base_address for x in sc.trampoline_chain]
            log.debug("Applying TRAMPOLINE patch @ {} with len = {} jumps...".format(
                int2hex(sec_text.virtual_address + sc.offset),
                len(chain)
            ))
            for (x, y) in pairwise(chain):
                if y is None:
                    break
                edge = asm.jump_short(pc=sec_text.virtual_address + x,
                                      dest=sec_text.virtual_address + y)
                code[x], code[x + 1] = edge[0], edge[1]
            end = chain.pop()
            long_edge = asm.jump(pc=sec_text.virtual_address + end,
                                 dest=tab_start_addr + len(tab_code))
            for i in range(len(long_edge)):
                code[end + i] = long_edge[i]
            tab_code += tab_entry(pc=tab_start_addr + len(tab_code),
                                  site=sec_text.virtual_address + sc.offset + 2)
            log.debug("-----")

        if sc.type == syscall.TYPE.NOP_SLEDDED and not enabled_nop_sled:
            log.debug("Skipped NOP SLEDDED patch...")
            log.debug("-----")

        if sc.type == syscall.TYPE.NOP_SLEDDED and enabled_nop_sled:
            log.debug("Applying NOP SLEDDED patch @ {}...".format(
                int2hex(sec_text.virtual_address + sc.offset)
            ))
            code[sc.offset] = asm.call_rax()[0]
            code[sc.offset + 1] = asm.call_rax()[1]
            log.debug("-----")

    if enabled_nop_sled:
        log.info("Building the NOP sled...")
        content = asm.nop() * 0x200
        content += asm.jump(pc=0x200,
                            dest=tab_start_addr + len(tab_code))
        content += [0x00] * (0x1000 - len(content))
        sec_sled.content = content
        # the final tab entry ends with a ret and not with a jump
        tab_code += asm.push_reg("rbx")  # for stack alignment
        tab_code += asm.call(pc=tab_start_addr + len(tab_code),
                             dest=code_registers_backup_addr)
        tab_code += asm.call(pc=tab_start_addr + len(tab_code),
                             dest=code_hook_addr)
        tab_code += asm.call(pc=tab_start_addr + len(tab_code),
                             dest=code_registers_restore_addr)
        tab_code += asm.pop_reg("rbx")  # for stack alignment
        tab_code += asm.ret()
    sec_plt.content = code_plt + tab_code
    seg_plt.content = code_plt + tab_code
    binary.get_section(".text").content = code

    # Build and save the final binary we instrumented.
    log.info("Assembling final binary...")
    if os.path.isfile(output_file):
        os.remove(output_file)
    binary.write(output_file)
    os.chmod(output_file, os.stat(output_file).st_mode | stat.S_IEXEC)
    log.info("Saved {}".format(output_file))
