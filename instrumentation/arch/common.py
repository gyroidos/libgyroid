import sys
import struct
from itertools import tee, zip_longest


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


class Endian:
    BIG = 0x00
    LITTLE = 0x01


def p8(number: int, signed: bool = False) -> bytes:
    """pack an 8-bit integer into a byte"""
    fmt = "b" if signed else "B"
    return struct.pack("{}".format(fmt), number)


def u8(content: bytes, signed: bool = False) -> int:
    """unpack 1 byte into an 8-bit integer"""
    assert len(content) == 1
    fmt = "b" if signed else "B"
    return struct.unpack("{}".format(fmt), content)[0]


def p16(number: int, endianness: Endian = Endian.LITTLE, signed: bool = False) -> bytes:
    """pack a 16-bit integer into a word"""
    fmt = "h" if signed else "H"
    end = "<" if endianness == Endian.LITTLE else ">"
    return struct.pack("{}{}".format(end, fmt), number)


def u16(content: bytes, endianness: Endian = Endian.LITTLE, signed: bool = False) -> bytes:
    """unpack 2 bytes into a 16-bit integer"""
    assert len(content) == 2
    fmt = "h" if signed else "H"
    end = "<" if endianness == Endian.LITTLE else ">"
    return struct.unpack("{}{}".format(end, fmt), content)[0]


def p32(number: int, endianness: Endian = Endian.LITTLE, signed: bool = False) -> bytes:
    """pack a 32-bit integer into a double word"""
    fmt = "i" if signed else "I"
    end = "<" if endianness == Endian.LITTLE else ">"
    return struct.pack("{}{}".format(end, fmt), number)


def u32(content: bytes, endianness: Endian = Endian.LITTLE, signed: bool = False) -> int:
    """unpack a double word into a 32-bit integer"""
    assert len(content) == 4
    fmt = "i" if signed else "I"
    end = "<" if endianness == Endian.LITTLE else ">"
    return struct.unpack("{}{}".format(end, fmt), content)[0]


def p64(number: int, endianness: Endian = Endian.LITTLE, signed: bool = False) -> bytes:
    """pack a 64-bit integer into a quad word"""
    fmt = "q" if signed else "Q"
    end = "<" if endianness == Endian.LITTLE else ">"
    return struct.pack("{}{}".format(end, fmt), number)


def u64(content: bytes, endianness: Endian = Endian.LITTLE, signed: bool = False) -> int:
    """unpack a quad word into a 64-bit integer"""
    assert len(content) == 8
    fmt = "q" if signed else "Q"
    end = "<" if endianness == Endian.LITTLE else ">"
    return struct.unpack("{}{}".format(end, fmt), content)[0]


def chunker(iterable, chunk_size, fill_value=None):
    """Partition an iterable into chunks of the given chunk_size"""
    args = [iter(iterable)] * chunk_size
    return zip_longest(*args, fillvalue=fill_value)


def pairwise(iterable):
    """
    If x is an iterable, return an iterator that goes through x in pairs,
    (current, next) or (previous, current):
    x -> (x0, x1) (x1, x2) (x2, x3) ...
    """
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


def int2hex(number: int) -> str:
    """transform an integer to hex string"""
    return hex(number)


def hex2int(hex_str: str) -> int:
    """transform a hex string to a unsigned integer"""
    return int(hex_str, 16)


def byte2hex(byte: bytes, prefix=False) -> str:
    """transform bytes to a hex string (with or without 0x prefix)"""
    prefix = "" if not prefix else "0x"
    return prefix + byte.hex()


def hex2byte(hex_str: str) -> bytes:
    """transform hex string to a bytes array"""
    if hex_str[0:2] == "0x":
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def is_int(text: str) -> bool:
    """check if the given text can be cast to int"""
    try:
        num = int(text)
        return True
    except ValueError:
        return False


class log:
    """
    Colorful logging to the console.
    """

    class colors:
        ENDC = '\033[0m'
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'

    COLORS_ENABLED = True
    DEBUG_ENABLED = False

    @staticmethod
    def info(message) -> None:
        if log.COLORS_ENABLED:
            print(log.colors.BLUE + "[*] " + log.colors.ENDC, end='')
        else:
            print("[*] ", end='')
        print(message)

    @staticmethod
    def error(message) -> None:
        if log.COLORS_ENABLED:
            print(log.colors.RED + "[-] " + log.colors.ENDC, end='')
        else:
            print("[-] ", end='')
        print(message)

    @staticmethod
    def success(message) -> None:
        if log.COLORS_ENABLED:
            print(log.colors.GREEN + "[+] " + log.colors.ENDC, end='')
        else:
            print("[+] ", end='')
        print(message)

    @staticmethod
    def debug(message) -> None:
        if not log.DEBUG_ENABLED:
            return
        if log.COLORS_ENABLED:
            print(log.colors.YELLOW + "[d] " + log.colors.ENDC, end='')
        else:
            print("[d] ", end='')
        print(message)

    @staticmethod
    def stderr(message) -> None:
        print(message, file=sys.stderr)
