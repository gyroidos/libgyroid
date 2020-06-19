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


import os
import re
import sys
import lief
import timeit
import shutil
import platform
import argparse
import subprocess
from typing import Tuple
from arch.common import log as log
from arch.x86_64 import instrument as x86_64_instrument
from arch.aarch64 import instrument as aarch64_instrument


def detect_libc() -> Tuple[str, str, str]:
    """
    Detect the host's OS kernel and CPU arch.
    Detect host's system libc and copy it to /tmp so that
    we can patch it later on.

    :return: Triple of (kernel, arch, dst of patchable libc copy)
    """
    kernel = platform.system()
    arch = platform.machine()

    (deps, _) = subprocess.Popen(
        "ldd /usr/bin/ls",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT).communicate()
    # libc.so.6 => /lib64/libc.so.6 (0x00007f5b3bab7000)
    hits = re.findall(r"libc\.so\.\d+ +=> +(.+) +\(", deps.decode())
    assert len(hits) == 1
    src_libc = hits[0]
    dst_libc = os.path.basename(hits[0])
    dst_libc = os.path.join("/", "tmp", dst_libc)
    log.success("Detected libc @ {}".format(src_libc))
    if os.path.isfile(dst_libc):
        os.remove(dst_libc)
    shutil.copy(src_libc, dst_libc)

    return kernel, arch, dst_libc


def main() -> None:
    parser = argparse.ArgumentParser(
        description=
        "Script for hooking syscalls in x86_64 and aarch64 (libc) binaries.\n\n" + \
        "Examples:\n" + \
        "\t ./instrument.py" + \
        "\t will detect your system's libc and instrument it by\n" + \
        "adding libgyroid.so as a dependency and dispatch_sc as a hooking symbol.\n" + \
        "\t ./instrument.py --binary_file /path/to/bin/file --hooking_library /path/to" + \
        "/hooking/lib.so --hooking_function func_name\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--binary_file",
        action="store",
        type=str,
        default=None,
        help="the binary file which will be instrumented; in most cases this is the libc")
    parser.add_argument(
        "--output_file",
        action="store",
        type=str,
        default=None,
        help="where and under what name to store the instrumented file;\n"
             "by default the output is saved under the same directory as "
             "the input binary_file but with an -instrumented prefix"
    )
    parser.add_argument(
        "--hooking_library",
        action="store",
        type=str,
        default="libgyroid.so",
        help="the shared library which exports "
             "the syscall hooking function;"
             "this library will be added as a "
             "dependency to the instrumented binary "
             "[default: libgyroid.so]")
    parser.add_argument(
        "--hooking_function",
        action="store",
        type=str,
        default="dispatch_sc",
        help="instrumented syscalls will be "
             "replaced with calls to this function"
             "[default: dispatch_sc]")
    parser.add_argument(
        "--disable_colors",
        action="store_true",
        help="disable the colors in the logging messages"
    )
    parser.add_argument(
        "--enable_debug",
        action="store_true",
        help="enable the debugging logging messages"
    )
    parser.add_argument(
        "--analysis_only",
        action="store_true",
        help="analyse the binary and report the results without performing any patching;"
             "at the moment implemented only for x86_64 binaries."
    )
    parser.add_argument(
        "--disable_nop_sled",
        action="store_true",
        help="don't perform nop-sled patches for x86_64 binaries;"
             "nop-sledding works only for static binaries (not for .so!)"
    )
    args = parser.parse_args()

    log.COLORS_ENABLED = not args.disable_colors
    log.DEBUG_ENABLED = args.enable_debug

    # no binary file specified; detect libc
    if args.binary_file is None:
        log.info("No binary file specified.")
        log.info("Detecting and copying system's libc.")
        kernel, arch, args.binary_file = detect_libc()
    else:
        # binary file was specified;
        # check if its arch and OS are supported
        log.info("Checking {}".format(args.binary_file))
        bin_file = lief.parse(args.binary_file)

        if bin_file.header.machine_type == lief.ELF.ARCH.AARCH64:
            arch = "aarch64"
        elif bin_file.header.machine_type == lief.ELF.ARCH.x86_64:
            arch = "x86_64"
        else:
            arch = bin_file.header.machine_type

        if bin_file.header.identity_os_abi == lief.ELF.OS_ABI.LINUX\
                or bin_file.header.identity_os_abi == lief.ELF.OS_ABI.SYSTEMV:
            kernel = "Linux"
        else:
            kernel = bin_file.header.identity_os_abi

    # If either the OS kernel or the CPU arch are
    # not supported, exit forcefully.
    if kernel != "Linux":
        log.error("Unsupported OS kernel: {}".format(kernel))
        sys.exit(1)
    if arch != "x86_64" and arch != "aarch64":
        log.error("Unsupported arch: {}".format(arch))
        sys.exit(1)
    log.success("Detected OS: {}".format(kernel))
    log.success("Detected arch: {}".format(arch))

    if arch == "x86_64":
        bin_file = lief.parse(args.binary_file)
        if not bin_file.has_section(".symtab"):
            log.error("stripped x86_64 binaries are not supported")
            sys.exit(1)

    # where to save the instrumented file
    if args.output_file is None:
        args.output_file = "{}-instrumented".format(args.binary_file)

    # start the instrumentation
    time_start = timeit.default_timer()
    if arch == "x86_64":
        x86_64_instrument(binary_file=args.binary_file,
                          output_file=args.output_file,
                          hooking_library=args.hooking_library,
                          hooking_function=args.hooking_function,
                          analysis_only=args.analysis_only,
                          enabled_nop_sled=not args.disable_nop_sled)
    elif arch == "aarch64":
        aarch64_instrument(binary_file=args.binary_file,
                           output_file=args.output_file,
                           hooking_library=args.hooking_library,
                           hooking_function=args.hooking_function)
    time_end = timeit.default_timer()
    log.info("Total execution time: %.2f seconds" % (time_end - time_start))


if __name__ == "__main__":
    main()
