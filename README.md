# GyroidOS

GyroidOS reduces the Linux kernel's attack surface by:
- hooking raw syscalls inside x86_64 and aarch64 Linux ELF binaries;
- handling some of the hooked syscalls by providing an alternative implementation.

---

### Prerequisites to build the project
- gcc/clang
- cmake
- python3 + virtualenv


### Building and testing from scratch
```bash
git clone https://github.com/gyroidos/libgyroid
cd libgyroid
```

#### Instrument an ELF binary

To hook the system call sites in an ELF binary the following steps are necessary:

```
source ./venv/bin/activate
cd instrumentation
python3 instrument.py--binary_file <binary file to patch> --output_file <output file location> --disable_nop_sled
```

This hooks the system call sites in the given ELF binary and calls dispatch_sc in libgyroid.so on each hooked system call

#### Building libgyroid
The following commands build the system call handling library 'libgyroid':

```
source configure_libgyroid.sh
cmake ..
make
```

### Testing
The binary instrumentation framework and system call handling have been tested on a Fedora 32 server installation using the GNU libc 2.31.
To verify the build of libgyroid was successful, the following steps can be used:

```
cp build/libgyroid/libgyroid.so /lib64/libgyroid.so
source configure_hooking.sh
cd instrumentation
python3 instrument.py--binary_file /lib64/<libc>.so --output_file patchedlibc.so --disable_nop_sled
sudo cp patchedlibc.so /lib64/patchedlibc.so
```

Now, arbitrary programs can be run with the system calls issued by the libc being dispatched and handled by libgyroid as follows:

```
LD_PRELOAD="/lib64/patchedlibc.so" <executable file>
```
