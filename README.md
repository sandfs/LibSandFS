# LibSandFS

LibSandFS is a helper library that provides high-level APIs and
abstractions for developers to write eBPF code for enforcing
custom security checks in the kernel as a part of SandFS.

This library is based on bpf samples found in Linux kernel tree.

# Build kernel

You will need to install and run a kernel with SandFS support
to test this library. To clone the kernel sources do:

```
$ git clone https://github.com/sandfs/SandFS-Kernel
$ cd SandFS-Kernel
$ make menuconfig
    Select 'File systems -> Sandfs sandboxing file system' and save/exit.
$ make -j4
$ sudo make install -j4
```

# Build library

Boot into the new kernel to test LibSandFS. You will also need
LLVM/Clang toolchain with bpf backend to build the library.

```
$ LLC=llc CLANG=clang make
```

* [Open Source Summit, 2019 Presentation](https://static.sched.com/hosted_files/osseu19/20/OSSEUSandFS.pdf)

* [LWN article](https://lwn.net/Articles/803890/)

* If you use this work for your research, we would deep appreciate a citation to our APSys '18 [Paper](https://dl.acm.org/citation.cfm?id=3265734)

```
@inproceedings{Bijlani:2018:LFF:3265723.3265734,
 author = {Bijlani, Ashish and Ramachandran, Umakishore},
 title = {A Lightweight and Fine-grained File System Sandboxing Framework},
 booktitle = {Proceedings of the 9th Asia-Pacific Workshop on Systems},
 year = {2018},
 location = {Jeju Island, Republic of Korea},
 pages = {17:1--17:7},
 numpages = {7},
 publisher = {ACM},
}
```
