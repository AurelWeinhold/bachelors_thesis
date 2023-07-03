Bachelors Thesis
===

This is the repository of my, Aurel Weinhold, Bachelors Thesis.

To bootstrap the eBPF filter and user space application,
[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap.git) is used.


## Running

To execute the server:
```shell
$ sudo ./server/thesis[_ebpf|_userspace] ifindex port
```
- Find `ifindex` by running `ip link show` and select the appropriate interface.
- `port`, the port you want to block all IPv4, TCP traffic on.
- `sudo` is needed, as the server attaches the eBPF program to the kernel.

To execute the client:
```
$ ./client/client[_clock] ip port nrThreads nrPackets [threadId]
```
This runs the client starting `nrThreads` threads each sending `nrPackets`
packets to the server at `ip`@`port`. An optional thread ID can be given for
debugging.


## Building

### Install Dependencies

- Linux kernel >= 5.15, but it is tested on the latest kernel distributed by
  Arch.
- `clang`
- `libelf`
- `zlib`

Package names may vary across Linux distributions.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```
## Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/AurelWeinhold/bachelors_thesis
```


### Build

```shell
$ git submodule update --init --recursive       # check out libbpf
$ mkdir build && cd build
$ cmake ..
$ make
```

This creates two new directories in `build`, client and server, and five
executables:
| executable                | description                                                            |
| ------------------------- | ---------------------------------------------------------------------- |
| `server/thesis`           | The server application in the "mixed" configuration.                   |
| `server/thesis_ebpf`      | The server application in the "ebpf-only" configuration.               |
| `server/thesis_userspace` | The server application in the "user-space-only" configuration.         |
| `client/client`           | The regular client                                                     |
| `client/client_clock`     | The regular client, but it prints the clock time measured to `stdout`. |

### Debugging

To print message inside the eBPF program use `bpf_printk` and inspect the prints
by using `$ sudo cat /sys/kernel/debug/tracing/trace_pipe`.
