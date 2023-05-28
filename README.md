Bachelors Thesis
===

This is the repository of my, Aurel Weinhold, Bachelors Thesis.

To bootstrap the eBPF filter and user space application,
[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap.git) is used.


## Running

To run simply run the executable with `sudo`:
```shell
$ sudo ./thesis ifindex port
```
Find `ifindex` by running `ip link show` and select the appropriate interface.

`port`, the port you want to block all IPv4, TCP traffic on.


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
$ git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
```


### Build

```shell
$ git submodule update --init --recursive       # check out libbpf
$ mkdir build && cd build
$ cmake ../src
$ make
```


## Troubleshooting

Libbpf debug logs are quite helpful to pinpoint the exact source of problems, so
it's usually a good idea to look at them before starting to debug or posting
question online.

`./minimal` is always running with libbpf debug logs turned on.

For `./bootstrap`, run it in verbose mode (`-v`) to see libbpf debug logs:

```shell
$ sudo ./bootstrap -v
libbpf: loading object 'bootstrap_bpf' from buffer
libbpf: elf: section(2) tp/sched/sched_process_exec, size 384, link 0, flags 6, type=1
libbpf: sec 'tp/sched/sched_process_exec': found program 'handle_exec' at insn offset 0 (0 bytes), code size 48 insns (384 bytes)
libbpf: elf: section(3) tp/sched/sched_process_exit, size 432, link 0, flags 6, type=1
libbpf: sec 'tp/sched/sched_process_exit': found program 'handle_exit' at insn offset 0 (0 bytes), code size 54 insns (432 bytes)
libbpf: elf: section(4) license, size 13, link 0, flags 3, type=1
libbpf: license of bootstrap_bpf is Dual BSD/GPL
...
```

### Debugging

To print message inside the eBPF program use `bpf_printk` and inspect the prints
by using `$ sudo cat /sys/kernel/debug/tracing/trace_pipe`.
