# syscap

`syscap` is a small eBPF-based syscall observer for a target Docker container.

It attaches to `raw_syscalls/sys_enter` and `raw_syscalls/sys_exit`, correlates the two sides of a syscall with a per-thread in-flight map, and records completed syscall events for one target container during a capture window.

## Current Features

`syscap` currently implements:

- Container-scoped syscall collection based on the target container's `cgroup_id`
- eBPF-side filtering so unrelated host syscalls are dropped before they reach user space
- `sys_enter` and `sys_exit` correlation by thread ID
- Per-event recording with:
  - host `pid`, `tid`, `ppid`, `uid`
  - syscall ID and syscall name
  - enter and exit timestamps
  - syscall duration in nanoseconds
  - return value and derived `errno`
  - thread `comm`
  - syscall arguments captured from `sys_enter`
- Named argument output for supported syscalls instead of plain `args[6]`
- Optional syscall-name filtering through `--target-syscall`
- Per-syscall performance summary at shutdown:
  - call count
  - failure count
  - success rate
  - `P50` latency
  - `P99` latency
- Two output files:
  - `running.log` for per-event records
  - `performance.log` for end-of-run summary

## How Container Scoping Works

The tool resolves the target container's init PID with `docker inspect`, reads that process's cgroup path from `/proc/<pid>/cgroup`, and uses the cgroup directory inode as the container's `cgroup_id`.

User space writes that `cgroup_id` into a BPF array map before the programs are attached. The `sys_enter` program compares the current task's `cgroup_id` with the configured target and ignores unmatched events early in the kernel.

## Requirements

- Linux
- Docker
- Root privileges for loading and attaching eBPF programs
- `cgroup v2`
- Go toolchain

## Build

Generate the eBPF bindings and build the binary:

```bash
go generate ./...
go build -o syscap .
```

You can also use the local build helper if you keep it in sync with the repo:

```bash
bash build.sh
```

## Usage

Capture all observed syscalls for one container:

```bash
sudo ./syscap --container-id <container-id>
```

Capture only selected syscall names:

```bash
sudo ./syscap --container-id <container-id> --target-syscall read,write,openat
```

The program runs for up to 60 seconds by default, or until interrupted with `Ctrl+C`.

## Output

During capture, `syscap` writes detailed per-event records into `running.log` and shows a live counter in the terminal.

Example event record:

```text
pid=208126 tid=208126 uid=0 ppid=207122 syscall=openat ts_ns_enter=17209363377129 ts_ns_exit=17209363385440 duration(ns)=8311 ret=3 comm=ls args=[dfd=4294967196, filename=140653523757952, flags=524288, mode=0]
```

Field meanings:

- `pid`: host process ID (`tgid`)
- `tid`: host thread ID
- `uid`: caller UID
- `ppid`: host parent PID
- `syscall`: syscall name
- `ts_ns_enter`: timestamp captured at `sys_enter`
- `ts_ns_exit`: timestamp captured at `sys_exit`
- `duration(ns)`: `ts_ns_exit - ts_ns_enter`
- `ret`: syscall return value
- `comm`: thread name
- `args`: syscall arguments rendered with argument names when available

At shutdown, `syscap` prints and stores a per-syscall summary in `performance.log`.

Example summary:

```text
openat:
    called: 128
    failed: 3
    Success Rate: 0.976562
    P50 delay: 5421
    P99 delay: 34871
```

## Notes

- Syscall IDs and names in this project are based on the local `x86_64` syscall table.
- Argument names are generated from the local tracing metadata and are meant to improve readability, not to fully reconstruct pointed-to user memory.
- Pointer-like arguments are still logged as raw numeric values.
