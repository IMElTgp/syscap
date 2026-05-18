# syscap

`syscap` is a small eBPF-based syscall observer for a target (Docker) container.

It attaches to `raw_syscalls/sys_enter` and `raw_syscalls/sys_exit`, correlates the two sides of a syscall with a per-thread in-flight map, and prints completed syscall events for the specified container during a capture window.

## What It Does

`syscap` currently implements:

- Container-scoped syscall collection using the container's `cgroup_id`
- `sys_enter` and `sys_exit` correlation by thread ID
- Per-event output with:
  - host `pid`, `tid`, `ppid`, `uid`
  - syscall ID
  - enter and exit timestamps
  - syscall duration in nanoseconds
  - return value and derived `errno`
  - thread `comm`
  - raw syscall arguments (`args[6]`)
- A final summary of distinct syscalls observed during the capture session

## How Container Scoping Works

The tool resolves the target container's init PID with `docker inspect`, reads that process's cgroup path from `/proc/<pid>/cgroup`, and uses the cgroup directory inode as the container's `cgroup_id`.

Each syscall event carries the current task's `cgroup_id`, and user space keeps only events that match the target container.

## Requirements

- Linux
- Docker
- Root privileges for loading and attaching eBPF programs
- `cgroup v2`
- Go toolchain

## Build

Generate the eBPF bindings and build the binary:

```bash
# bash build.sh
go generate ./...
go build -o syscap .
```

## Usage

Run `syscap` with a container ID:

```bash
sudo ./syscap --container-id <container-id>
```

The program runs for up to 60 seconds by default, or until interrupted with `Ctrl+C`.

## Output

Each printed line represents one completed syscall observed from the target container:

```text
pid=208126 tid=208126 uid=0 ppid=207122 syscall_id=257 ts_ns_enter=17209363377129 ts_ns_exit=17209363385440 duration(ns)=8311 ret=3 comm=ls args=[4294967196 140653523757952 524288 0 524288 140653523757952]
```

Field meanings:

- `pid`: host process ID (`tgid`)
- `tid`: host thread ID
- `uid`: caller UID
- `ppid`: host parent PID
- `syscall_id`: raw syscall number
- `ts_ns_enter`: timestamp captured at `sys_enter`
- `ts_ns_exit`: timestamp captured at `sys_exit`
- `duration(ns)`: `ts_ns_exit - ts_ns_enter`
- `ret`: syscall return value
- `comm`: thread name
- `args`: raw syscall argument slots as captured at `sys_enter`

At shutdown, `syscap` also prints the distinct syscall names observed for the target container during the session.

## Notes

- Syscall IDs and names in this project are based on the local `x86_64` syscall table.
- `args[6]` are exposed as raw argument slots; their meaning depends on the syscall.
