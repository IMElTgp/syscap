package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func main() {
	fmt.Println("hello, syscap")

	if err := run(); err != nil {
		fmt.Println(err.Error())
		return
	}
}

func init() {
	initTable()
}

type Config struct {
	ContainerID   string
	TargetSyscall string
}

func parseArgs(args []string) (Config, error) {
	var cfg Config
	fs := flag.NewFlagSet("syscap", flag.ContinueOnError)

	fs.StringVar(&cfg.ContainerID, "container-id", "", "target container ID")
	fs.StringVar(&cfg.TargetSyscall, "target-syscall", "", "target syscall name")

	if err := fs.Parse(args); err != nil {
		return cfg, fmt.Errorf("failed to parse arguments: %w", err)
	}

	if err := validateArgs(cfg, fs.Args()); err != nil {
		return cfg, fmt.Errorf("including invalid arguments: %w", err)
	}

	return cfg, nil
}

func validateArgs(cfg Config, rest []string) error {
	if cfg.ContainerID == "" {
		return fmt.Errorf("Usage: ./syscap --container-id <containerID> (--target-syscall <syscall name 1>,<syscall name 2>,...)")
	}

	if strings.ContainsAny(cfg.TargetSyscall, "\t\n\r") {
		return fmt.Errorf("invalid --target-syscall %q: syscall name must not contain whitespace", cfg.TargetSyscall)
	}

	if len(rest) != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", rest)
	}

	return nil
}

func splitSupportedSyscallFilter(targetSyscalls string) (syscalls map[string]struct{}) {
	syscalls = make(map[string]struct{})
	parts := strings.Split(targetSyscalls, ",")
	for _, syscall := range parts {
		syscalls[syscall] = struct{}{}
	}
	return
}

func checkIfExistInMap(m map[string]struct{}, elem string) bool {
	_, ok := m[elem]
	return ok
}

func run() error {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		return fmt.Errorf("failed to parse arguments: %w", err)
	}
	containerID, targetSyscall := cfg.ContainerID, cfg.TargetSyscall

	cgroupID, err := resolveCgroupID(containerID)
	if err != nil {
		return fmt.Errorf("failed to resolve cgroup ID: %w", err)
	}

	seenSyscalls := make(map[uint32]struct{})
	syscalls := splitSupportedSyscallFilter(targetSyscall)

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove mem lock: %w", err)
	}

	obj := programObjects{}
	if err := loadProgramObjects(&obj, nil); err != nil {
		return fmt.Errorf("failed to load object: %w", err)
	}
	defer obj.Close()

	if err := obj.CgroupIdMap.Update(uint32(0), cgroupID, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to ship parsed cgroup ID to the eBPF program: %w", err)
	}

	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", obj.programPrograms.CaptureSysEnter, nil)
	if err != nil {
		return fmt.Errorf("failed to attach to enter tracepoint: %w", err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", obj.CaptureSysExit, nil)
	if err != nil {
		return fmt.Errorf("failed to attach to exit tracepoint: %w", err)
	}
	defer tpExit.Close()

	ctxSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rd, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader: %w", err)
	}
	defer rd.Close()

	go func() {
		select {
		case <-ctx.Done():
			fmt.Println("Program terminated after running for 60 seconds")
		case <-ctxSignal.Done():
			fmt.Println("\nProgram terminated with Ctrl+C caught")
		}
		fmt.Println("Syscalls this container called during this term of obversation: ")
		for syscallID := range seenSyscalls {
			fmt.Print(syscallTable[int(syscallID)] + ", ")

		}
		fmt.Println()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("ringbuf reader failed to read: %w", err)
		}

		var event Event

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("failed to decode record from ringbuf reader: %w", err)
		}

		comm := unix.ByteSliceToString(event.Comm[:])
		seenSyscalls[event.SyscallID] = struct{}{}

		if targetSyscall == "" || checkIfExistInMap(syscalls, syscallTable[int(event.SyscallID)]) {
			fmt.Printf("pid=%d tid=%d uid=%d ppid=%d syscall=%s ts_ns_enter=%d ts_ns_exit=%d duration(ns)=%d ret=%d comm=%s args=%v\n", event.Pid, event.Tid, event.Uid, event.Ppid, syscallTable[int(event.SyscallID)], event.TimeStampEnter, event.TimeStampExit, event.TimeStampExit-event.TimeStampEnter, event.Ret, comm, event.Args)
		}
	}
}

func extractPID(containerID string) (pid int, err error) {
	if containerID == "" {
		return -1, fmt.Errorf("container ID provided is empty, cannot extract container main process ID")
	}

	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID).Output()
	if err != nil {
		return -1, fmt.Errorf("failed to extract main process ID of container %s: %w", containerID, err)
	}

	pid, err = strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return -1, fmt.Errorf("met error while processing extracted main process ID: %w", err)
	}

	return
}

func resolveCgroupPath(containerID string) (string, error) {
	pid, err := extractPID(containerID)
	if err != nil {
		return "", fmt.Errorf("resolving cgroup path failed: %w", err)
	}

	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", fmt.Errorf("resolving cgroup path failed: %w", err)
	}
	defer f.Close()

	var buf = bufio.NewReader(f)
	cgroupPath, err := buf.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("resolving cgroup path failed: %w", err)
	}

	parts := strings.SplitN(cgroupPath, ":", 3)
	return strings.TrimSpace(filepath.Join("/sys/fs/cgroup", parts[2])), nil
}

func resolveCgroupID(containerID string) (uint64, error) {
	// cgroup ID is just its inode
	cgroupPath, err := resolveCgroupPath(containerID)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve cgroup path: %w", err)
	}

	info, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, fmt.Errorf("failed to stat cgroup path: %w", err)
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to get stat_t for %s: %w", cgroupPath, err)
	}

	return st.Ino, nil
}
