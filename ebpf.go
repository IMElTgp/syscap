//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb program ./bpf/program.bpf.c -- -I./bpf

package main

type Event struct {
	Pid, Tid, Uid, SyscallID, Ppid          uint32
	Errno                                   int32
	Ret                                     int64
	TimeStampEnter, TimeStampExit, CgroupID uint64

	Comm [16]byte
	Args [6]uint64
}
