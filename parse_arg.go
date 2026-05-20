/**
 * parse_arg.go
 * all code in this file is completely **vibe coded**,
 * because it is almost impossible to hand-write such code.
 */

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type namedValue struct {
	Name  string
	Value uint64
}

// FormatParsedArguments formats one syscall's raw args into a human-readable
// text form such as "family=AF_NETLINK, type=SOCK_RAW".
//
// This function intentionally derives argument names from syscallFields in
// syscalls.go so later argument work stays aligned with that source of truth.
func FormatParsedArguments(syscallName string, rawArgs [6]uint64) string {
	fields, ok := syscallFields[syscallName]
	if !ok || len(fields) == 0 {
		return ""
	}

	parts := make([]string, 0, len(fields))
	for idx, fieldDecl := range fields {
		argName := argumentName(fieldDecl)
		parts = append(parts, fmt.Sprintf("%s=%s", argName, ParseArgumentValue(syscallName, idx, rawArgs[idx])))
	}
	return strings.Join(parts, ", ")
}

// ParseArgumentValue converts a raw syscall argument into a readable string.
// It is intended to be called by main.go's formatArgumentText later.
func ParseArgumentValue(syscallName string, argIndex int, raw uint64) string {
	fields, ok := syscallFields[syscallName]
	if !ok || argIndex < 0 || argIndex >= len(fields) {
		return strconv.FormatUint(raw, 10)
	}

	fieldName := argumentName(fields[argIndex])
	return parseArgumentValueByField(syscallName, fieldName, raw)
}

func parseArgumentValueByField(syscallName, fieldName string, raw uint64) string {
	switch syscallName {
	case "socket":
		switch fieldName {
		case "family":
			return decodeExact(raw, socketFamilies)
		case "type":
			return decodeSocketType(raw)
		}
	case "clone":
		if fieldName == "clone_flags" {
			return decodeCloneFlags(raw)
		}
	case "unshare":
		if fieldName == "unshare_flags" {
			return decodeBitmask(raw, namespaceFlags, "")
		}
	case "mmap":
		switch fieldName {
		case "prot":
			return decodeBitmask(raw, mmapProtections, "PROT_NONE")
		case "flags":
			return decodeBitmask(raw, mmapFlags, "")
		}
	case "mprotect", "pkey_mprotect":
		if fieldName == "prot" {
			return decodeBitmask(raw, mmapProtections, "PROT_NONE")
		}
	case "open", "openat":
		if fieldName == "flags" {
			return decodeOpenFlags(raw)
		}
	case "ptrace":
		if fieldName == "request" {
			return decodeExact(raw, ptraceRequests)
		}
	case "bpf":
		if fieldName == "cmd" {
			return decodeExact(raw, bpfCommands)
		}
	case "seccomp":
		switch fieldName {
		case "op":
			return decodeExact(raw, seccompOperations)
		case "flags":
			return decodeBitmask(raw, seccompFlags, "0")
		}
	case "prctl":
		if fieldName == "option" {
			return decodeExact(raw, prctlOptions)
		}
	}

	return strconv.FormatUint(raw, 10)
}

func argumentName(fieldDecl string) string {
	parts := strings.Fields(fieldDecl)
	if len(parts) == 0 {
		return fieldDecl
	}
	return strings.TrimLeft(parts[len(parts)-1], "*")
}

func decodeExact(raw uint64, table map[uint64]string) string {
	if name, ok := table[raw]; ok {
		return name
	}
	return strconv.FormatUint(raw, 10)
}

func decodeBitmask(raw uint64, defs []namedValue, zeroName string) string {
	if raw == 0 && zeroName != "" {
		return zeroName
	}

	names := make([]string, 0)
	remaining := raw
	for _, def := range defs {
		if def.Value == 0 {
			continue
		}
		if remaining&def.Value == def.Value {
			names = append(names, def.Name)
			remaining &^= def.Value
		}
	}

	sort.Strings(names)
	if remaining != 0 {
		names = append(names, fmt.Sprintf("0x%x", remaining))
	}
	if len(names) == 0 {
		return strconv.FormatUint(raw, 10)
	}
	return strings.Join(names, "|")
}

func decodeSocketType(raw uint64) string {
	const sockTypeMask uint64 = 0xf

	baseType := raw & sockTypeMask
	remaining := raw &^ sockTypeMask

	names := make([]string, 0, 3)
	if name, ok := socketTypes[baseType]; ok {
		names = append(names, name)
	}

	extras := make([]string, 0, 2)
	if remaining&sockNonblock == sockNonblock {
		extras = append(extras, "SOCK_NONBLOCK")
		remaining &^= sockNonblock
	}
	if remaining&sockCloexec == sockCloexec {
		extras = append(extras, "SOCK_CLOEXEC")
		remaining &^= sockCloexec
	}

	names = append(names, extras...)
	sort.Strings(names)
	if remaining != 0 {
		names = append(names, fmt.Sprintf("0x%x", remaining))
	}
	if len(names) == 0 {
		return strconv.FormatUint(raw, 10)
	}
	return strings.Join(names, "|")
}

func decodeOpenFlags(raw uint64) string {
	const oAccmode uint64 = 0x3

	names := make([]string, 0, 8)
	switch raw & oAccmode {
	case 0:
		names = append(names, "O_RDONLY")
	case 1:
		names = append(names, "O_WRONLY")
	case 2:
		names = append(names, "O_RDWR")
	default:
		names = append(names, fmt.Sprintf("0x%x", raw&oAccmode))
	}

	remaining := raw &^ oAccmode
	if remaining&oTmpfile == oTmpfile {
		names = append(names, "O_TMPFILE")
		remaining &^= oTmpfile
	}
	if remaining&oSync == oSync {
		names = append(names, "O_SYNC")
		remaining &^= oSync
	}

	extras := make([]string, 0)
	for _, def := range openFlagBits {
		if remaining&def.Value == def.Value {
			extras = append(extras, def.Name)
			remaining &^= def.Value
		}
	}

	names = append(names, extras...)
	sort.Strings(names)
	if remaining != 0 {
		names = append(names, fmt.Sprintf("0x%x", remaining))
	}
	return strings.Join(names, "|")
}

func decodeCloneFlags(raw uint64) string {
	const exitSignalMask uint64 = 0xff

	names := make([]string, 0, 8)
	remaining := raw

	exitSignal := raw & exitSignalMask
	remaining &^= exitSignalMask
	if exitSignal != 0 {
		names = append(names, fmt.Sprintf("SIGNAL_%d", exitSignal))
	}

	for _, def := range cloneFlags {
		if remaining&def.Value == def.Value {
			names = append(names, def.Name)
			remaining &^= def.Value
		}
	}

	sort.Strings(names)
	if remaining != 0 {
		names = append(names, fmt.Sprintf("0x%x", remaining))
	}
	if len(names) == 0 {
		return strconv.FormatUint(raw, 10)
	}
	return strings.Join(names, "|")
}

const (
	sockNonblock = 0x800
	sockCloexec  = 0x80000

	oCreat     = 0x40
	oExcl      = 0x80
	oNoctty    = 0x100
	oTrunc     = 0x200
	oAppend    = 0x400
	oNonblock  = 0x800
	oDsync     = 0x1000
	oAsync     = 0x2000
	oDirect    = 0x4000
	oLarge     = 0x8000
	oDirectory = 0x10000
	oNofollow  = 0x20000
	oNoatime   = 0x40000
	oCloexec   = 0x80000
	oSync      = 0x101000
	oPath      = 0x200000
	oTmpfile   = 0x410000
)

var socketFamilies = map[uint64]string{
	0:  "AF_UNSPEC",
	1:  "AF_UNIX",
	2:  "AF_INET",
	10: "AF_INET6",
	16: "AF_NETLINK",
	17: "AF_PACKET",
}

var socketTypes = map[uint64]string{
	1:  "SOCK_STREAM",
	2:  "SOCK_DGRAM",
	3:  "SOCK_RAW",
	4:  "SOCK_RDM",
	5:  "SOCK_SEQPACKET",
	6:  "SOCK_DCCP",
	10: "SOCK_PACKET",
}

var namespaceFlags = []namedValue{
	{"CLONE_NEWCGROUP", 0x02000000},
	{"CLONE_NEWIPC", 0x08000000},
	{"CLONE_NEWNET", 0x40000000},
	{"CLONE_NEWNS", 0x00020000},
	{"CLONE_NEWPID", 0x20000000},
	{"CLONE_NEWUSER", 0x10000000},
	{"CLONE_NEWUTS", 0x04000000},
}

var mmapProtections = []namedValue{
	{"PROT_EXEC", 0x4},
	{"PROT_GROWSDOWN", 0x01000000},
	{"PROT_GROWSUP", 0x02000000},
	{"PROT_READ", 0x1},
	{"PROT_SEM", 0x8},
	{"PROT_WRITE", 0x2},
}

var mmapFlags = []namedValue{
	{"MAP_32BIT", 0x40},
	{"MAP_ANONYMOUS", 0x20},
	{"MAP_DENYWRITE", 0x800},
	{"MAP_EXECUTABLE", 0x1000},
	{"MAP_FAILED", 0x0},
	{"MAP_FIXED", 0x10},
	{"MAP_FIXED_NOREPLACE", 0x100000},
	{"MAP_GROWSDOWN", 0x100},
	{"MAP_HUGETLB", 0x40000},
	{"MAP_LOCKED", 0x2000},
	{"MAP_NONBLOCK", 0x10000},
	{"MAP_NORESERVE", 0x4000},
	{"MAP_POPULATE", 0x8000},
	{"MAP_PRIVATE", 0x02},
	{"MAP_SHARED", 0x01},
	{"MAP_STACK", 0x20000},
	{"MAP_SYNC", 0x80000},
}

var openFlagBits = []namedValue{
	{"O_APPEND", oAppend},
	{"O_ASYNC", oAsync},
	{"O_CLOEXEC", oCloexec},
	{"O_CREAT", oCreat},
	{"O_DIRECT", oDirect},
	{"O_DIRECTORY", oDirectory},
	{"O_DSYNC", oDsync},
	{"O_EXCL", oExcl},
	{"O_LARGEFILE", oLarge},
	{"O_NOATIME", oNoatime},
	{"O_NOCTTY", oNoctty},
	{"O_NOFOLLOW", oNofollow},
	{"O_NONBLOCK", oNonblock},
	{"O_PATH", oPath},
	{"O_TRUNC", oTrunc},
}

var cloneFlags = []namedValue{
	{"CLONE_CHILD_CLEARTID", 0x00200000},
	{"CLONE_CHILD_SETTID", 0x01000000},
	{"CLONE_FILES", 0x00000400},
	{"CLONE_FS", 0x00000200},
	{"CLONE_IO", 0x80000000},
	{"CLONE_NEWCGROUP", 0x02000000},
	{"CLONE_NEWIPC", 0x08000000},
	{"CLONE_NEWNET", 0x40000000},
	{"CLONE_NEWNS", 0x00020000},
	{"CLONE_NEWPID", 0x20000000},
	{"CLONE_NEWUSER", 0x10000000},
	{"CLONE_NEWUTS", 0x04000000},
	{"CLONE_PARENT", 0x00008000},
	{"CLONE_PARENT_SETTID", 0x00100000},
	{"CLONE_PTRACE", 0x00002000},
	{"CLONE_SETTLS", 0x00080000},
	{"CLONE_SIGHAND", 0x00000800},
	{"CLONE_SYSVSEM", 0x00040000},
	{"CLONE_THREAD", 0x00010000},
	{"CLONE_UNTRACED", 0x00800000},
	{"CLONE_VFORK", 0x00004000},
	{"CLONE_VM", 0x00000100},
}

var ptraceRequests = map[uint64]string{
	0:      "PTRACE_TRACEME",
	1:      "PTRACE_PEEKTEXT",
	2:      "PTRACE_PEEKDATA",
	3:      "PTRACE_PEEKUSER",
	4:      "PTRACE_POKETEXT",
	5:      "PTRACE_POKEDATA",
	6:      "PTRACE_POKEUSER",
	7:      "PTRACE_CONT",
	8:      "PTRACE_KILL",
	9:      "PTRACE_SINGLESTEP",
	12:     "PTRACE_GETREGS",
	13:     "PTRACE_SETREGS",
	14:     "PTRACE_GETFPREGS",
	15:     "PTRACE_SETFPREGS",
	16:     "PTRACE_ATTACH",
	17:     "PTRACE_DETACH",
	24:     "PTRACE_SYSCALL",
	0x4200: "PTRACE_SETOPTIONS",
	0x4201: "PTRACE_GETEVENTMSG",
	0x4202: "PTRACE_GETSIGINFO",
	0x4203: "PTRACE_SETSIGINFO",
	0x4204: "PTRACE_GETREGSET",
	0x4205: "PTRACE_SETREGSET",
	0x4206: "PTRACE_SEIZE",
	0x4207: "PTRACE_INTERRUPT",
	0x4208: "PTRACE_LISTEN",
	0x4209: "PTRACE_PEEKSIGINFO",
	0x420a: "PTRACE_GETSIGMASK",
	0x420b: "PTRACE_SETSIGMASK",
	0x420d: "PTRACE_SECCOMP_GET_METADATA",
	0x420e: "PTRACE_GET_SYSCALL_INFO",
}

var bpfCommands = map[uint64]string{
	0:  "BPF_MAP_CREATE",
	1:  "BPF_MAP_LOOKUP_ELEM",
	2:  "BPF_MAP_UPDATE_ELEM",
	3:  "BPF_MAP_DELETE_ELEM",
	4:  "BPF_MAP_GET_NEXT_KEY",
	5:  "BPF_PROG_LOAD",
	6:  "BPF_OBJ_PIN",
	7:  "BPF_OBJ_GET",
	8:  "BPF_PROG_ATTACH",
	9:  "BPF_PROG_DETACH",
	10: "BPF_PROG_TEST_RUN",
	11: "BPF_PROG_GET_NEXT_ID",
	12: "BPF_MAP_GET_NEXT_ID",
	13: "BPF_PROG_GET_FD_BY_ID",
	14: "BPF_MAP_GET_FD_BY_ID",
	15: "BPF_OBJ_GET_INFO_BY_FD",
	16: "BPF_PROG_QUERY",
	17: "BPF_RAW_TRACEPOINT_OPEN",
	18: "BPF_BTF_LOAD",
	19: "BPF_BTF_GET_FD_BY_ID",
	20: "BPF_TASK_FD_QUERY",
	21: "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
	22: "BPF_MAP_FREEZE",
	23: "BPF_BTF_GET_NEXT_ID",
	24: "BPF_MAP_LOOKUP_BATCH",
	25: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
	26: "BPF_MAP_UPDATE_BATCH",
	27: "BPF_MAP_DELETE_BATCH",
	28: "BPF_LINK_CREATE",
	29: "BPF_LINK_UPDATE",
	30: "BPF_LINK_GET_FD_BY_ID",
	31: "BPF_LINK_GET_NEXT_ID",
	32: "BPF_ENABLE_STATS",
	33: "BPF_ITER_CREATE",
	34: "BPF_LINK_DETACH",
	35: "BPF_PROG_BIND_MAP",
	36: "BPF_TOKEN_CREATE",
}

var seccompOperations = map[uint64]string{
	0: "SECCOMP_SET_MODE_STRICT",
	1: "SECCOMP_SET_MODE_FILTER",
	2: "SECCOMP_GET_ACTION_AVAIL",
	3: "SECCOMP_GET_NOTIF_SIZES",
}

var seccompFlags = []namedValue{
	{"SECCOMP_FILTER_FLAG_LOG", 0x2},
	{"SECCOMP_FILTER_FLAG_NEW_LISTENER", 0x8},
	{"SECCOMP_FILTER_FLAG_SPEC_ALLOW", 0x4},
	{"SECCOMP_FILTER_FLAG_TSYNC", 0x1},
	{"SECCOMP_FILTER_FLAG_TSYNC_ESRCH", 0x10},
	{"SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV", 0x20},
}

var prctlOptions = map[uint64]string{
	1:          "PR_SET_PDEATHSIG",
	2:          "PR_GET_PDEATHSIG",
	3:          "PR_GET_DUMPABLE",
	4:          "PR_SET_DUMPABLE",
	15:         "PR_SET_NAME",
	16:         "PR_GET_NAME",
	21:         "PR_GET_SECCOMP",
	22:         "PR_SET_SECCOMP",
	23:         "PR_CAPBSET_READ",
	24:         "PR_CAPBSET_DROP",
	36:         "PR_SET_CHILD_SUBREAPER",
	37:         "PR_GET_CHILD_SUBREAPER",
	38:         "PR_SET_NO_NEW_PRIVS",
	39:         "PR_GET_NO_NEW_PRIVS",
	40:         "PR_GET_TID_ADDRESS",
	0x59616d61: "PR_SET_PTRACER",
}
