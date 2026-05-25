package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// from seenSyscalls

const (
	EPERM        = -1
	ENOENT       = -2
	EAGAIN       = -11
	ENOMEM       = -12
	EACCES       = -13
	EBUSY        = -16
	EEXIST       = -17
	ENOTDIR      = -20
	EINVAL       = -22
	ENFILE       = -23
	EMFILE       = -24
	ENOSYS       = -38
	ENOTSUP      = -95
	EOPNOTSUPP   = -95
	ECONNREFUSED = -111
	EHOSTUNREACH = -113
	EALREADY     = -114
	EINPROGRESS  = -115
	ETIMEDOUT    = -110
	ENETUNREACH  = -101
)

type RiskLevel int

const (
	Critical RiskLevel = iota
	High
	Low
	None
)

func (r RiskLevel) String() string {
	switch r {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Low:
		return "low"
	case None:
		return "none"
	default:
		return "unknown"
	}
}

func (r RiskLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// the lower RiskLevel is, the higher its danger is
type Risk struct {
	RiskLevel RiskLevel `json:"risk_level"`
	// "sensitive", "arg_sensitive", "failing_too_much", "delay_too_high", "abnormal_ret_val"
	RiskCategory   string                  `json:"risk_category"`
	RelatedSyscall string                  `json:"related_syscall"`
	Evidence       string                  `json:"evidence"`
	Snapshot       MetadataForRiskAnalysis `json:"snapshot"`
}

type RiskCollector struct {
	Risks []Risk
}

type SensitiveArgRule struct {
	Pattern *regexp.Regexp
	Reason  string
}

var sensitiveSyscalls = map[string]struct{}{
	"setns":             {},
	"unshare":           {},
	"mount":             {},
	"umount2":           {},
	"pivot_root":        {},
	"move_mount":        {},
	"open_tree":         {},
	"mount_setattr":     {},
	"fsmount":           {},
	"fspick":            {},
	"bpf":               {},
	"ptrace":            {},
	"process_vm_readv":  {},
	"process_vm_writev": {},
	"init_module":       {},
	"finit_module":      {},
	"delete_module":     {},
	"kexec_load":        {},
	"kexec_file_load":   {},
	"perf_event_open":   {},
	"mknod":             {},
	"mknodat":           {},
	"reboot":            {},
	"swapon":            {},
	"swapoff":           {},
	"capset":            {},
}

func (r *RiskCollector) generateFindingForSensitiveSyscall(syscallName string) {
	if !checkIfExistInMap(sensitiveSyscalls, syscallName) {
		return
	}

	r.Risks = append(r.Risks, Risk{
		RiskLevel:      High,
		RiskCategory:   "sensitive",
		RelatedSyscall: syscallName,
		Evidence:       fmt.Sprintf("syscall %s is sensitive in normal containers", syscallName),
		Snapshot:       getInfoFromSyscallName(syscallName),
	})
}

func getInfoFromSyscallName(syscallName string) MetadataForRiskAnalysis {
	return syscallOverallInfo[reversedSyscallTable[syscallName]]
}

func checkSensitiveArg(syscallName string, sensitiveCond ...SensitiveArgRule) (risks []Risk) {
	metadata := getInfoFromSyscallName(syscallName)
	for _, r := range metadata.Running {
		args := r.Arguments
		for _, cond := range sensitiveCond {
			if cond.Pattern.MatchString(args) {
				matchedExpr := cond.Pattern.String()
				riskLevel := RiskLevel(High)
				if checkIfExistInMap(sensitiveSyscalls, syscallName) {
					riskLevel = Critical
				}

				risks = append(risks, Risk{
					RiskLevel:      riskLevel,
					RiskCategory:   "arg_sensitive",
					RelatedSyscall: syscallName,
					Evidence: fmt.Sprintf(
						"pid=%d tid=%d comm=%q duration=%s ret=%d syscall=%s matched=%q reason=%q args=(%s)",
						r.Pid,
						r.Tid,
						r.Comm,
						r.Duration,
						r.ReturnValue,
						r.SyscallName,
						matchedExpr,
						cond.Reason,
						args,
					),
					Snapshot: metadata,
				})
			}
		}
	}
	return
}

func mc(s string) *regexp.Regexp {
	return regexp.MustCompile(s)
}

func sar(pattern, reason string) SensitiveArgRule {
	return SensitiveArgRule{
		Pattern: mc(pattern),
		Reason:  reason,
	}
}

var sensitiveArgSyscalls = map[string][]SensitiveArgRule{
	"socket": {
		sar(`family=AF_PACKET`, "AF_PACKET exposes link-layer packet access and is unusual for ordinary application containers."),
		sar(`family=AF_NETLINK`, "AF_NETLINK talks to kernel networking control paths and is more sensitive than ordinary TCP/UDP traffic."),
		sar(`type=[^,]*SOCK_RAW([^,]*)?$`, "SOCK_RAW allows raw packet construction or inspection and usually deserves extra review in containers."),
	},
	"clone": {
		sar(`clone_flags=[^,]*CLONE_NEWCGROUP([^,]*)?$`, "Creating a new cgroup namespace changes container control boundaries and is uncommon for regular workloads."),
		sar(`clone_flags=[^,]*CLONE_NEWIPC([^,]*)?$`, "Creating a new IPC namespace changes inter-process communication boundaries and is uncommon for regular workloads."),
		sar(`clone_flags=[^,]*CLONE_NEWNET([^,]*)?$`, "Creating a new network namespace is a boundary-changing operation that is usually runtime-managed, not app-managed."),
		sar(`clone_flags=[^,]*CLONE_NEWNS([^,]*)?$`, "Creating a new mount namespace is strongly related to filesystem and isolation boundary changes."),
		sar(`clone_flags=[^,]*CLONE_NEWPID([^,]*)?$`, "Creating a new PID namespace changes process-view boundaries and is unusual in ordinary application containers."),
		sar(`clone_flags=[^,]*CLONE_NEWUSER([^,]*)?$`, "Creating a new user namespace affects UID/GID privilege boundaries and deserves extra review."),
		sar(`clone_flags=[^,]*CLONE_NEWUTS([^,]*)?$`, "Creating a new UTS namespace changes hostname/domain isolation boundaries and is uncommon in ordinary workloads."),
	},
	"unshare": {
		sar(`unshare_flags=[^,]*CLONE_NEWCGROUP([^,]*)?$`, "Unsharing into a new cgroup namespace changes control boundaries and is uncommon for regular workloads."),
		sar(`unshare_flags=[^,]*CLONE_NEWIPC([^,]*)?$`, "Unsharing into a new IPC namespace changes communication boundaries and is uncommon for regular workloads."),
		sar(`unshare_flags=[^,]*CLONE_NEWNET([^,]*)?$`, "Unsharing into a new network namespace changes network isolation boundaries."),
		sar(`unshare_flags=[^,]*CLONE_NEWNS([^,]*)?$`, "Unsharing into a new mount namespace is closely related to filesystem and isolation boundary changes."),
		sar(`unshare_flags=[^,]*CLONE_NEWPID([^,]*)?$`, "Unsharing into a new PID namespace changes process-view boundaries and deserves extra review."),
		sar(`unshare_flags=[^,]*CLONE_NEWUSER([^,]*)?$`, "Unsharing into a new user namespace affects privilege boundaries and deserves extra review."),
		sar(`unshare_flags=[^,]*CLONE_NEWUTS([^,]*)?$`, "Unsharing into a new UTS namespace changes hostname/domain isolation boundaries."),
	},
	"mmap": {
		sar(`prot=[^,]*PROT_EXEC([^,]*)?$`, "Executable memory mappings are more sensitive than ordinary data mappings and may support loaders, JITs, or injection-style behavior."),
		sar(`prot=[^,]*PROT_EXEC[^,]*PROT_WRITE([^,]*)?$`, "Writable and executable memory at the same time is a classic high-signal pattern for code loading or injection paths."),
	},
	"mprotect": {
		sar(`prot=[^,]*PROT_EXEC([^,]*)?$`, "Changing memory protections to executable is more sensitive than ordinary protection changes."),
		sar(`prot=[^,]*PROT_EXEC[^,]*PROT_WRITE([^,]*)?$`, "Changing memory to writable and executable at once is a strong signal for loader or injection-style behavior."),
	},
	"open": {
		sar(`flags=[^,]*O_PATH([^,]*)?$`, "O_PATH is more OS-internal than ordinary file access and may indicate handle-style filesystem probing."),
		sar(`flags=[^,]*O_TMPFILE([^,]*)?$`, "O_TMPFILE creates unnamed temporary files and may indicate stealthier staging behavior."),
		sar(`flags=[^,]*O_CREAT[^,]*O_TRUNC[^,]*O_WRONLY([^,]*)?$`, "Creating, truncating, and opening a file for write in one step is a strong signal of overwrite or file-drop behavior."),
	},
	"openat": {
		sar(`flags=[^,]*O_PATH([^,]*)?$`, "O_PATH is more OS-internal than ordinary file access and may indicate handle-style filesystem probing."),
		sar(`flags=[^,]*O_TMPFILE([^,]*)?$`, "O_TMPFILE creates unnamed temporary files and may indicate stealthier staging behavior."),
		sar(`flags=[^,]*O_CREAT[^,]*O_TRUNC[^,]*O_WRONLY([^,]*)?$`, "Creating, truncating, and opening a file for write in one step is a strong signal of overwrite or file-drop behavior."),
	},
	"ptrace": {
		sar(`request=PTRACE_ATTACH`, "PTRACE_ATTACH indicates one process is trying to attach to another for inspection or control."),
		sar(`request=PTRACE_SEIZE`, "PTRACE_SEIZE is a modern non-stopping attach path and still indicates cross-process tracing intent."),
		sar(`request=PTRACE_POKEDATA`, "PTRACE_POKEDATA attempts to modify another process's memory and is highly sensitive."),
		sar(`request=PTRACE_POKETEXT`, "PTRACE_POKETEXT attempts to modify another process's code or text area and is highly sensitive."),
		sar(`request=PTRACE_SETREGS`, "PTRACE_SETREGS attempts to alter another process's register state and is highly sensitive."),
	},
	"bpf": {
		sar(`cmd=BPF_MAP_CREATE`, "BPF_MAP_CREATE directly uses eBPF kernel facilities and is uncommon in ordinary application containers."),
		sar(`cmd=BPF_PROG_LOAD`, "BPF_PROG_LOAD attempts to load an eBPF program into the kernel and is highly sensitive."),
		sar(`cmd=BPF_LINK_CREATE`, "BPF_LINK_CREATE attempts to attach eBPF objects into kernel execution paths and is highly sensitive."),
	},
	"seccomp": {
		sar(`op=SECCOMP_SET_MODE_FILTER`, "Installing seccomp filter mode changes syscall policy at runtime and is security-relevant."),
		sar(`op=SECCOMP_SET_MODE_STRICT`, "Switching to strict seccomp mode is unusual enough to deserve explicit review."),
		sar(`flags=[^,]*SECCOMP_FILTER_FLAG_LOG([^,]*)?$`, "SECCOMP_FILTER_FLAG_LOG changes seccomp behavior toward logging and indicates active seccomp policy management."),
		sar(`flags=[^,]*SECCOMP_FILTER_FLAG_NEW_LISTENER([^,]*)?$`, "SECCOMP_FILTER_FLAG_NEW_LISTENER sets up a userspace notification path and is more sensitive than ordinary filter installation."),
		sar(`flags=[^,]*SECCOMP_FILTER_FLAG_TSYNC([^,]*)?$`, "SECCOMP_FILTER_FLAG_TSYNC synchronizes policy across threads and indicates broad seccomp policy changes."),
	},
	"prctl": {
		sar(`option=PR_SET_SECCOMP`, "PR_SET_SECCOMP changes seccomp state and is directly security-relevant."),
		sar(`option=PR_SET_NO_NEW_PRIVS`, "PR_SET_NO_NEW_PRIVS changes privilege-transition behavior and is security-relevant."),
		sar(`option=PR_SET_PTRACER`, "PR_SET_PTRACER changes who may trace this process and affects debugging or introspection exposure."),
		sar(`option=PR_SET_DUMPABLE`, "PR_SET_DUMPABLE changes dumpability and can affect ptrace and memory-inspection exposure."),
	},
}

func (r *RiskCollector) syscallHasSensitiveArgs(syscallName string) {
	patterns, ok := sensitiveArgSyscalls[syscallName]
	if !ok {
		return
	}
	r.Risks = append(r.Risks, checkSensitiveArg(syscallName, patterns...)...)
}

const failingRateCeil = 0.4
const minRecordedCalled = 20

func checkFailingTooMuch(syscallName string) bool {
	res := syscallOverallInfo[reversedSyscallTable[syscallName]].Result
	if res.CalledCount < minRecordedCalled || float64(res.FailedCount)/float64(res.CalledCount) < failingRateCeil {
		return false
	}
	return true
}

var sensitiveFailingSyscalls = map[string]struct{}{
	"mount":             {},
	"umount2":           {},
	"setns":             {},
	"unshare":           {},
	"ptrace":            {},
	"process_vm_readv":  {},
	"process_vm_writev": {},
	"bpf":               {},
	"perf_event_open":   {},
	"mknod":             {},
	"mknodat":           {},
	"init_module":       {},
	"finit_module":      {},
	"execve":            {},
	"connect":           {},
	"open":              {},
	"openat":            {},
	"chmod":             {},
	"chown":             {},
	"unlink":            {},
	"unlinkat":          {},
	"rename":            {},
	"renameat":          {},
	"renameat2":         {},
}

func (r *RiskCollector) generateFindingForSyscallsFailingTooMuch(syscallName string) {
	if !checkFailingTooMuch(syscallName) {
		return
	}

	riskLevel := Low
	if checkIfExistInMap(sensitiveFailingSyscalls, syscallName) {
		riskLevel = High
	}

	r.Risks = append(r.Risks, Risk{
		RiskLevel:      riskLevel,
		RiskCategory:   "failing_too_much",
		RelatedSyscall: syscallName,
		Evidence:       fmt.Sprintf("Totally count: %d, failing count: %d", getInfoFromSyscallName(syscallName).Result.CalledCount, getInfoFromSyscallName(syscallName).Result.FailedCount),
		Snapshot:       getInfoFromSyscallName(syscallName),
	})
}

const warningP50delay = 5 * time.Millisecond
const warningP99delay = 50 * time.Millisecond

func checkP50DelayTooLong(syscallName string) bool {
	return syscallOverallInfo[reversedSyscallTable[syscallName]].Result.P50Delay > warningP50delay
}

func checkP99DelayTooLong(syscallName string) bool {
	return syscallOverallInfo[reversedSyscallTable[syscallName]].Result.P99Delay > warningP99delay
}

var delayCriticalSyscalls = map[string]struct{}{
	"open":            {},
	"openat":          {},
	"connect":         {},
	"accept":          {},
	"read":            {},
	"write":           {},
	"fsync":           {},
	"fdatasync":       {},
	"futex":           {},
	"epoll_wait":      {},
	"ppoll":           {},
	"pselect6":        {},
	"execve":          {},
	"clone":           {},
	"mmap":            {},
	"mprotect":        {},
	"mount":           {},
	"umount2":         {},
	"rename":          {},
	"renameat":        {},
	"unlink":          {},
	"unlinkat":        {},
	"bpf":             {},
	"perf_event_open": {},
}

func highDelaySyscallRiskRating(syscallName string) RiskLevel {
	if !checkP50DelayTooLong(syscallName) {
		return None
	}
	if !checkP99DelayTooLong(syscallName) {
		return None
	}
	if checkIfExistInMap(delayCriticalSyscalls, syscallName) {
		return High
	}
	return Low
}

func (r *RiskCollector) generateFindingForHighDelaySyscalls(syscallName string) {
	riskLevel := highDelaySyscallRiskRating(syscallName)
	if riskLevel == None {
		return
	}

	r.Risks = append(r.Risks, Risk{
		RiskLevel:      riskLevel,
		RiskCategory:   "delay_too_high",
		RelatedSyscall: syscallName,
		Evidence:       fmt.Sprintf("P50Delay=%d, P99Delay=%d", getInfoFromSyscallName(syscallName).Result.P50Delay, getInfoFromSyscallName(syscallName).Result.P99Delay),
		Snapshot:       getInfoFromSyscallName(syscallName),
	})
}

var sensitiveSyscallsWithErrno = map[int](map[string]struct{}){
	EPERM: map[string]struct{}{
		"mount":             {},
		"unshare":           {},
		"setns":             {},
		"ptrace":            {},
		"bpf":               {},
		"perf_event_open":   {},
		"mknod":             {},
		"process_vm_writev": {},
	},
	EMFILE: map[string]struct{}{
		"open":   {},
		"openat": {},
		"socket": {},
	},
	ENFILE: map[string]struct{}{
		"open":   {},
		"openat": {},
		"socket": {},
	},
	ENOENT: map[string]struct{}{
		"open":      {},
		"openat":    {},
		"execve":    {},
		"unlink":    {},
		"unlinkat":  {},
		"rename":    {},
		"renameat":  {},
		"renameat2": {},
	},
	ENOMEM: map[string]struct{}{
		"mmap": {},
	},
	EAGAIN: map[string]struct{}{
		"clone": {},
	},
	ECONNREFUSED: map[string]struct{}{
		"connect": {},
	},
	ETIMEDOUT: map[string]struct{}{
		"connect": {},
	},
	ENETUNREACH: map[string]struct{}{
		"connect": {},
	},
	EHOSTUNREACH: map[string]struct{}{
		"connect": {},
	},
}

func (r *RiskCollector) checkAbnormalRetVal(syscallName string) {
	for _, running := range getInfoFromSyscallName(syscallName).Running {
		if !checkIfExistInMap(sensitiveSyscallsWithErrno[int(running.ReturnValue)], syscallName) {
			continue
		}

		var riskLevel RiskLevel

		evidence := ""
		switch running.ReturnValue {
		case EPERM:
			evidence = fmt.Sprintf("syscall %s with return value %d(EPERM) shows it is breaking its priority border", syscallName, EPERM)
			riskLevel = Critical
		case ENOENT:
			evidence = fmt.Sprintf("syscall %s with return value %d(ENOENT) shows it failed to complete file/directory-related operations", syscallName, ENOENT)
			riskLevel = High
		case EMFILE, ENFILE, ENOMEM, EAGAIN:
			evidence = fmt.Sprintf("syscall %s with return value %d(EMFILE/ENFILE/ENOMEM/EAGAIN) shows it may exhaust system resource", syscallName, running.ReturnValue)
			riskLevel = High
		case ECONNREFUSED, ETIMEDOUT, ENETUNREACH, EHOSTUNREACH:
			evidence = fmt.Sprintf("syscall %s with return value %d(ECONNREFUSED/ETIMEDOUT/ENETUNREACH/EHOSTUNREACH) may met issues with net connection", syscallName, running.ReturnValue)
			riskLevel = Low
		default:
			continue
		}

		if checkIfExistInMap(sensitiveSyscalls, syscallName) {
			riskLevel = max(0, riskLevel-1)
		}

		r.Risks = append(r.Risks, Risk{
			RiskLevel:      riskLevel,
			RiskCategory:   "abnormal_ret_val",
			RelatedSyscall: syscallName,
			Evidence:       evidence,
			Snapshot:       getInfoFromSyscallName(syscallName),
		})
	}
}

func generateOverallFinding(syscallName string) []Risk {
	r := &RiskCollector{
		Risks: make([]Risk, 0),
	}

	r.generateFindingForSensitiveSyscall(syscallName)
	r.generateFindingForHighDelaySyscalls(syscallName)
	r.generateFindingForSyscallsFailingTooMuch(syscallName)
	r.syscallHasSensitiveArgs(syscallName)
	r.checkAbnormalRetVal(syscallName)

	return r.Risks
}
