#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct event {
    __u32 pid;                  // pid of the process that called this syscall
    __u32 tid;                  // tid of the very thread that called this syscall
    __u32 uid;                  // uid of the process that called this syscall
    __u32 syscall_id;           // the identifier of this syscall
    __u32 ppid;                 // parent's pid
    __s32 errno;                // ret < 0 ? ret : 0;

    __s64 ret;          // return value on exiting
    __u64 ts_ns_enter;  // timestamp of this event's entering
    __u64 ts_ns_exit;   // timestamp of this event's exiting
    __u64 cgroup_id;    // inode for the task's cgroup which this event is about 
    
    char comm[TASK_COMM_LEN];   // command name
    __u64 args[6];              // arguments of the traced syscall
};

struct enter_state {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 syscall_id;
    __u32 ppid;
    __s32 _pad;

    __u64 ts_ns_enter;
    __u64 cgroup_id;

    char comm[TASK_COMM_LEN];
    __u64 args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);                 // tid as key
    __type(value, struct enter_state);  // struct enter_state (partially event) as value
} inflight SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int capture_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct enter_state state = {};
    state.pid = bpf_get_current_pid_tgid() >> 32;
    state.tid = (__u32)bpf_get_current_pid_tgid();
    state.uid = (__u32)bpf_get_current_uid_gid();
    state.cgroup_id = bpf_get_current_cgroup_id();
    state.ts_ns_enter = bpf_ktime_get_ns();
    state.syscall_id = ctx->id;

    struct task_struct *task = bpf_get_current_task_btf();
    state.ppid = BPF_CORE_READ(task, real_parent, pid);

    if (bpf_get_current_comm(state.comm, sizeof(state.comm)) < 0) {
        return 0;
    }

    state.args[0] = ctx->args[0];
    state.args[1] = ctx->args[1];
    state.args[2] = ctx->args[2];
    state.args[3] = ctx->args[3];
    state.args[4] = ctx->args[4];
    state.args[5] = ctx->args[5];

    bpf_map_update_elem(&inflight, &state.tid, &state, BPF_ANY);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int capture_sys_exit(struct trace_event_raw_sys_exit *ctx)  
{
    struct event *event = {};
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->ret = ctx->ret;
    event->ts_ns_exit = bpf_ktime_get_ns();
    event->errno = event->ret < 0 ? -event->ret : 0;

    const __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct enter_state *state = bpf_map_lookup_elem(&inflight, &tid);
    if (!state) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    event->pid = state->pid;
    event->tid = state->tid;
    event->uid = state->uid;
    event->ppid = state->ppid;
    event->cgroup_id = state->cgroup_id;
    event->syscall_id = state->syscall_id;
    event->ts_ns_enter = state->ts_ns_enter;

    __builtin_memcpy(event->comm, state->comm, sizeof(state->comm));
    __builtin_memcpy(event->args, state->args, sizeof(state->args));

    bpf_map_delete_elem(&inflight, &tid);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
