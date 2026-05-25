#include "vmlinux.h"
#include "map.c"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

// event is sent to the user end as it carries all necessary metadata
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
    __u64 deref_args[6];        // arguments dereferenced by reading the user-side address space
};

// enter_state is used for passing partial information between sys_enter and sys_exit 
// handlers
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
    __u64 deref_args[6];
};

// events is a ringbuf used to communicate between user and kernel ends
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// inflight is an eBPF hash map used to communicate between sys_enter and sys_exit
// handlers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);                 // tid as key
    __type(value, struct enter_state);  // struct enter_state (partially event) as value
} inflight SEC(".maps");

// cgroup_id_map is an eBPF array used to ship parsed cgroup ID from user end
// to kernel end for early filtering
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cgroup_id_map SEC(".maps");

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

    __u32 key = 0;
    __u64 *target_cgroup_id = bpf_map_lookup_elem(&cgroup_id_map, &key);
    if (target_cgroup_id && *target_cgroup_id != state.cgroup_id) {
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    state.ppid = BPF_CORE_READ(task, real_parent, pid);

    if (bpf_get_current_comm(state.comm, sizeof(state.comm)) < 0) {
        return 0;
    }

    // check syscall_ptr_args here, and fill real data in that address if the argument is actually a pointer
    state.args[0] = ctx->args[0];
    state.args[1] = ctx->args[1];
    state.args[2] = ctx->args[2];
    state.args[3] = ctx->args[3];
    state.args[4] = ctx->args[4];
    state.args[5] = ctx->args[5];

    for (int i = 0; i < 6; ++i) {
        state.deref_args[i] = 0;
    }

    for (int i = 0; i < 6; ++i) {
        if (state.syscall_id >= (sizeof(syscall_ptr_args)) / sizeof(__u8)) {
            return 0;
        }

        if (syscall_ptr_args[state.syscall_id] & (1U << i)) {
            // here, buffers in arguments may have their data be 0, because 
            // buffer value is determined on exit
            if (bpf_probe_read_user(&state.deref_args[i], sizeof(state.deref_args[i]), (const void *)state.args[i]) < 0) {
                continue;
            }
        }
    }

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
    __builtin_memcpy(event->deref_args, state->deref_args, sizeof(state->deref_args));

    // a kind-of-rough solution on buffer arguments
    // if one of the dereferenced pointer arguments is 0, it represents:
    // 1. the reading activity failed and returned with return value < 0;
    // 2. the actual data is really 0;
    // 3. the argument is actually a buffer.

    // for 1. , try once more reading, making it a best-effort reading activity;
    // for 2. , the second attempt is expected to get 0 again, so it doesn't matter
    // as well;
    // for 3. , if the argument is a buffer, we may get the real data this time.
    for (int i = 0; i < 6; ++i) {
        if (event->deref_args[i] != 0) {
            continue;
        }
        if (event->syscall_id >= (sizeof(syscall_ptr_args)) / (sizeof(__u8))) {
            bpf_ringbuf_discard(event, 0);
            return 0;
        }

        if (syscall_ptr_args[event->syscall_id] & (1U << i)) {
            if (event->deref_args[i] != 0) {
                continue;
            }
            if (bpf_probe_read_user(&event->deref_args[i], sizeof(event->deref_args[i]), (const void *)state->args[i]) < 0) {
                continue;
            }
        }
    }

    bpf_map_delete_elem(&inflight, &tid);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
