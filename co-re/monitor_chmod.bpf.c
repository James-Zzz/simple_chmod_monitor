`#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor_chmod.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * Use following method to fetch event you want to probe:
 *
 * #cat /proc/kallsyms | grep fchmodat
 * 0000000000000000 t do_fchmodat
 *
 *
 * Failed to monitor sys_enter_fchmodat:
 * sudo ls /sys/kernel/debug/tracing/events/syscalls
 * SEC("tracepoint/raw_syscalls/sys_enter_fchmodat")
 * Got following error message:
 * libbpf: prog 'sys_fchmodat': failed to attach to pfd 6: Permission denied
 * libbpf: prog 'sys_fchmodat': failed to attach to tracepoint
 *         'syscalls/sys_enter_fchmodat': Permission denied
 * libbpf: failed to auto-attach program 'sys_fchmodat': -13
 * failed to attach BPF programs
 */
SEC("kprobe/do_fchmodat")
int sys_fchmodat(struct pt_regs *ctx) {
    const char *file_name = (void *)&PT_REGS_PARM2(ctx);
    umode_t mode = PT_REGS_PARM3(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};
    const char *argp;

    data.pid = pid;
    data.mode = mode;
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_core_read(&argp, sizeof(argp), file_name);
    if (argp) {
        bpf_core_read_user_str(&data.path, sizeof(data.path), argp);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
