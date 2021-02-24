#include <vmlinux.h>
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
 * Use following method to fetch syscall you want to probe:
 *
 * #cat /proc/kallsyms | grep fchmodat
 * 0000000000000000 T __x64_sys_fchmodat
 */
SEC("kprobe/__x64_sys_fchmodat")
int sys_fchmodat(struct pt_regs *ctx) {
    struct pt_regs *__ctx = (void *)PT_REGS_PARM1(ctx);
    const char *file_name = (void *)&PT_REGS_PARM2(__ctx);
    umode_t *mode = (void *)&PT_REGS_PARM3(__ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};
    const char *argp;

    data.pid = pid;
    bpf_core_read(&data.mode, sizeof(data.mode), mode);
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);

    bpf_core_read(&argp, sizeof(argp), file_name);
    if (argp) {
        bpf_core_read_user_str(&data.path, sizeof(data.path), argp);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
