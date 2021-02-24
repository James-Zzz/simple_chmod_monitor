#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "monitor_chmod.h"

#ifndef bpf_probe_read_user 
#define bpf_probe_read_user bpf_probe_read
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_fchmodat")
int sys_fchmodat(struct pt_regs *ctx) {
    struct pt_regs *__ctx = (void *)PT_REGS_PARM1_CORE(ctx);
    const char *file_name = (void *)PT_REGS_PARM2_CORE(__ctx);
    umode_t *mode = (void *)PT_REGS_PARM3_CORE(__ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *current = (void *)bpf_get_current_task();
    struct data_t data = {};

    /* Store PID and mode in hash table, then submit at syscall return */
    bpf_core_read(&data.mode, sizeof(data.mode), mode);
    data.pid = pid;
    BPF_CORE_READ_STR_INTO(&data.comm, current, group_leader, comm);
    bpf_core_read_user_str(&data.path, PATH_LEN, file_name);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}
