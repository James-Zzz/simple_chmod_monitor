#include <uapi/linux/ptrace.h>

#ifndef bpf_probe_read_user
#define bpf_probe_read_user bpf_probe_read
#endif

#ifndef CMD_LEN
#define CMD_LEN 16
#endif

#ifndef PATH_LEN
#define PATH_LEN 128
#endif

enum event_type {
    EVENT_PATH,
    EVENT_RET,
};

struct val_t {
    u64 pid;
    u32 mode;
};

struct data_t {
    u32 pid;
    u32 mode;
    u32 type;
    char comm[CMD_LEN];
    char path[PATH_LEN];
};

BPF_HASH(infohash, u32, struct val_t);
BPF_PERF_OUTPUT(events);

static int retrieve_file_name(struct pt_regs *ctx,
                              const char *ptr,
                              struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        bpf_probe_read_user(data->path, PATH_LEN, argp);
    }

    return 0;
}

/*
 * It's weird that, definitions of fchmodat and sys_fchmodat user
 * level fchmodat are mismatch.
 * User level:
 * int fchmodat(int fd, char const *file, mode_t mode, int flag);
 * Kernel level: fs/open.c
 * SYSCALL_DEFINE3(fchmodat, int, dfd, const char __user *, filename,
 *                 umode_t, mode);
 * 
 * Use PT_REGS_PARMx to retrieveparameters from pt_regs manually.
 */
int sys__fchmodat(struct pt_regs *ctx) {
    struct pt_regs * __ctx = (void *)PT_REGS_PARM1(ctx);
    const char __user * file_name = (void *)&PT_REGS_PARM2(__ctx);
    umode_t *mode = (void *)&PT_REGS_PARM3(__ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t data = {};
    struct val_t info = {};

    /* Store PID and mode in hash table, then submit at syscall return */
    bpf_probe_read_user(&info.mode, sizeof(info.mode), mode);
    info.pid = pid;
    infohash.update(&pid, &info);

    /* Just to submit file name when fchmodat syscall is invoked. */
    data.pid = pid;
    data.type = EVENT_PATH;

    retrieve_file_name(ctx, file_name, &data);

    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}

int ret_sys__fchmodat(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t data = {};
    struct val_t * info;

    info = infohash.lookup(&pid);
    if (0 == info) {
        return 0;
    }

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.type = EVENT_RET;
    data.pid  = pid;
    data.mode = info->mode;

    events.perf_submit(ctx, &data, sizeof(struct data_t));
    infohash.delete(&pid);

    return 0;
}
