#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "monitor_chmod.h"
#include "monitor_chmod.skel.h"
#include "trace_helpers.h"


int libbpf_print_fn(enum libbpf_print_level level,
        const char *format, va_list args)
{   
    if (level == LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}


/* Function to be invoked at sys_fchmodat triggered */
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct data_t *info = data;

    printf("%-8d %-16s %-64s %04o\n", info->pid, info->comm,
                                      info->path, info->mode);
}

int main(void) {
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb = NULL;
    struct monitor_chmod_bpf *obj;
    int err;

    libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = monitor_chmod_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = monitor_chmod_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = monitor_chmod_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

    printf("%-8s %-16s %-64s %-4s\n", "PID", "COMM", "PATH", "MODE");

	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 1, &pb_opts);

	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	while ((err = perf_buffer__poll(pb, 100)) >= 0)
		;

cleanup:
	perf_buffer__free(pb);
	monitor_chmod_bpf__destroy(obj);

	return err != 0;
}
