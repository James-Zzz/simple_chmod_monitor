#!/usr/bin/python3
#
# script to monitor chmod application privoded by coreutils.

from bcc import BPF
from bcc.utils import printb
from collections import defaultdict

class EventType(object):
    EVENT_PATH = 0
    EVENT_RET  = 1

# Dictionary to store path for processes.
path = defaultdict(list)

# Add more tuples in this list for syscall to be monitored.
#
# For current usage, we need to monitor chmod application provided
# by coreutils only. Accroding to source code of coreutils/src/chmod.c
# and gnulib/lib/openat.h, chmod application invokes fchmodat syscall.
# So we monitor fchmodat syscall here.
monitor_syscall_tuples = [
    ("fchmodat", "sys__fchmodat", "ret_sys__fchmodat"),
]

# Load BPF program from C souce code
bpf = BPF(src_file = "get_chmod_info.c")

# Process event callback.
# Event callback declaratino: callback(cpu, data, size)
def print_event(cpu, data, size):
    event = bpf["events"].event(data)

    if event.type == EventType.EVENT_PATH:
        if event.path:
            path[event.pid].append(event.path)
    elif event.type == EventType.EVENT_RET:

        printb(b"%-8d %-8s %-64s %04o" % (event.pid, event.comm, path[event.pid][0], event.mode))

        try:
            del(path[event.pid])
        except Exception:
            pass

def main():
    for (syscall, entry, ret) in monitor_syscall_tuples:
        bpf.attach_kprobe(event=bpf.get_syscall_fnname(syscall), fn_name=entry)
        bpf.attach_kretprobe(event=bpf.get_syscall_fnname(syscall), fn_name=ret)

    # Message header
    print("%-8s %-8s %-64s %-4s" % ("PID", "COMM", "PATH", "MODE"))

    bpf["events"].open_perf_buffer(print_event)
    while 1:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()
