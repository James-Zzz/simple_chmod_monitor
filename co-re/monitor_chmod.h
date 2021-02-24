#ifndef __MONITOR_CHMOD_H
#define __MONITOR_CHMOD_H

#ifndef CMD_LEN
#define CMD_LEN 16
#endif

#ifndef PATH_LEN
#define PATH_LEN 128
#endif

struct data_t {
    __u32 pid;
    __u32 mode;
    char comm[CMD_LEN];
    char path[PATH_LEN];
};

#endif //__MONITOR_CHMOD_H
