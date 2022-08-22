# simple_chmod_monitor
Add CO-RE support for monitor_chmod

Validated at kernel version: 5.10.0, 5.15.0, 5.13.0

Please install clang-12

## Prerequisites
CONFIG_DEBUG_INFO_BTF must be configured.
Check CONFIG_DEBUG_INFO_BTF on your kenrel config:
```
#cat /boot//config-$(uname -r)|grep BTF
```
## Build

Clone libbpf-bootstrap from:[libbfp-bootstrap](https://github.com/libbpf/libbpf-bootstrap.git)

Change work directory to libbpf-bootstrap, fetch source code form submodules
```
#git submodule update --init --recursive
```

Clone bcc source code from: [bcc](https://github.com/iovisor/bcc.git)

Clone libbpf source code to bcc/src/cc/libbpf folder from: [libbpf](https://github.com/libbpf/libbpf.git)

Change work directory to bcc/libbpf-tools, add monitor_chmod to "APPS" in Makefile, and then make:
```
#make BPFTOOL_SRC=/src/to/libbpf-bootstrap/bpftool/src CLANG=/usr/bin/clang-12
```

monitor_chmod executable would be generated at bcc/libbpf-tools folder.

## Usage: 
Step 1. Launch monitor_chmod first:
```
#sudo ./monitor_chmod
```

Step 2. Execute chmod to change file attribute:
```
#chmod 777 /tmp/test.file
#chmod 0567 /tmp/test.file
```


Then you will get following ouput at terminal window at which monitor_chmod has been launched.
```
PID      COMM     PATH                                                             MODE
41447    chmod    /tmp/test.file                                                   0777
41448    chmod    /tmp/test.file                                                   0567
