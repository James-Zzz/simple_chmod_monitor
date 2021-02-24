# simple_chmod_monitor
Add CO-RE support for monitor_chmod

Validated at kernel version: 5.10.0, 5.5.8, 5.4.86

## Prerequisites
CONFIG_DEBUG_INFO_BTF must be configured.
Check CONFIG_DEBUG_INFO_BTF on your kenrel config:
```
#cat /boot//config-$(uname -r)|grep BTF
```
## Build

Clone bcc source code from: [bcc](https://github.com/iovisor/bcc.git)
Clone libbpf source code to bcc/src/cc/libbpf folder from: [libbpf](https://github.com/libbpf/libbpf.git)
Change work directory to bcc/libbpf-tools, add monitor_chmod to "APPS" in Makefile, and then
execute make. monitor_chmod executable would be generated at bcc/libbpf-tools folder.

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
