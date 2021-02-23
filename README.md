# simple_chmod_monitor
Use BPF to monitor chmod application provided by coreutils


## Usage: 
Step 1. Launch monitor_chmod.py first:

  #sudo ./monitor_chmod.py


Step 2. Execute chmod to change file attribute:

  #chmod 777 /tmp/test.file
  #chmod 0567 /tmp/test.file


Then you will get following ouput at terminal window which monitor_chmod.py has been launched at.

PID      COMM     PATH                                                             MODE
41447    chmod    /tmp/test.file                                                   0777
41448    chmod    /tmp/test.file                                                   0567

