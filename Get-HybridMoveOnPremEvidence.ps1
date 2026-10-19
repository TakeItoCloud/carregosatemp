#Requires -Version 5.1
<#
.SYNOPSIS
    Collects read-only evidence on one on-premises Exchange server for hybrid mailbox move (MRSProxy) problems and writes an HTML + CSV report.

.DESCRIPTION
    Run it on EACH internet-facing Exchange server that the firewall publishes for the MRSProxy name, in an elevated
    Exchange Management Shell. It checks the path Exchange Online uses for a hybrid move, layer by layer:

      1. Exchange inventory      Get-ExchangeServer, EWS and Autodiscover virtual directories (MRSProxy, WSSecurity, auth).
      2. IIS configuration       Windows authentication providers, Extended Protection, kernel mode, svc-Integrated handler,
                                 EWS application pool state, HTTPS bindings (including SNI host-name bindings).
      3. Certificates            Exchange certificates on every Exchange server, the certificate http.sys binds to 0.0.0.0:443.
      4. Live TLS + HTTP probe   Opens TLS to every Exchange server (and optionally the public IP) with SNI = the hybrid name,
                                 reads the certificate actually served, and the 401 challenge headers of /EWS/mrsproxy.svc.
      5. Sign-in probe           (-TestCredential) One NTLM-authenticated GET to /EWS/mrsproxy.svc on each server, like
                                 Exchange Online does. Shows whether the server accepts the endpoint account.
      6. TLS registry            SCHANNEL protocols and .NET SystemDefaultTlsVersions / SchUseStrongCrypto.
      7. Logs                    IIS log lines for /EWS/mrsproxy.svc (status, sub-status, Win32 status, client IP),
                                 HTTPERR, Application (MRS / ASP.NET), System (Schannel), Security 4625 failed logons.
      8. Network                 Internal DNS answer for the hybrid name, outbound 443 to Exchange Online, proxy settings.

    Read-only: changes nothing on Exchange, IIS, Windows or Active Directory. -TestCredential sends one normal
    authenticated HTTPS request per server; it appears in the IIS and Security logs like any sign-in. The password is
    never written to the log or the report.

    Cannot see: the firewall / reverse proxy, what Exchange Online receives from the internet, NTLM validation on the
    domain controllers (use Get-HybridMoveAuthEvidence.ps1), or the logs of other servers (run this on each server).
    Anything it cannot read is reported as NotAssessed with the reason.

    Sources (read 2026-10-16):
      https://learn.microsoft.com/exchange/hybrid-deployment-prerequisites
      https://learn.microsoft.com/exchange/certificate-requirements
      https://learn.microsoft.com/exchange/hybrid-deployment/troubleshoot-a-hybrid-deployment
      https://learn.microsoft.com/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-extended-protection
      https://learn.microsoft.com/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-tls-configuration
      https://learn.microsoft.com/troubleshoot/exchange/move-mailboxes/remote-server-returned-error-403-forbidden
      https://learn.microsoft.com/troubleshoot/exchange/move-mailboxes/hybrid-deployment-errors
      https://learn.microsoft.com/troubleshoot/developer/webapps/iis/health-diagnostic-performance/http-status-code

.PARAMETER HybridHostName
    The public name Exchange Online calls for MRSProxy (the RemoteServer of the migration endpoint).

.PARAMETER EndpointAccount
    Account saved in the migration endpoint, as DOMAIN\user or user. Used to filter Security 4625 events and as the
    default user name for -TestCredential.

.PARAMETER StartTime
    Start of the log window (local time). Default: 24 hours ago.

.PARAMETER EndTime
    End of the log window (local time). Default: now.

.PARAMETER PublicIp
    Optional public IP of the hybrid name. The script tries a TLS probe to it (usually blocked from inside when the
    firewall only allows Microsoft; that result is reported as Info, not as a failure).

.PARAMETER ExoIpListPath
    Optional ExoIpRanges-*.csv produced by Get-HybridMoveCloudEvidence.ps1. When given, IIS client IPs are classified as
    "inside Exchange Online ranges" or not, which shows whether the firewall source-NATs or proxies the traffic.

.PARAMETER TestCredential
    Prompts once for the endpoint account password and runs the sign-in probe against every Exchange server.

.PARAMETER MaxLogRows
    Maximum rows exported per log type. Default 20000.

.PARAMETER EvidencePath
    Case evidence folder. When given, results go to <EvidencePath>\Exchange\Get-HybridMoveOnPremEvidence\... (the layout
    Get-HybridMoveVerdict.ps1 -EvidencePath reads) and -OutputPath is ignored. Run on each Exchange server (local folder or a UNC share; copy the Exchange folder to the case evidence folder afterwards if the share is not reachable from the server).

.PARAMETER OutputPath
    Root output folder. Default C:\Scripts\Cannes. Results go to <OutputPath>\Get-HybridMoveOnPremEvidence\<Server>-<timestamp>\.

.EXAMPLE
    .\Get-HybridMoveOnPremEvidence.ps1 -HybridHostName hybrid1.contoso.com -EndpointAccount CONTOSO\migadmin
    Collects everything for the last 24 hours without signing in.

.EXAMPLE
    .\Get-HybridMoveOnPremEvidence.ps1 -HybridHostName hybrid1.contoso.com -EndpointAccount CONTOSO\migadmin -StartTime '2026-10-16 13:00' -EndTime '2026-10-16 16:00' -ExoIpListPath C:\Temp\ExoIpRanges.csv -TestCredential
    Narrow log window, classifies client IPs and runs the NTLM sign-in probe (prompts for the password).

.OUTPUTS
    Report-<ts>.html, Checks-<ts>.csv and one CSV per data set in the run folder; the run log in ...\Logs\.
    Exit codes: 0 all collection steps ran, 1 one or more steps failed (see NotAssessed rows), 2 could not run.

.NOTES
    Owner: Carlos Annes (TakeItToCloud)
    Version: 1.0.2
    Created: 2026-10-16
    Last updated: 2026-10-17
    Requires: Windows PowerShell 5.1 (the Exchange Management Shell runs on 5.1 on the Exchange server, so this script
              targets 5.1), Exchange Management Shell (Exchange 2016/2019/SE), WebAdministration (IIS, built in),
              local Administrator (Security log, IIS config) and an Exchange role that can run Get-ExchangeServer,
              Get-ExchangeCertificate and Get-*VirtualDirectory (e.g. Organization Management or View-Only Organization
              Management plus local admin).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')][string]$HybridHostName,
    [string]$EndpointAccount,
    [datetime]$StartTime = (Get-Date).AddHours(-24),
    [datetime]$EndTime = (Get-Date),
    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')][string]$PublicIp,
    [string]$ExoIpListPath,
    [switch]$TestCredential,
    [ValidateRange(100, 1000000)][int]$MaxLogRows = 20000,
    [string]$EvidencePath,
    [string]$OutputPath = 'C:\Scripts\Cannes'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -EvidencePath sends the results to <EvidencePath>\Exchange (case evidence layout read by Get-HybridMoveVerdict.ps1).
$OutputPathNote = ''
if ($EvidencePath) {
    if ($PSBoundParameters.ContainsKey('OutputPath')) { $OutputPathNote = "-EvidencePath given: -OutputPath '$OutputPath' ignored." }
    $OutputPath = Join-Path $EvidencePath 'Exchange'
}
# ---- Configuration --------------------------------------------------------------------------------
$ScriptName    = 'Get-HybridMoveOnPremEvidence'
$ScriptVersion = '1.0.2'
$Stamp         = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunDir        = Join-Path (Join-Path $OutputPath $ScriptName) "$($env:COMPUTERNAME)-$Stamp"
$LogDir        = Join-Path (Join-Path $OutputPath $ScriptName) 'Logs'
$LogFile       = Join-Path $LogDir "$ScriptName-$($env:COMPUTERNAME)-$Stamp.log"
$StartRun      = Get-Date
$ExitCode      = 0
$Script:Checks = New-Object System.Collections.Generic.List[object]
$Script:Data   = [ordered]@{}
$Script:StepOk = 0; $Script:StepFailed = 0
$CertWarnDays  = 60   # warn when the hybrid certificate expires within this many days (time to renew and re-assign)
# IIS sc-win32-status 2148074254 = 0x8009030E "No credentials are available in the security package": the NTLM
# challenge leg that precedes a successful 200 (seen in lab IIS logs 2026-10-17: 401.0 -> 401.1/0x8009030E -> 200).
$NtlmChallengeWin32 = '2148074254'

# Built-in modules this script uses (not installed from the gallery; if missing, the related checks are NotAssessed).
$RequiredModules = @(
    @{ Name = 'WebAdministration'; Source = 'IIS (Windows feature Web-Scripting-Tools / IIS management)' }
)

# NTSTATUS codes seen in Security 4625 / 4776 events (Windows standard values).
$NtStatusText = @{
    '0x0' = 'Success'; '0xC000006A' = 'Wrong password'; '0xC0000064' = 'User name does not exist'
    '0xC000006D' = 'Logon failure (bad user name or authentication information)'; '0xC000006E' = 'Account restriction'
    '0xC000006F' = 'Logon outside allowed hours'; '0xC0000070' = 'Workstation restriction'; '0xC0000071' = 'Password expired'
    '0xC0000072' = 'Account disabled'; '0xC0000193' = 'Account expired'; '0xC0000224' = 'Password must change at next logon'
    '0xC0000234' = 'Account locked out'; '0xC000015B' = 'Logon type not granted on this computer'
}

# Documentation used in the checks.
$Ref = @{
    Ports    = 'https://learn.microsoft.com/exchange/hybrid-deployment-prerequisites'
    Cert     = 'https://learn.microsoft.com/exchange/certificate-requirements'
    Hybrid   = 'https://learn.microsoft.com/exchange/hybrid-deployment/troubleshoot-a-hybrid-deployment'
    EP       = 'https://learn.microsoft.com/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-extended-protection'
    Tls      = 'https://learn.microsoft.com/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/exchange-tls-configuration'
    Mrs403   = 'https://learn.microsoft.com/troubleshoot/exchange/move-mailboxes/remote-server-returned-error-403-forbidden'
    Handler  = 'https://learn.microsoft.com/troubleshoot/exchange/move-mailboxes/hybrid-deployment-errors'
    IisCodes = 'https://learn.microsoft.com/troubleshoot/developer/webapps/iis/health-diagnostic-performance/http-status-code'
}

# ---- Helpers --------------------------------------------------------------------------------------
function Write-Log {
    <# .SYNOPSIS Writes one timestamped line to the log file and the console. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'House rule names the helper Write-Log.')]
    param([ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO', [Parameter(Mandatory)][string]$Message)
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'o'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Information -MessageData $line -InformationAction Continue
}

function Write-ErrorDetail {
    <# .SYNOPSIS Logs a caught error with step, item, message, type, position and stack. #>
    param([Parameter(Mandatory)]$ErrorRecord, [Parameter(Mandatory)][string]$Step, [string]$Item = $env:COMPUTERNAME)
    Write-Log ERROR "Step: $Step | Item: $Item"
    Write-Log ERROR "Message: $($ErrorRecord.Exception.Message)"
    Write-Log ERROR "Type: $($ErrorRecord.Exception.GetType().FullName)"
    Write-Log ERROR "Position: $($ErrorRecord.InvocationInfo.PositionMessage)"
    Write-Log ERROR "Stack: $($ErrorRecord.ScriptStackTrace)"
}

function Add-Check {
    <# .SYNOPSIS Adds one finding row: Pass | Warn | Fail | Info | NotAssessed. #>
    param([string]$Area, [string]$Check, [ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'NotAssessed')][string]$Status, [string]$Detail, [string]$Reference = '')
    $Script:Checks.Add([pscustomobject]@{ Server = $env:COMPUTERNAME; Area = $Area; Check = $Check; Status = $Status; Detail = $Detail; Reference = $Reference })
}

function Add-Data {
    <# .SYNOPSIS Stores a data set for the HTML report and exports it to CSV (capped at MaxLogRows). #>
    param([Parameter(Mandatory)][string]$Name, [AllowNull()]$Rows)
    $list = @($Rows | Where-Object { $null -ne $_ })
    if ($list.Count -gt $MaxLogRows) { Write-Log WARN "$Name has $($list.Count) rows; exporting the first $MaxLogRows"; $list = $list[0..($MaxLogRows - 1)] }
    $Script:Data[$Name] = $list
    if ($list.Count -gt 0) {
        $file = Join-Path $RunDir (($Name -replace '[^A-Za-z0-9]+', '-') + "-$Stamp.csv")
        $list | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
        Write-Log INFO "$Name : $($list.Count) row(s) -> $file"
    } else { Write-Log INFO "$Name : 0 rows" }
}

function Invoke-Step {
    <# .SYNOPSIS Runs one collection step in its own try/catch; a failure becomes a NotAssessed row, never a silent skip. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Body)
    Write-Log INFO "STEP start: $Name"
    try { & $Body; $Script:StepOk++; Write-Log INFO "STEP end: $Name" }
    catch {
        $Script:StepFailed++
        Write-ErrorDetail -ErrorRecord $_ -Step $Name
        Add-Check -Area $Name -Check 'Collection step' -Status NotAssessed -Detail "Step failed: $($_.Exception.Message)"
    }
}

function Get-Prop {
    <# .SYNOPSIS Returns a property value as text, or 'NotAssessed' when absent (never invents a value). #>
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject -or -not $InputObject.PSObject.Properties[$Name]) { return 'NotAssessed' }
    $v = $InputObject.$Name
    if ($null -eq $v) { return '' }
    if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { return (@($v) | ForEach-Object { "$_" }) -join ', ' }
    return "$v"
}

function Get-IisValue {
    <# .SYNOPSIS Reads one IIS configuration attribute and returns its plain value. #>
    param([string]$Location, [string]$Filter, [string]$Name)
    $v = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $Location -Filter $Filter -Name $Name
    if ($null -ne $v -and $v.PSObject.Properties['Value']) { return $v.Value } else { return $v }
}

function ConvertTo-HexStatus {
    <# .SYNOPSIS Formats an event status value (Int32/UInt32/string) as 0xXXXXXXXX. #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { if ($Value -match '^0x') { return $Value.ToUpper().Replace('0X', '0x') } ; $n = 0L; if (-not [long]::TryParse($Value, [ref]$n)) { return $Value } ; $Value = $n }
    $u = [BitConverter]::ToUInt32([BitConverter]::GetBytes([long]$Value), 0)
    return ('0x{0:X}' -f $u)
}

function Get-Win32Text {
    <# .SYNOPSIS Returns the Windows text for an IIS sc-win32-status code (asks Windows; no hard-coded table). #>
    param([string]$Code)
    $n = 0L
    if (-not [long]::TryParse($Code, [ref]$n)) { return '' }
    if ($n -eq 0) { return 'Success' }
    $i = [BitConverter]::ToInt32([BitConverter]::GetBytes([long]($n -band [long]4294967295)), 0)
    try { return (New-Object ComponentModel.Win32Exception $i).Message } catch { return '' }
}

function Get-IisAuthMeaning {
    <# .SYNOPSIS Plain meaning of an IIS status/sub-status/Win32 combination for /EWS/mrsproxy.svc. #>
    param([string]$Status, [string]$SubStatus, [string]$Win32)
    switch ("$Status.$SubStatus") {
        '200.0' { return 'Signed in and served' }
        '401.0' { return 'Challenge sent - normal first step' }
        '401.1' { if ($Win32 -eq $NtlmChallengeWin32) { return 'NTLM handshake step - normal when a 200 follows' } else { return 'Sign-in REJECTED (logon failed)' } }
        '401.2' { return 'Logon failed due to server configuration' }
        '403.0' { return 'Forbidden - check MRSProxyEnabled' }
        '405.0' { return 'Method not allowed - check svc-Integrated handler' }
        default { return '' }
    }
}

function Test-NameCovered {
    <# .SYNOPSIS True when Text contains the host name or a wildcard that covers it. #>
    param([string]$HostName, [string]$Text)
    if (-not $Text) { return $false }
    $parent = $HostName.Substring($HostName.IndexOf('.') + 1)
    foreach ($n in @($HostName, "*.$parent")) {
        if ($Text -match ('(?<![\w.-])' + [regex]::Escape($n) + '(?![\w.-])')) { return $true }
    }
    return $false
}

function ConvertTo-UInt32Ip {
    <# .SYNOPSIS IPv4 text to UInt32 (network order). #>
    param([string]$Ip)
    $b = ([Net.IPAddress]::Parse($Ip)).GetAddressBytes(); [Array]::Reverse($b); return [BitConverter]::ToUInt32($b, 0)
}

function Test-IpInRange {
    <# .SYNOPSIS Returns InRange / NotInRange / NotAssessed for an IPv4 address against pre-parsed CIDR ranges. #>
    param([string]$Ip, [object[]]$Ranges)
    if (-not $Ranges -or $Ranges.Count -eq 0) { return 'NotAssessed' }
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return 'NotAssessed (IPv6)' }
    $v = ConvertTo-UInt32Ip $Ip
    foreach ($r in $Ranges) { if (($v -band $r.Mask) -eq ($r.Net -band $r.Mask)) { return 'InRange' } }
    return 'NotInRange'
}

function Invoke-TlsProbe {
    <# .SYNOPSIS TLS handshake with SNI, reads the served certificate and the unauthenticated 401 challenge of /EWS/mrsproxy.svc. #>
    param([string]$Target, [string]$SniName, [int]$TimeoutMs = 8000, [switch]$SkipHttp)
    $r = [ordered]@{ Target = $Target; Reachable = $false; Protocol = ''; Subject = ''; Issuer = ''; Thumbprint = ''; NotAfter = ''
        NameCoversHybrid = ''; ChainValidOnThisServer = ''; HttpStatusLine = ''; WwwAuthenticate = ''; Error = '' }
    $tcp = New-Object Net.Sockets.TcpClient; $ssl = $null
    try {
        $ar = $tcp.BeginConnect($Target, 443, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "TCP 443 not reachable within $($TimeoutMs / 1000)s" }
        $tcp.EndConnect($ar); $r.Reachable = $true
        # The callback accepts any certificate only so it can be READ; nothing is trusted or changed.
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]))
        $ssl.ReadTimeout = $TimeoutMs; $ssl.WriteTimeout = $TimeoutMs
        $ssl.AuthenticateAsClient($SniName, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
        $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $san = ($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | ForEach-Object { $_.Format($false) }) -join ' '
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $r.Protocol = "$($ssl.SslProtocol)"; $r.Subject = $c.Subject; $r.Issuer = $c.Issuer; $r.Thumbprint = $c.Thumbprint
        $r.NotAfter = $c.NotAfter.ToString('yyyy-MM-dd'); $r.NameCoversHybrid = Test-NameCovered -HostName $SniName -Text "$san $($c.Subject)"
        $r.ChainValidOnThisServer = $chain.Build($c)
        if (-not $SkipHttp) { try {
            $bytes = [Text.Encoding]::ASCII.GetBytes("GET /EWS/mrsproxy.svc HTTP/1.1`r`nHost: $SniName`r`nUser-Agent: HybridMoveEvidence`r`nConnection: close`r`n`r`n")
            $ssl.Write($bytes, 0, $bytes.Length); $ssl.Flush()
            $reader = New-Object IO.StreamReader($ssl, [Text.Encoding]::ASCII)
            $r.HttpStatusLine = $reader.ReadLine(); $auth = @()
            while ($true) { $line = $reader.ReadLine(); if ($null -eq $line -or $line -eq '') { break }; if ($line -match '^WWW-Authenticate:\s*(.+)$') { $auth += $Matches[1] } }
            $r.WwwAuthenticate = $auth -join ' | '
        } catch { $r.Error = "HTTP probe: $($_.Exception.Message)" } }
    } catch { $r.Error = $_.Exception.Message }
    finally { if ($ssl) { $ssl.Dispose() }; $tcp.Close() }
    [pscustomobject]$r
}

function Invoke-AuthProbe {
    <# .SYNOPSIS One NTLM-authenticated GET to /EWS/mrsproxy.svc on a server, with the hybrid name as Host header. #>
    param([string]$ServerFqdn, [string]$HostHeader, [pscredential]$Credential)
    $uri = [Uri]"https://$ServerFqdn/EWS/mrsproxy.svc"
    $oldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    $oldProt = [Net.ServicePointManager]::SecurityProtocol
    $code = ''; $err = ''
    try {
        # Accept the certificate only for this probe (the TLS probe already reports which one is served).
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $req = [Net.HttpWebRequest]::Create($uri)
        $req.Method = 'GET'; $req.Host = $HostHeader; $req.Timeout = 30000; $req.AllowAutoRedirect = $false; $req.UserAgent = 'HybridMoveEvidence'
        $cc = New-Object Net.CredentialCache
        $cc.Add($uri, 'NTLM', $Credential.GetNetworkCredential())   # force NTLM, as used from Exchange Online
        $req.Credentials = $cc
        try { $resp = $req.GetResponse(); $code = [int]$resp.StatusCode; $resp.Close() }
        catch [Net.WebException] { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode; $_.Exception.Response.Close() } else { $err = $_.Exception.Message } }
    } catch { $err = $_.Exception.Message }
    finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCb; [Net.ServicePointManager]::SecurityProtocol = $oldProt }
    [pscustomobject]@{ Server = $ServerFqdn; HostHeader = $HostHeader; User = $Credential.UserName; HttpStatus = $code; Error = $err }
}

function ConvertFrom-NetshSslCert {
    <# .SYNOPSIS Parses 'netsh http show sslcert' without relying on labels (works on localized Windows): binding = "<addr>:<port>", hash = 40 hex chars. #>
    param([string[]]$Lines)
    $cur = $null
    foreach ($line in $Lines) {
        $val = ($line -split ':\s+', 2)[-1].Trim()
        if ($line -match ':\s+(\S+:\d+)\s*$' -and $line -notmatch '[0-9a-fA-F]{40}') {
            if ($cur) { [pscustomobject]$cur }
            $cur = [ordered]@{ Binding = $Matches[1]; CertificateHash = ''; StoreName = '' }; continue
        }
        if ($cur -and $val -match '^[0-9a-fA-F]{40}$') { $cur.CertificateHash = $val.ToUpper(); continue }
        if ($cur -and $val -match '^(MY|WebHosting|Root)$') { $cur.StoreName = $val }
    }
    if ($cur) { [pscustomobject]$cur }
}

function Read-W3CLog {
    <# .SYNOPSIS Reads W3C log lines that contain Pattern, mapped by the file's #Fields header, filtered to the UTC window. #>
    param([string[]]$Files, [string]$Pattern, [datetime]$FromUtc, [datetime]$ToUtc)
    foreach ($f in $Files) {
        $fieldsLine = Get-Content -Path $f -TotalCount 20 | Where-Object { $_ -like '#Fields:*' } | Select-Object -First 1
        if (-not $fieldsLine) { Write-Log WARN "No #Fields header in $f; skipped"; continue }
        $fields = ($fieldsLine -replace '^#Fields:\s*', '').Split(' ')
        $hits = if ($Pattern) { Select-String -Path $f -Pattern $Pattern -SimpleMatch } else { Select-String -Path $f -Pattern '^[^#]' }
        foreach ($h in $hits) {
            $parts = $h.Line.Split(' ')
            if ($parts.Count -ne $fields.Count) { continue }
            $o = [ordered]@{ LogFile = Split-Path $f -Leaf }
            for ($i = 0; $i -lt $fields.Count; $i++) { $o[$fields[$i]] = $parts[$i] }
            $t = [datetime]::MinValue
            if ($o.Contains('date') -and $o.Contains('time') -and [datetime]::TryParse("$($o['date']) $($o['time'])", [ref]$t)) {
                if ($t -lt $FromUtc -or $t -gt $ToUtc) { continue }
                $o['DateTimeUtc'] = $t.ToString('yyyy-MM-dd HH:mm:ss')
            }
            [pscustomobject]$o
        }
    }
}

function Export-HtmlReport {
    <# .SYNOPSIS Writes a self-contained HTML report: summary checks first, then every data set. #>
    param([string]$Path, [string]$Title, [string]$Subtitle)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
    $order = @{ Fail = 0; Warn = 1; NotAssessed = 2; Info = 3; Pass = 4 }
    $rows = foreach ($c in ($Script:Checks | Sort-Object { $order[$_.Status] }, Area)) {
        $refCell = if ($c.Reference) { "<a href='$(& $enc $c.Reference)'>doc</a>" } else { '' }
        "<tr class='$($c.Status.ToLower())'><td>$(& $enc $c.Status)</td><td>$(& $enc $c.Area)</td><td>$(& $enc $c.Check)</td><td>$(& $enc $c.Detail)</td><td>$refCell</td></tr>"
    }
    $counts = ($Script:Checks | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ' &middot; '
    $sections = foreach ($k in $Script:Data.Keys) {
        $d = @($Script:Data[$k])
        if ($d.Count -eq 0) { "<h2>$(& $enc $k)</h2><p class='muted'>No rows.</p>" }
        else { "<h2>$(& $enc $k) <span class='muted'>($($d.Count))</span></h2><div class='wrap'>" + (($d | Select-Object -First 2000 | ConvertTo-Html -Fragment) -join "`n") + '</div>' }
    }
    $html = @"
<!doctype html><html><head><meta charset="utf-8"><title>$(& $enc $Title)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b;background:#fff}
h1{margin:0 0 4px}h2{margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:4px}
.muted{color:#666;font-weight:normal;font-size:.9em}.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#f3f3f3;position:sticky;top:0}
tr.fail td:first-child{background:#f8d7da;font-weight:bold}tr.warn td:first-child{background:#fff3cd;font-weight:bold}
tr.pass td:first-child{background:#d1e7dd}tr.notassessed td:first-child{background:#e2e3e5}tr.info td:first-child{background:#cfe2ff}
</style></head><body>
<h1>$(& $enc $Title)</h1><p class="muted">$(& $enc $Subtitle)</p><p>$counts</p>
<h2>Findings</h2><table><tr><th>Status</th><th>Area</th><th>Check</th><th>Detail</th><th>Ref</th></tr>
$($rows -join "`n")
</table>
$($sections -join "`n")
</body></html>
"@
    Set-Content -Path $Path -Value $html -Encoding UTF8
}

# ---- Main -----------------------------------------------------------------------------------------
foreach ($dir in @($RunDir, $LogDir)) {
    if (-not (Test-Path $dir)) { Write-Information "Folder $dir is missing - creating it." -InformationAction Continue; New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}
Write-Information "Log file: $LogFile" -InformationAction Continue
Write-Log INFO "$ScriptName $ScriptVersion | Start $($StartRun.ToString('o')) | User $env:USERDOMAIN\$env:USERNAME | Computer $env:COMPUTERNAME | PS $($PSVersionTable.PSVersion)"
Write-Log INFO ("Parameters: " + (($PSBoundParameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' | '))
Write-Log INFO "Run folder: $RunDir"
if ($OutputPathNote) { Write-Log WARN $OutputPathNote }

$Script:ExoRanges = @()
$Script:Servers = @()
$Script:CertMap = @{}

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Log WARN 'Not running elevated: Security log, IIS configuration and some registry reads will be NotAssessed.' }
    Add-Check -Area 'Run' -Check 'Elevated session' -Status $(if ($isAdmin) { 'Pass' } else { 'Warn' }) -Detail "Administrator: $isAdmin"

    # Exchange cmdlets: load the Exchange Management Shell at script scope if they are not present.
    if (-not (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)) {
        if ($env:ExchangeInstallPath -and (Test-Path (Join-Path $env:ExchangeInstallPath 'bin\RemoteExchange.ps1'))) {
            Write-Log INFO 'Loading the Exchange Management Shell (RemoteExchange.ps1, Connect-ExchangeServer -auto)'
            . (Join-Path $env:ExchangeInstallPath 'bin\RemoteExchange.ps1')
            Connect-ExchangeServer -auto -ClientApplication:ManagementShell | Out-Null
        }
    }
    $haveExchange = [bool](Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)
    if (-not $haveExchange) { Write-Log WARN 'Exchange cmdlets not available: run from the Exchange Management Shell on an Exchange server.' }
    Add-Check -Area 'Run' -Check 'Exchange Management Shell' -Status $(if ($haveExchange) { 'Pass' } else { 'NotAssessed' }) -Detail $(if ($haveExchange) { 'Exchange cmdlets loaded' } else { 'Exchange cmdlets not available; Exchange checks skipped' })

    foreach ($m in $RequiredModules) {
        $found = Get-Module -ListAvailable -Name $m.Name
        if ($found) { Import-Module $m.Name; Write-Log INFO "Module $($m.Name) available" }
        else { Write-Log WARN "Module $($m.Name) not available ($($m.Source)); related checks NotAssessed. It is part of Windows/IIS and is not installed by this script." }
    }
    $haveIis = [bool](Get-Module -Name WebAdministration)

    if ($ExoIpListPath) {
        Invoke-Step -Name 'Exchange Online IP list' -Body {
            # Microsoft: permit the IP addresses in the Exchange Online table -> rows with ServiceArea = Exchange.
            $rows = @(Import-Csv -Path $ExoIpListPath | Where-Object { $_.Ip -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$' -and (-not $_.PSObject.Properties['ServiceArea'] -or $_.ServiceArea -eq 'Exchange') })
            $Script:ExoRanges = foreach ($r in $rows) {
                $p = $r.Ip.Split('/'); $bits = [int]$p[1]
                $mask = if ($bits -eq 0) { [uint32]0 } else { [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $bits)) }
                [pscustomobject]@{ Net = ConvertTo-UInt32Ip $p[0]; Mask = $mask; Text = $r.Ip }
            }
            Add-Check -Area 'Network' -Check 'Exchange Online IPv4 ranges loaded' -Status Info -Detail "$(@($Script:ExoRanges).Count) IPv4 ranges from $ExoIpListPath"
        }
    }

    # 1. Exchange inventory ------------------------------------------------------------------------
    if ($haveExchange) {
        Invoke-Step -Name 'Exchange servers' -Body {
            $Script:Servers = @(Get-ExchangeServer -ErrorAction Stop | Sort-Object Name)
            Add-Data 'Exchange servers' ($Script:Servers | Select-Object Name, Fqdn, Site, @{n = 'ServerRole'; e = { Get-Prop $_ 'ServerRole' } }, @{n = 'Version'; e = { Get-Prop $_ 'AdminDisplayVersion' } }, @{n = 'InternetWebProxy'; e = { Get-Prop $_ 'InternetWebProxy' } })
            $builds = @($Script:Servers | ForEach-Object { Get-Prop $_ 'AdminDisplayVersion' } | Sort-Object -Unique)
            Add-Check -Area 'Exchange' -Check 'Same build on all servers' -Status $(if ($builds.Count -le 1) { 'Pass' } else { 'Warn' }) -Detail ("Builds: " + ($builds -join ' ; '))
        }

        Invoke-Step -Name 'EWS virtual directories (all servers)' -Body {
            $all = @(Get-WebServicesVirtualDirectory -ADPropertiesOnly -ErrorAction Stop)
            Add-Data 'EWS virtual directories (AD)' ($all | Select-Object Server, Name, MRSProxyEnabled, @{n = 'MRSProxyMaxConnections'; e = { Get-Prop $_ 'MRSProxyMaxConnections' } }, InternalUrl, ExternalUrl)
            foreach ($v in $all) {
                $ok = "$($v.MRSProxyEnabled)" -eq 'True'
                Add-Check -Area 'MRSProxy' -Check "MRSProxyEnabled on $($v.Server)" -Status $(if ($ok) { 'Pass' } else { 'Warn' }) -Detail "MRSProxyEnabled=$($v.MRSProxyEnabled). Must be True on every server the firewall publishes for $HybridHostName." -Reference $Ref.Mrs403
            }
        }

        Invoke-Step -Name 'EWS virtual directory (this server)' -Body {
            $v = Get-WebServicesVirtualDirectory -Server $env:COMPUTERNAME -ErrorAction Stop | Select-Object -First 1
            $row = [pscustomobject]@{
                Server = $env:COMPUTERNAME; MRSProxyEnabled = Get-Prop $v 'MRSProxyEnabled'; WSSecurityAuthentication = Get-Prop $v 'WSSecurityAuthentication'
                WindowsAuthentication = Get-Prop $v 'WindowsAuthentication'; BasicAuthentication = Get-Prop $v 'BasicAuthentication'; OAuthAuthentication = Get-Prop $v 'OAuthAuthentication'
                ExternalAuthenticationMethods = Get-Prop $v 'ExternalAuthenticationMethods'; ExtendedProtectionTokenChecking = Get-Prop $v 'ExtendedProtectionTokenChecking'
                InternalUrl = Get-Prop $v 'InternalUrl'; ExternalUrl = Get-Prop $v 'ExternalUrl'; MetabasePath = Get-Prop $v 'MetabasePath'
            }
            Add-Data 'EWS virtual directory (this server)' $row
            Add-Check -Area 'MRSProxy' -Check 'Windows authentication on EWS (NTLM for /ews/mrsproxy.svc)' -Status $(if ($row.WindowsAuthentication -eq 'True') { 'Pass' } else { 'Fail' }) -Detail "WindowsAuthentication=$($row.WindowsAuthentication). Microsoft lists NTLM as the provider for mailbox migrations." -Reference $Ref.Ports
            Add-Check -Area 'MRSProxy' -Check 'WSSecurity authentication on EWS' -Status $(if ($row.WSSecurityAuthentication -eq 'True') { 'Pass' } else { 'Warn' }) -Detail "WSSecurityAuthentication=$($row.WSSecurityAuthentication). The hybrid troubleshooter expects True." -Reference 'https://learn.microsoft.com/troubleshoot/exchange/move-or-migrate-mailboxes/troubleshoot-migration-issues-in-exchange-hybrid'
            Add-Check -Area 'MRSProxy' -Check 'Extended Protection on EWS' -Status Info -Detail "ExtendedProtectionTokenChecking=$($row.ExtendedProtectionTokenChecking). If not None, any device that terminates TLS in front must present the SAME certificate as IIS (SSL bridging) or sign-ins fail." -Reference $Ref.EP
            $extHost = if ($row.ExternalUrl -match '^https?://([^/]+)') { $Matches[1] } else { '' }
            Add-Check -Area 'MRSProxy' -Check 'EWS ExternalUrl host vs hybrid name' -Status $(if ($extHost -eq $HybridHostName) { 'Pass' } else { 'Info' }) -Detail "ExternalUrl host '$extHost', migration endpoint name '$HybridHostName'. A difference is allowed; it only matters if certificates or firewall rules are built for one name only."
        }

        Invoke-Step -Name 'Autodiscover virtual directory (this server)' -Body {
            $a = Get-AutodiscoverVirtualDirectory -Server $env:COMPUTERNAME -ErrorAction Stop | Select-Object -First 1
            Add-Data 'Autodiscover virtual directory (this server)' ([pscustomobject]@{ Server = $env:COMPUTERNAME; WSSecurityAuthentication = Get-Prop $a 'WSSecurityAuthentication'; WindowsAuthentication = Get-Prop $a 'WindowsAuthentication'; OAuthAuthentication = Get-Prop $a 'OAuthAuthentication'; ExtendedProtectionTokenChecking = Get-Prop $a 'ExtendedProtectionTokenChecking' })
        }

        Invoke-Step -Name 'Hybrid configuration' -Body {
            $h = Get-HybridConfiguration -ErrorAction Stop
            if (-not $h) { Add-Check -Area 'Hybrid' -Check 'Hybrid configuration object' -Status Warn -Detail 'Get-HybridConfiguration returned nothing.'; return }
            Add-Data 'Hybrid configuration' ($h | Select-Object @{n = 'Features'; e = { Get-Prop $_ 'Features' } }, @{n = 'Domains'; e = { Get-Prop $_ 'Domains' } }, @{n = 'ClientAccessServers'; e = { Get-Prop $_ 'ClientAccessServers' } }, @{n = 'ReceivingTransportServers'; e = { Get-Prop $_ 'ReceivingTransportServers' } }, @{n = 'SendingTransportServers'; e = { Get-Prop $_ 'SendingTransportServers' } }, @{n = 'TlsCertificateName'; e = { Get-Prop $_ 'TlsCertificateName' } }, @{n = 'OnPremisesSmartHost'; e = { Get-Prop $_ 'OnPremisesSmartHost' } })
        }

        Invoke-Step -Name 'Exchange certificates (all servers)' -Body {
            $rows = foreach ($s in $Script:Servers) {
                try {
                    foreach ($c in @(Get-ExchangeCertificate -Server $s.Name -ErrorAction Stop)) {
                        $domains = Get-Prop $c 'CertificateDomains'
                        $Script:CertMap["$($c.Thumbprint)"] = [pscustomobject]@{ RootCAType = Get-Prop $c 'RootCAType'; Domains = $domains; Subject = $c.Subject }
                        [pscustomobject]@{ Server = $s.Name; Thumbprint = $c.Thumbprint; Subject = $c.Subject; Issuer = Get-Prop $c 'Issuer'; NotAfter = ([datetime]$c.NotAfter).ToString('yyyy-MM-dd')
                            DaysLeft = [int](([datetime]$c.NotAfter) - (Get-Date)).TotalDays; Services = Get-Prop $c 'Services'; RootCAType = Get-Prop $c 'RootCAType'; IsSelfSigned = Get-Prop $c 'IsSelfSigned'
                            Status = Get-Prop $c 'Status'; CoversHybridName = Test-NameCovered -HostName $HybridHostName -Text $domains; CertificateDomains = $domains }
                    }
                } catch { Write-ErrorDetail -ErrorRecord $_ -Step 'Get-ExchangeCertificate' -Item $s.Name; Add-Check -Area 'Certificates' -Check "Certificates on $($s.Name)" -Status NotAssessed -Detail $_.Exception.Message }
            }
            Add-Data 'Exchange certificates' $rows
            $mine = @($rows | Where-Object { $_.Server -eq $env:COMPUTERNAME -and $_.CoversHybridName -and $_.RootCAType -eq 'ThirdParty' })
            if ($mine.Count -eq 0) { Add-Check -Area 'Certificates' -Check "Public certificate for $HybridHostName on this server" -Status Fail -Detail 'No third-party certificate on this server covers the hybrid name.' -Reference $Ref.Cert }
            foreach ($c in $mine) {
                $st = if ($c.Status -ne 'Valid' -or $c.DaysLeft -lt 0) { 'Fail' } elseif ($c.DaysLeft -lt $CertWarnDays) { 'Warn' } else { 'Pass' }
                Add-Check -Area 'Certificates' -Check "Public certificate for $HybridHostName on this server" -Status $st -Detail "$($c.Thumbprint) | $($c.Issuer) | expires $($c.NotAfter) ($($c.DaysLeft) days) | Services: $($c.Services)" -Reference $Ref.Cert
                Add-Check -Area 'Certificates' -Check 'Hybrid certificate assigned to IIS and SMTP' -Status $(if ($c.Services -match 'IIS' -and $c.Services -match 'SMTP') { 'Pass' } else { 'Warn' }) -Detail "Services: $($c.Services). Microsoft: internet-facing servers need the commercial certificate with IIS and SMTP assigned. The http.sys binding check below is what IIS really serves." -Reference $Ref.Hybrid
            }
        }
    }

    # 2. http.sys bindings (what IIS really serves) -------------------------------------------------
    Invoke-Step -Name 'http.sys SSL bindings' -Body {
        $raw = @(& netsh http show sslcert 2>&1 | ForEach-Object { "$_" })
        $raw | Out-File -FilePath (Join-Path $RunDir "netsh-sslcert-$Stamp.txt") -Encoding UTF8
        $rows = @(ConvertFrom-NetshSslCert -Lines $raw)
        $rows = foreach ($r in $rows) {
            $m = $Script:CertMap[$r.CertificateHash]
            [pscustomobject]@{ Binding = $r.Binding; CertificateHash = $r.CertificateHash; StoreName = $r.StoreName; Subject = $(if ($m) { $m.Subject } else { 'not an Exchange certificate / unknown' })
                RootCAType = $(if ($m) { $m.RootCAType } else { 'NotAssessed' }); CoversHybridName = $(if ($m) { Test-NameCovered -HostName $HybridHostName -Text $m.Domains } else { 'NotAssessed' }) }
        }
        Add-Data 'http.sys SSL bindings (this server)' $rows
        $main = @($rows | Where-Object { $_.Binding -in @('0.0.0.0:443', '[::]:443') })
        if ($main.Count -eq 0) { Add-Check -Area 'Certificates' -Check 'Certificate bound to 0.0.0.0:443' -Status NotAssessed -Detail 'No 0.0.0.0:443 binding parsed; see netsh-sslcert file.' }
        foreach ($b in $main) {
            $good = $b.RootCAType -eq 'ThirdParty' -and "$($b.CoversHybridName)" -eq 'True'
            Add-Check -Area 'Certificates' -Check "Certificate IIS serves on $($b.Binding)" -Status $(if ($good) { 'Pass' } else { 'Fail' }) -Detail "$($b.CertificateHash) | $($b.Subject) | RootCAType=$($b.RootCAType) | covers hybrid name=$($b.CoversHybridName). Exchange Online only trusts a commercial CA certificate that covers $HybridHostName." -Reference $Ref.Cert
        }
        foreach ($b in @($rows | Where-Object { $_.Binding -notmatch '^(0\.0\.0\.0|\[::\]|127\.0\.0\.1):' -and $_.Binding -match ':443$' })) {
            Add-Check -Area 'Certificates' -Check "Extra 443 binding $($b.Binding)" -Status Info -Detail "Host-name or IP specific binding with $($b.CertificateHash) ($($b.Subject))."
        }
    }

    # 3. IIS configuration ---------------------------------------------------------------------------
    if ($haveIis) {
        Invoke-Step -Name 'IIS configuration for EWS' -Body {
            $loc = 'Default Web Site/EWS'; $wa = 'system.webServer/security/authentication/windowsAuthentication'
            $providers = @(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $loc -Filter "$wa/providers/add" | ForEach-Object { $_.value })
            $row = [pscustomobject]@{
                Location = $loc; WindowsAuthEnabled = Get-IisValue $loc $wa 'enabled'; Providers = $providers -join ', '; UseKernelMode = Get-IisValue $loc $wa 'useKernelMode'
                ExtendedProtectionTokenChecking = Get-IisValue $loc "$wa/extendedProtection" 'tokenChecking'
                BasicAuthEnabled = Get-IisValue $loc 'system.webServer/security/authentication/basicAuthentication' 'enabled'
                AnonymousAuthEnabled = Get-IisValue $loc 'system.webServer/security/authentication/anonymousAuthentication' 'enabled'
                SslFlags = Get-IisValue $loc 'system.webServer/security/access' 'sslFlags'
            }
            Add-Data 'IIS EWS authentication' $row
            Add-Check -Area 'IIS' -Check 'NTLM provider on EWS' -Status $(if ($providers -contains 'NTLM') { 'Pass' } else { 'Fail' }) -Detail "Providers: $($row.Providers). Exchange Online signs in to /ews/mrsproxy.svc with Negotiate, which falls back to NTLM over the internet." -Reference $Ref.Ports
            $handler = @(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $loc -Filter 'system.webServer/handlers/add' | Where-Object { $_.name -like 'svc-Integrated*' })
            Add-Check -Area 'IIS' -Check 'svc-Integrated handler mapping on EWS' -Status $(if ($handler.Count -gt 0) { 'Pass' } else { 'Fail' }) -Detail "Found $($handler.Count). Missing handler causes HTTP 405 on mrsproxy.svc." -Reference $Ref.Handler
            $app = Get-WebApplication -Site 'Default Web Site' -Name 'EWS'
            $pool = if ($app) { $app.applicationPool } else { '' }
            $state = if ($pool) { (Get-WebAppPoolState -Name $pool).Value } else { 'NotAssessed' }
            Add-Check -Area 'IIS' -Check 'EWS application pool' -Status $(if ($state -eq 'Started') { 'Pass' } else { 'Fail' }) -Detail "Pool '$pool' state $state"
            Add-Data 'IIS Default Web Site HTTPS bindings' (Get-WebBinding -Name 'Default Web Site' -Protocol https | Select-Object protocol, bindingInformation, sslFlags, certificateHash)
        }
    } else { Add-Check -Area 'IIS' -Check 'IIS configuration' -Status NotAssessed -Detail 'WebAdministration module not available.' }

    # 4. Live TLS + HTTP probe ----------------------------------------------------------------------
    Invoke-Step -Name 'TLS and HTTP probe' -Body {
        $targets = New-Object System.Collections.Generic.List[string]
        $targets.Add('127.0.0.1')
        foreach ($s in $Script:Servers) { if ($s.Fqdn) { $targets.Add("$($s.Fqdn)") } }
        if ($PublicIp) { $targets.Add($PublicIp) }
        $rows = foreach ($t in ($targets | Select-Object -Unique)) { Invoke-TlsProbe -Target $t -SniName $HybridHostName }
        $rows = foreach ($r in $rows) { $m = $Script:CertMap["$($r.Thumbprint)"]; $r | Add-Member -NotePropertyName ExchangeRootCAType -NotePropertyValue $(if ($m) { $m.RootCAType } else { 'NotAssessed' }) -PassThru }
        Add-Data 'TLS probe (SNI = hybrid name)' $rows
        foreach ($r in $rows) {
            if (-not $r.Reachable) {
                $st = if ($PublicIp -and $r.Target -eq $PublicIp) { 'Info' } else { 'Warn' }
                Add-Check -Area 'TLS' -Check "TLS to $($r.Target)" -Status $st -Detail "Not reachable: $($r.Error)$(if ($st -eq 'Info') { ' (expected when the firewall only allows Microsoft IPs to the public address)' })"; continue
            }
            $good = "$($r.NameCoversHybrid)" -eq 'True' -and $r.ExchangeRootCAType -ne 'Registry' -and $r.Subject -notmatch '\.local\b'
            Add-Check -Area 'TLS' -Check "Certificate served by $($r.Target)" -Status $(if ($good) { 'Pass' } else { 'Fail' }) -Detail "$($r.Subject) | issuer $($r.Issuer) | $($r.Thumbprint) | covers hybrid name=$($r.NameCoversHybrid) | RootCAType=$($r.ExchangeRootCAType) | $($r.Protocol)" -Reference $Ref.Cert
            if ($r.HttpStatusLine) {
                $offers = $r.WwwAuthenticate
                Add-Check -Area 'Authentication' -Check "mrsproxy.svc challenge from $($r.Target)" -Status $(if ($offers -match 'NTLM|Negotiate') { 'Pass' } else { 'Warn' }) -Detail "$($r.HttpStatusLine) | WWW-Authenticate: $offers"
            }
        }
    }

    # 5. Sign-in probe -------------------------------------------------------------------------------
    if ($TestCredential) {
        Invoke-Step -Name 'NTLM sign-in probe' -Body {
            $credArgs = @{ Message = 'Endpoint account (DOMAIN\user) for the NTLM sign-in probe. The password is not logged.' }
            if ($EndpointAccount) { $credArgs.UserName = $EndpointAccount }
            $cred = Get-Credential @credArgs
            if (-not $cred) { Add-Check -Area 'Authentication' -Check 'NTLM sign-in probe' -Status NotAssessed -Detail 'No credential entered (prompt cancelled or empty).'; return }
            Write-Log INFO "Sign-in probe as $($cred.UserName) (password <redacted>)"
            $fqdns = @($Script:Servers | ForEach-Object { "$($_.Fqdn)" } | Where-Object { $_ })
            if ($fqdns.Count -eq 0) { $fqdns = @([Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName) }
            $rows = foreach ($f in $fqdns) { Invoke-AuthProbe -ServerFqdn $f -HostHeader $HybridHostName -Credential $cred }
            Add-Data 'NTLM sign-in probe' $rows
            foreach ($r in $rows) {
                if ($r.Error) { Add-Check -Area 'Authentication' -Check "NTLM sign-in on $($r.Server)" -Status NotAssessed -Detail $r.Error; continue }
                $st = if ("$($r.HttpStatus)" -eq '401') { 'Fail' } else { 'Pass' }
                Add-Check -Area 'Authentication' -Check "NTLM sign-in on $($r.Server)" -Status $st -Detail "HTTP $($r.HttpStatus) as $($r.User). 401 = server rejected the sign-in; any other code = sign-in accepted (MRSProxy may still answer 4xx to a plain GET)." -Reference $Ref.IisCodes
            }
        }
    }

    # 6. TLS registry --------------------------------------------------------------------------------
    Invoke-Step -Name 'TLS registry' -Body {
        $rows = foreach ($p in 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3') {
            foreach ($side in 'Server', 'Client') {
                $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\$side"
                $i = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                [pscustomobject]@{ Setting = "$p $side"; Enabled = $(if ($i -and $i.PSObject.Properties['Enabled']) { $i.Enabled } else { 'NotSet (OS default)' }); DisabledByDefault = $(if ($i -and $i.PSObject.Properties['DisabledByDefault']) { $i.DisabledByDefault } else { 'NotSet (OS default)' }) }
            }
        }
        $net = foreach ($h in @(@{ Hive = '64-bit'; Key = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' }, @{ Hive = '32-bit'; Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' })) {
            $i = Get-ItemProperty -Path $h.Key -ErrorAction SilentlyContinue
            foreach ($n in 'SystemDefaultTlsVersions', 'SchUseStrongCrypto') {
                [pscustomobject]@{ Setting = ".NET 4 $($h.Hive) $n"; Enabled = $(if ($i -and $i.PSObject.Properties[$n]) { $i.$n } else { 'NotSet' }); DisabledByDefault = '' }
            }
        }
        Add-Data 'TLS registry' (@($rows) + @($net))
        $t12 = $rows | Where-Object { $_.Setting -eq 'TLS 1.2 Server' }
        Add-Check -Area 'TLS' -Check 'TLS 1.2 server side' -Status $(if ("$($t12.Enabled)" -eq '0' -or "$($t12.DisabledByDefault)" -eq '1') { 'Fail' } else { 'Pass' }) -Detail "Enabled=$($t12.Enabled) DisabledByDefault=$($t12.DisabledByDefault)" -Reference $Ref.Tls
        $bad = @($net | Where-Object { "$($_.Enabled)" -ne '1' })
        Add-Check -Area 'TLS' -Check '.NET SystemDefaultTlsVersions and SchUseStrongCrypto = 1' -Status $(if ($bad.Count -eq 0) { 'Pass' } else { 'Warn' }) -Detail $(if ($bad.Count -eq 0) { 'All four values are 1.' } else { 'Not 1: ' + (($bad | ForEach-Object { "$($_.Setting)=$($_.Enabled)" }) -join ', ') + '. Microsoft requires both explicitly set to 1 (Extended Protection prerequisites).' }) -Reference $Ref.EP
    }

    # 7. Logs ----------------------------------------------------------------------------------------
    $fromUtc = $StartTime.ToUniversalTime(); $toUtc = $EndTime.ToUniversalTime()
    Add-Check -Area 'Logs' -Check 'Log window' -Status Info -Detail "Local $($StartTime.ToString('yyyy-MM-dd HH:mm')) - $($EndTime.ToString('yyyy-MM-dd HH:mm')) = UTC $($fromUtc.ToString('yyyy-MM-dd HH:mm')) - $($toUtc.ToString('yyyy-MM-dd HH:mm')). IIS and move-report times are UTC."

    if ($haveIis) {
        Invoke-Step -Name 'IIS logs for /EWS/mrsproxy.svc' -Body {
            $site = Get-Website -Name 'Default Web Site'
            $dir = Join-Path ([Environment]::ExpandEnvironmentVariables($site.logFile.directory)) "W3SVC$($site.id)"
            $files = @(Get-ChildItem -Path $dir -Filter '*.log' -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $StartTime } | Sort-Object LastWriteTime | ForEach-Object { $_.FullName })
            Write-Log INFO "IIS log folder $dir, $($files.Count) file(s) in window"
            $hits = @(Read-W3CLog -Files $files -Pattern 'mrsproxy.svc' -FromUtc $fromUtc -ToUtc $toUtc)
            $hits = @(foreach ($h in $hits) {
                $cip = if ($h.PSObject.Properties['c-ip']) { $h.'c-ip' } else { '' }
                $h | Add-Member -NotePropertyName ClientIpInExoRanges -NotePropertyValue (Test-IpInRange -Ip $cip -Ranges $Script:ExoRanges) -PassThru
            })
            Add-Data 'IIS mrsproxy requests' $hits
            if ($hits.Count -eq 0) {
                Add-Check -Area 'Logs' -Check 'MRSProxy requests reached this server' -Status Warn -Detail "No /EWS/mrsproxy.svc requests in $($files.Count) IIS log file(s) for the window. The firewall sends them to another server, or they are stopped before IIS (firewall, TLS)."
            } else {
                $sum = $hits | Group-Object { "$($_.'sc-status').$($_.'sc-substatus') win32=$($_.'sc-win32-status')" } | ForEach-Object {
                    $f = $_.Group[0]
                    [pscustomobject]@{ Result = $_.Name; Count = $_.Count; Meaning = Get-IisAuthMeaning -Status $f.'sc-status' -SubStatus $f.'sc-substatus' -Win32 $f.'sc-win32-status'
                        HttpStatus = "$($f.'sc-status').$($f.'sc-substatus')"; Win32Text = Get-Win32Text $f.'sc-win32-status'
                        FirstUtc = ($_.Group | Select-Object -First 1).DateTimeUtc; LastUtc = ($_.Group | Select-Object -Last 1).DateTimeUtc
                        Users = (@($_.Group | ForEach-Object { $_.'cs-username' } | Sort-Object -Unique) -join ', '); ClientIps = (@($_.Group | ForEach-Object { $_.'c-ip' } | Sort-Object -Unique | Select-Object -First 10) -join ', ') }
                }
                Add-Data 'IIS mrsproxy summary' $sum
                $ok = @($hits | Where-Object { $_.'sc-status' -eq '200' }).Count
                # 401.1 with Win32 0x8009030E is the normal NTLM challenge step (a 200 follows); only other 401.1 codes are rejections.
                $rejected = @($hits | Where-Object { $_.'sc-status' -eq '401' -and $_.'sc-substatus' -eq '1' -and $_.'sc-win32-status' -ne $NtlmChallengeWin32 })
                $f401 = $rejected.Count
                Add-Check -Area 'Logs' -Check 'MRSProxy requests reached this server' -Status Pass -Detail "$($hits.Count) request(s); HTTP 200 (signed in): $ok; rejected sign-ins: $f401 (normal NTLM handshake steps not counted)"
                if ($f401 -gt 0) {
                    $why = ($rejected | Group-Object 'sc-win32-status' | ForEach-Object { "$(Get-Win32Text $_.Name) x$($_.Count)" }) -join '; '
                    Add-Check -Area 'Authentication' -Check 'Sign-ins rejected on mrsproxy.svc (IIS 401.1)' -Status Fail -Detail "$f401 rejected: $why. Last at $(($rejected | Select-Object -Last 1).DateTimeUtc) UTC from $((@($rejected | ForEach-Object { $_.'c-ip' } | Sort-Object -Unique)) -join ', '). Security 4625 below / DC 4776 give the account reason." -Reference $Ref.IisCodes
                }
                $ips = @($hits | ForEach-Object { $_.'c-ip' } | Sort-Object -Unique)
                $outside = @($hits | Where-Object { $_.ClientIpInExoRanges -eq 'NotInRange' } | ForEach-Object { $_.'c-ip' } | Sort-Object -Unique)
                Add-Check -Area 'Network' -Check 'Source IPs seen by IIS' -Status Info -Detail ("$($ips.Count) source IP(s): " + (($ips | Select-Object -First 10) -join ', ') + $(if ($outside.Count) { ". Not in Exchange Online ranges: $($outside -join ', ') - the firewall source-NATs or proxies the traffic." } else { '' }))
            }
        }
    }

    Invoke-Step -Name 'HTTPERR log' -Body {
        $dir = Join-Path $env:windir 'System32\LogFiles\HTTPERR'
        $files = @(Get-ChildItem -Path $dir -Filter 'httperr*.log' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $StartTime } | ForEach-Object { $_.FullName })
        $rows = @(Read-W3CLog -Files $files -Pattern '' -FromUtc $fromUtc -ToUtc $toUtc | Where-Object { -not $_.PSObject.Properties['s-port'] -or $_.'s-port' -eq '443' })
        Add-Data 'HTTPERR (port 443)' $rows
        if ($rows.Count -gt 0) { Add-Data 'HTTPERR summary' ($rows | Group-Object 's-reason' | Select-Object @{n = 'Reason'; e = { $_.Name } }, Count) }
        Add-Check -Area 'Logs' -Check 'http.sys errors on 443' -Status Info -Detail "$($rows.Count) HTTPERR line(s). Connection_Dropped / Timer_* reasons point to network or timeouts before IIS."
    }

    Invoke-Step -Name 'Application log (MRS / ASP.NET)' -Body {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = $StartTime; EndTime = $EndTime } -ErrorAction SilentlyContinue |
            Where-Object { ($_.ProviderName -match '^ASP\.NET' -and $_.Id -eq 1309) -or ($_.ProviderName -match '^MSExchange' -and $_.Message -match 'MRS|Mailbox Replication|mrsproxy') })
        Add-Data 'Application events (MRS, ASP.NET 1309)' ($ev | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, @{n = 'Message'; e = { ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(1500, ($_.Message -replace '\s+', ' ').Length)) } })
        $disabled = @($ev | Where-Object { $_.Message -match 'MRS proxy service is disabled' })
        if ($disabled.Count) { Add-Check -Area 'MRSProxy' -Check 'ASP.NET 1309 "MRS proxy service is disabled"' -Status Fail -Detail "$($disabled.Count) event(s)." -Reference $Ref.Mrs403 }
        Add-Check -Area 'Logs' -Check 'Application errors related to MRS' -Status Info -Detail "$($ev.Count) event(s) in window."
    }

    Invoke-Step -Name 'System log (Schannel)' -Body {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Schannel'; StartTime = $StartTime; EndTime = $EndTime } -ErrorAction SilentlyContinue)
        Add-Data 'Schannel events' ($ev | Select-Object TimeCreated, Id, LevelDisplayName, @{n = 'Message'; e = { ($_.Message -replace '\s+', ' ') } })
        Add-Check -Area 'TLS' -Check 'Schannel (TLS) events' -Status $(if ($ev.Count) { 'Warn' } else { 'Pass' }) -Detail "$($ev.Count) Schannel event(s) in window. TLS handshake failures on this server appear here."
    }

    Invoke-Step -Name 'Security log 4625 (failed logons)' -Body {
        if (-not $isAdmin) { Add-Check -Area 'Authentication' -Check 'Security 4625' -Status NotAssessed -Detail 'Needs an elevated session.'; return }
        $acct = if ($EndpointAccount) { ($EndpointAccount -split '\\')[-1] } else { '' }
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $StartTime; EndTime = $EndTime } -ErrorAction SilentlyContinue)
        $rows = foreach ($e in $ev) {
            $p = $e.Properties
            $user = "$($p[5].Value)"
            if ($acct -and $user -ne $acct) { continue }
            $sub = ConvertTo-HexStatus $p[9].Value; $st = ConvertTo-HexStatus $p[7].Value
            $why = if ($NtStatusText.ContainsKey($sub)) { $NtStatusText[$sub] } elseif ($NtStatusText.ContainsKey($st)) { $NtStatusText[$st] } else { 'See Microsoft event 4625 documentation' }
            [pscustomobject]@{ TimeCreated = $e.TimeCreated; Account = "$($p[6].Value)\$user"; Status = $st; SubStatus = $sub; Meaning = $why; LogonType = $p[10].Value; AuthPackage = $p[12].Value; Workstation = $p[13].Value; SourceIp = $p[19].Value }
        }
        $rows = @($rows)
        Add-Data 'Security 4625 failed logons' $rows
        if ($rows.Count -gt 0) {
            $top = ($rows | Group-Object Meaning | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; '
            Add-Check -Area 'Authentication' -Check "Failed logons$(if ($acct) { " for $acct" })" -Status Fail -Detail $top
        } else { Add-Check -Area 'Authentication' -Check "Failed logons$(if ($acct) { " for $acct" })" -Status Info -Detail 'No 4625 events in window (or failed-logon auditing is off). NTLM failures are also logged on the DC as 4776: run Get-HybridMoveAuthEvidence.ps1.' }
    }

    Invoke-Step -Name 'MRS log folders' -Body {
        if (-not $env:ExchangeInstallPath) { Add-Check -Area 'Logs' -Check 'Exchange logging folders' -Status NotAssessed -Detail 'ExchangeInstallPath not set.'; return }
        $root = Join-Path $env:ExchangeInstallPath 'Logging'
        $dirs = @(Get-ChildItem -Path $root -Directory -Recurse -Depth 2 -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'MailboxReplication|MRS' })
        $rows = foreach ($d in $dirs) { Get-ChildItem -Path $d.FullName -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $StartTime } | Select-Object @{n = 'Folder'; e = { $d.FullName } }, Name, Length, LastWriteTime }
        Add-Data 'MRS-related log files in window' $rows
        Add-Check -Area 'Logs' -Check 'MRS-related Exchange log folders' -Status Info -Detail "$($dirs.Count) folder(s) found under $root; files listed (not copied). Hand them to Microsoft Support if asked."
    }

    # 8. Network -------------------------------------------------------------------------------------
    Invoke-Step -Name 'Name resolution and outbound' -Body {
        $dns = @(Resolve-DnsName -Name $HybridHostName -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['IPAddress'] })
        Add-Data 'Internal DNS for hybrid name' ($dns | Select-Object Name, Type, IPAddress)
        Add-Check -Area 'Network' -Check "Internal DNS answer for $HybridHostName" -Status Info -Detail $(if ($dns.Count) { ($dns.IPAddress -join ', ') } else { 'No answer' })
        $out = Invoke-TlsProbe -Target 'outlook.office365.com' -SniName 'outlook.office365.com' -SkipHttp
        Add-Check -Area 'Network' -Check 'Outbound HTTPS to Exchange Online' -Status $(if ($out.Reachable -and -not $out.Error) { 'Pass' } else { 'Warn' }) -Detail $(if ($out.Reachable) { "TLS to outlook.office365.com OK ($($out.Protocol))" } else { $out.Error }) -Reference $Ref.Ports
        $wp = (& netsh winhttp show proxy 2>&1) -join ' '
        Add-Check -Area 'Network' -Check 'WinHTTP proxy' -Status Info -Detail ($wp -replace '\s+', ' ')
    }
}
catch {
    Write-ErrorDetail -ErrorRecord $_ -Step 'Fatal'
    $ExitCode = 2
}
finally {
    try {
        $html = Join-Path $RunDir "Report-$Stamp.html"
        $Script:Checks | Export-Csv -Path (Join-Path $RunDir "Checks-$Stamp.csv") -NoTypeInformation -Encoding UTF8
        Export-HtmlReport -Path $html -Title "Hybrid move evidence - $env:COMPUTERNAME" -Subtitle "$ScriptName $ScriptVersion | hybrid name $HybridHostName | window $($StartTime.ToString('yyyy-MM-dd HH:mm')) - $($EndTime.ToString('yyyy-MM-dd HH:mm')) local | run $($StartRun.ToString('yyyy-MM-dd HH:mm'))"
        Write-Log INFO "HTML report: $html"
    } catch { Write-ErrorDetail -ErrorRecord $_ -Step 'Write report'; if ($ExitCode -eq 0) { $ExitCode = 1 } }
    if ($ExitCode -eq 0 -and $Script:StepFailed -gt 0) { $ExitCode = 1 }
    $c = $Script:Checks
    $end = Get-Date
    Write-Log INFO ("End $($end.ToString('o')) | Duration $([int]($end - $StartRun).TotalSeconds)s | steps ok $($Script:StepOk) / failed $($Script:StepFailed) | findings Fail $(@($c | Where-Object Status -EQ 'Fail').Count), Warn $(@($c | Where-Object Status -EQ 'Warn').Count), NotAssessed $(@($c | Where-Object Status -EQ 'NotAssessed').Count) | Exit code $ExitCode")
    Write-Information "Log file: $LogFile" -InformationAction Continue
}
exit $ExitCode
