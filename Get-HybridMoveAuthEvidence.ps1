#Requires -Version 5.1
<#
.SYNOPSIS
    Collects read-only Active Directory evidence for the account a hybrid migration endpoint uses (state, password age,
    lockouts, NTLM validation results) and writes an HTML + CSV report.

.DESCRIPTION
    Run on a domain controller (best: the PDC emulator) in an elevated Windows PowerShell. When Exchange Online signs in
    to /EWS/mrsproxy.svc, the Exchange server passes the NTLM sign-in to a domain controller. The DC records the result:

      Account state     Enabled, locked out, password expired, password last set, per-DC bad password count/time.
      Domain policy     Lockout threshold, duration and observation window, maximum password age.
      Events            4776 (NTLM credential validation, with the error code and the Exchange server that asked),
                        4740 (account locked out, with the caller computer), 4625 (failed logon) for the account.

    Read-only: changes nothing in Active Directory or on the domain controllers. No module needed (uses ADSI).
    Cannot see: Exchange, IIS, the firewall or Exchange Online. Events exist only if the audit policy records them
    (Audit Credential Validation / Account Lockout / Logon); no events is reported as Info, not as "no failures".

    Sources (read 2026-10-16):
      https://learn.microsoft.com/exchange/hybrid-deployment-prerequisites  (mailbox migrations: NTLM to /ews/mrsproxy.svc)
      https://learn.microsoft.com/troubleshoot/exchange/move-or-migrate-mailboxes/troubleshoot-migration-issues-in-exchange-hybrid

.PARAMETER AccountName
    The endpoint account, as DOMAIN\user or user (sAMAccountName).

.PARAMETER StartTime
    Start of the event window (local time). Default: 24 hours ago.

.PARAMETER EndTime
    End of the event window (local time). Default: now.

.PARAMETER AllDomainControllers
    Also reads per-DC bad-password data and events from every domain controller (needs remote Event Log access).

.PARAMETER EvidencePath
    Case evidence folder. When given, results go to <EvidencePath>\DC\Get-HybridMoveAuthEvidence\... (the layout
    Get-HybridMoveVerdict.ps1 -EvidencePath reads) and -OutputPath is ignored. Run on the domain controller (local folder or a UNC share; copy the DC folder to the case evidence folder afterwards if needed).

.PARAMETER OutputPath
    Root output folder. Default C:\Scripts\Cannes. Results go to <OutputPath>\Get-HybridMoveAuthEvidence\<timestamp>\.

.EXAMPLE
    .\Get-HybridMoveAuthEvidence.ps1 -AccountName CONTOSO\migadmin
    Account state and this DC's events for the last 24 hours.

.EXAMPLE
    .\Get-HybridMoveAuthEvidence.ps1 -AccountName CONTOSO\migadmin -StartTime '2026-10-16 13:00' -AllDomainControllers
    Same, from 13:00, for every domain controller.

.OUTPUTS
    Report-<ts>.html, Checks-<ts>.csv and one CSV per data set; log in ...\Logs\.
    Exit codes: 0 all collection steps ran, 1 one or more steps failed (see NotAssessed rows), 2 could not run.

.NOTES
    Owner: Carlos Annes (TakeItToCloud)
    Version: 1.0.1
    Created: 2026-10-16
    Last updated: 2026-10-17
    Requires: Windows PowerShell 5.1 (default shell on the domain controllers), domain member, elevated session and
              rights to read the Security log (Domain Admins or Event Log Readers) on each DC queried.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^([^\\]+\\)?[^\\@]+$')][string]$AccountName,
    [datetime]$StartTime = (Get-Date).AddHours(-24),
    [datetime]$EndTime = (Get-Date),
    [switch]$AllDomainControllers,
    [string]$EvidencePath,
    [string]$OutputPath = 'C:\Scripts\Cannes'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -EvidencePath sends the results to <EvidencePath>\DC (case evidence layout read by Get-HybridMoveVerdict.ps1).
$OutputPathNote = ''
if ($EvidencePath) {
    if ($PSBoundParameters.ContainsKey('OutputPath')) { $OutputPathNote = "-EvidencePath given: -OutputPath '$OutputPath' ignored." }
    $OutputPath = Join-Path $EvidencePath 'DC'
}
# ---- Configuration --------------------------------------------------------------------------------
$ScriptName    = 'Get-HybridMoveAuthEvidence'
$ScriptVersion = '1.0.1'
$Stamp         = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunDir        = Join-Path (Join-Path $OutputPath $ScriptName) $Stamp
$LogDir        = Join-Path (Join-Path $OutputPath $ScriptName) 'Logs'
$LogFile       = Join-Path $LogDir "$ScriptName-$Stamp.log"
$StartRun      = Get-Date
$ExitCode      = 0
$Sam           = ($AccountName -split '\\')[-1]
$Script:Checks = New-Object System.Collections.Generic.List[object]
$Script:Data   = [ordered]@{}
$Script:StepOk = 0; $Script:StepFailed = 0
$RecentPasswordDays = 14

# NTSTATUS codes in 4776 / 4625 (Windows standard values).
$NtStatusText = @{
    '0x0' = 'Success'; '0xC000006A' = 'Wrong password'; '0xC0000064' = 'User name does not exist'
    '0xC000006D' = 'Logon failure (bad user name or authentication information)'; '0xC000006E' = 'Account restriction'
    '0xC000006F' = 'Logon outside allowed hours'; '0xC0000070' = 'Workstation restriction'; '0xC0000071' = 'Password expired'
    '0xC0000072' = 'Account disabled'; '0xC0000193' = 'Account expired'; '0xC0000224' = 'Password must change at next logon'
    '0xC0000234' = 'Account locked out'; '0xC000015B' = 'Logon type not granted on this computer'
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
    param([Parameter(Mandatory)]$ErrorRecord, [Parameter(Mandatory)][string]$Step, [string]$Item = $Sam)
    Write-Log ERROR "Step: $Step | Item: $Item"
    Write-Log ERROR "Message: $($ErrorRecord.Exception.Message)"
    Write-Log ERROR "Type: $($ErrorRecord.Exception.GetType().FullName)"
    Write-Log ERROR "Position: $($ErrorRecord.InvocationInfo.PositionMessage)"
    Write-Log ERROR "Stack: $($ErrorRecord.ScriptStackTrace)"
}

function Add-Check {
    <# .SYNOPSIS Adds one finding row: Pass | Warn | Fail | Info | NotAssessed. #>
    param([string]$Area, [string]$Check, [ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'NotAssessed')][string]$Status, [string]$Detail, [string]$Reference = '')
    $Script:Checks.Add([pscustomobject]@{ Area = $Area; Check = $Check; Status = $Status; Detail = $Detail; Reference = $Reference })
}

function Add-Data {
    <# .SYNOPSIS Stores a data set for the HTML report and exports it to CSV. #>
    param([Parameter(Mandatory)][string]$Name, [AllowNull()]$Rows)
    $list = @($Rows | Where-Object { $null -ne $_ })
    $Script:Data[$Name] = $list
    if ($list.Count -gt 0) {
        $file = Join-Path $RunDir (($Name -replace '[^A-Za-z0-9]+', '-') + "-$Stamp.csv")
        $list | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
        Write-Log INFO "$Name : $($list.Count) row(s) -> $file"
    } else { Write-Log INFO "$Name : 0 rows" }
}

function Invoke-Step {
    <# .SYNOPSIS Runs one collection step in its own try/catch; a failure becomes a NotAssessed row. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Body)
    Write-Log INFO "STEP start: $Name"
    try { & $Body; $Script:StepOk++; Write-Log INFO "STEP end: $Name" }
    catch {
        $Script:StepFailed++
        Write-ErrorDetail -ErrorRecord $_ -Step $Name
        Add-Check -Area $Name -Check 'Collection step' -Status NotAssessed -Detail "Step failed: $($_.Exception.Message)"
    }
}

function ConvertTo-HexStatus {
    <# .SYNOPSIS Formats an event status value (Int32/UInt32/string) as 0xXXXXXXXX. #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { if ($Value -match '^0x') { return $Value.ToUpper().Replace('0X', '0x') } ; $n = 0L; if (-not [long]::TryParse($Value, [ref]$n)) { return $Value } ; $Value = $n }
    $u = [BitConverter]::ToUInt32([BitConverter]::GetBytes([long]$Value), 0)
    return ('0x{0:X}' -f $u)
}

function Get-StatusText {
    <# .SYNOPSIS Plain-language meaning of an NTSTATUS hex code. #>
    param([string]$Hex)
    if ($NtStatusText.ContainsKey($Hex)) { return $NtStatusText[$Hex] } else { return 'Other - see Microsoft event documentation' }
}

function ConvertTo-LdapFilterValue {
    <# .SYNOPSIS Escapes a value for an LDAP filter (RFC 4515). #>
    param([string]$Value)
    return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00')
}

function Get-LdapBase {
    <# .SYNOPSIS Reads attributes of one object (base scope), optionally from a specific DC. #>
    param([string]$Dn, [string[]]$Attributes, [string]$Server)
    $path = if ($Server) { "LDAP://$Server/$Dn" } else { "LDAP://$Dn" }
    $s = New-Object DirectoryServices.DirectorySearcher([ADSI]$path, '(objectClass=*)')
    $s.SearchScope = 'Base'
    foreach ($a in $Attributes) { [void]$s.PropertiesToLoad.Add($a) }
    return $s.FindOne()
}

function Get-LdapValue {
    <# .SYNOPSIS First value of an attribute from a SearchResult, or $null. #>
    param($Result, [string]$Name)
    $k = $Name.ToLower()
    if ($Result -and $Result.Properties.Contains($k) -and $Result.Properties[$k].Count -gt 0) { return $Result.Properties[$k][0] }
    return $null
}

function ConvertFrom-FileTimeValue {
    <# .SYNOPSIS FILETIME (Int64) to local date text; 0 / max mean "never". #>
    param($Value)
    if ($null -eq $Value) { return 'NotAssessed' }
    $v = [long]$Value
    if ($v -le 0 -or $v -eq [long]::MaxValue) { return 'Never' }
    return [DateTime]::FromFileTime($v).ToString('yyyy-MM-dd HH:mm:ss')
}

function ConvertFrom-IntervalValue {
    <# .SYNOPSIS AD negative 100-ns interval to a readable duration. #>
    param($Value)
    if ($null -eq $Value) { return 'NotAssessed' }
    $v = [long]$Value
    if ($v -eq [long]::MinValue) { return 'Never (until an administrator unlocks / no expiry)' }
    if ($v -eq 0) { return '0' }
    return ([TimeSpan]::FromTicks([Math]::Abs($v))).ToString()
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

$Script:Dn = $null; $Script:Dcs = @(); $Script:Pdc = ''

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Add-Check -Area 'Run' -Check 'Elevated session' -Status $(if ($isAdmin) { 'Pass' } else { 'Warn' }) -Detail "Administrator: $isAdmin (needed for the Security log)"

    Invoke-Step -Name 'Domain and domain controllers' -Body {
        $d = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $Script:Pdc = "$($d.PdcRoleOwner.Name)"
        $Script:Dcs = @($d.DomainControllers | ForEach-Object { "$($_.Name)" })
        Add-Data 'Domain controllers' ($d.DomainControllers | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Site = "$($_.SiteName)"; IsPdc = ("$($_.Name)" -eq $Script:Pdc); OSVersion = "$($_.OSVersion)" } })
        $here = [Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        Add-Check -Area 'Domain' -Check 'Where this runs' -Status Info -Detail "Domain $($d.Name) | PDC emulator $Script:Pdc | this computer $here | DCs: $($Script:Dcs.Count). Lockouts (4740) are logged on the PDC emulator."
    }

    Invoke-Step -Name 'Domain password and lockout policy' -Body {
        $nc = ([ADSI]'LDAP://RootDSE').defaultNamingContext
        $r = Get-LdapBase -Dn "$nc" -Attributes @('lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow', 'maxPwdAge', 'minPwdAge')
        $row = [pscustomobject]@{ LockoutThreshold = Get-LdapValue $r 'lockoutThreshold'; LockoutDuration = ConvertFrom-IntervalValue (Get-LdapValue $r 'lockoutDuration')
            LockoutObservationWindow = ConvertFrom-IntervalValue (Get-LdapValue $r 'lockOutObservationWindow'); MaxPasswordAge = ConvertFrom-IntervalValue (Get-LdapValue $r 'maxPwdAge') }
        Add-Data 'Domain policy' $row
        Add-Check -Area 'Domain' -Check 'Lockout policy' -Status Info -Detail "Threshold $($row.LockoutThreshold) | duration $($row.LockoutDuration) | window $($row.LockoutObservationWindow). Each failed migration retry with a wrong password counts toward the threshold. Fine-grained password policies are not read."
    }

    Invoke-Step -Name 'Account state' -Body {
        $nc = ([ADSI]'LDAP://RootDSE').defaultNamingContext
        $s = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$nc", "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$(ConvertTo-LdapFilterValue $Sam)))")
        foreach ($a in 'distinguishedName', 'userAccountControl', 'lockoutTime', 'pwdLastSet', 'accountExpires', 'lastLogonTimestamp', 'adminCount') { [void]$s.PropertiesToLoad.Add($a) }
        $res = $s.FindOne()
        if (-not $res) { Add-Check -Area 'Account' -Check "Account $Sam" -Status Fail -Detail 'Not found in the domain.'; return }
        $Script:Dn = "$(Get-LdapValue $res 'distinguishedName')"
        $uac = [int](Get-LdapValue $res 'userAccountControl')
        $comp = [int](Get-LdapValue (Get-LdapBase -Dn $Script:Dn -Attributes @('msDS-User-Account-Control-Computed')) 'msDS-User-Account-Control-Computed')
        $pwdSetRaw = Get-LdapValue $res 'pwdLastSet'
        $row = [pscustomobject]@{ Account = $Sam; DistinguishedName = $Script:Dn; Enabled = -not ($uac -band 0x2); LockedOut = [bool]($comp -band 0x10); PasswordExpired = [bool]($comp -band 0x800000)
            PasswordNeverExpires = [bool]($uac -band 0x10000); PasswordLastSet = ConvertFrom-FileTimeValue $pwdSetRaw; LockoutTime = ConvertFrom-FileTimeValue (Get-LdapValue $res 'lockoutTime')
            AccountExpires = ConvertFrom-FileTimeValue (Get-LdapValue $res 'accountExpires'); LastLogonTimestamp = ConvertFrom-FileTimeValue (Get-LdapValue $res 'lastLogonTimestamp'); AdminCount = Get-LdapValue $res 'adminCount' }
        Add-Data 'Account state' $row
        Add-Check -Area 'Account' -Check 'Enabled' -Status $(if ($row.Enabled) { 'Pass' } else { 'Fail' }) -Detail "Enabled=$($row.Enabled)"
        Add-Check -Area 'Account' -Check 'Locked out' -Status $(if ($row.LockedOut) { 'Fail' } else { 'Pass' }) -Detail "LockedOut=$($row.LockedOut) | lockoutTime $($row.LockoutTime)"
        Add-Check -Area 'Account' -Check 'Password expired' -Status $(if ($row.PasswordExpired) { 'Fail' } else { 'Pass' }) -Detail "PasswordExpired=$($row.PasswordExpired) | never expires=$($row.PasswordNeverExpires)"
        $recent = $false
        if ($row.PasswordLastSet -match '^\d{4}-') { $recent = ([datetime]$row.PasswordLastSet) -gt (Get-Date).AddDays(-$RecentPasswordDays) }
        Add-Check -Area 'Account' -Check 'Password last set' -Status $(if ($recent) { 'Warn' } else { 'Info' }) -Detail "$($row.PasswordLastSet).$(if ($recent) { " Changed in the last $RecentPasswordDays days: if the migration endpoint was saved before this date, its password is old (Set-MigrationEndpoint -Credentials)." })"
    }

    Invoke-Step -Name 'Per-DC bad password data' -Body {
        if (-not $Script:Dn) { Add-Check -Area 'Account' -Check 'Per-DC bad password data' -Status NotAssessed -Detail 'Account not resolved.'; return }
        $targets = if ($AllDomainControllers) { $Script:Dcs } else { @('') }
        $rows = foreach ($dc in $targets) {
            try {
                $r = Get-LdapBase -Dn $Script:Dn -Attributes @('badPwdCount', 'badPasswordTime', 'lastLogon') -Server $dc
                [pscustomobject]@{ DomainController = $(if ($dc) { $dc } else { "$env:COMPUTERNAME (default)" }); BadPwdCount = Get-LdapValue $r 'badPwdCount'; BadPasswordTime = ConvertFrom-FileTimeValue (Get-LdapValue $r 'badPasswordTime'); LastLogon = ConvertFrom-FileTimeValue (Get-LdapValue $r 'lastLogon'); Error = '' }
            } catch { [pscustomobject]@{ DomainController = $dc; BadPwdCount = ''; BadPasswordTime = ''; LastLogon = ''; Error = $_.Exception.Message } }
        }
        $rows = @($rows)
        Add-Data 'Per-DC bad password data' $rows
        $bad = @($rows | Where-Object { "$($_.BadPwdCount)" -match '^\d+$' -and [int]$_.BadPwdCount -gt 0 })
        Add-Check -Area 'Account' -Check 'Recent bad passwords (per DC, not replicated)' -Status $(if ($bad.Count) { 'Warn' } else { 'Info' }) -Detail $(if ($bad.Count) { ($bad | ForEach-Object { "$($_.DomainController): $($_.BadPwdCount) at $($_.BadPasswordTime)" }) -join '; ' } else { 'badPwdCount 0 on the DCs read.' })
    }

    Invoke-Step -Name 'Security events 4776 / 4740 / 4625' -Body {
        if (-not $isAdmin) { Add-Check -Area 'Events' -Check 'Security log' -Status NotAssessed -Detail 'Needs an elevated session.'; return }
        $targets = if ($AllDomainControllers) { $Script:Dcs } else { @('') }
        $v4776 = New-Object System.Collections.Generic.List[object]; $v4740 = New-Object System.Collections.Generic.List[object]; $v4625 = New-Object System.Collections.Generic.List[object]
        foreach ($dc in $targets) {
            $wevArgs = @{ FilterHashtable = @{ LogName = 'Security'; Id = 4776, 4740, 4625; StartTime = $StartTime; EndTime = $EndTime }; ErrorAction = 'Stop' }
            if ($dc) { $wevArgs.ComputerName = $dc }
            $name = if ($dc) { $dc } else { $env:COMPUTERNAME }
            try { $ev = @(Get-WinEvent @wevArgs) }
            catch {
                if ($_.Exception.Message -match 'No events were found') { $ev = @() }
                else { Write-ErrorDetail -ErrorRecord $_ -Step 'Get-WinEvent' -Item $name; Add-Check -Area 'Events' -Check "Security log on $name" -Status NotAssessed -Detail $_.Exception.Message; continue }
            }
            foreach ($e in $ev) {
                $p = $e.Properties
                switch ($e.Id) {
                    4776 { if ("$($p[1].Value)" -ne $Sam) { break }; $st = ConvertTo-HexStatus $p[3].Value
                        $v4776.Add([pscustomobject]@{ DC = $name; TimeCreated = $e.TimeCreated; Account = "$($p[1].Value)"; Workstation = "$($p[2].Value)"; Status = $st; Meaning = Get-StatusText $st }) }
                    4740 { if ("$($p[0].Value)" -ne $Sam) { break }
                        $v4740.Add([pscustomobject]@{ DC = $name; TimeCreated = $e.TimeCreated; Account = "$($p[0].Value)"; CallerComputer = "$($p[1].Value)" }) }
                    4625 { if ("$($p[5].Value)" -ne $Sam) { break }; $sub = ConvertTo-HexStatus $p[9].Value
                        $v4625.Add([pscustomobject]@{ DC = $name; TimeCreated = $e.TimeCreated; Account = "$($p[6].Value)\$($p[5].Value)"; Status = ConvertTo-HexStatus $p[7].Value; SubStatus = $sub; Meaning = Get-StatusText $sub; LogonType = $p[10].Value; AuthPackage = $p[12].Value; Workstation = $p[13].Value; SourceIp = $p[19].Value }) }
                }
            }
        }
        Add-Data '4776 NTLM credential validation' $v4776
        Add-Data '4740 account lockouts' $v4740
        Add-Data '4625 failed logons' $v4625
        $fail = @($v4776 | Where-Object Status -NE '0x0')
        if ($v4776.Count -eq 0) { Add-Check -Area 'Events' -Check "NTLM validation (4776) for $Sam" -Status Info -Detail 'No 4776 events in window on the DCs read (other DC validated it, or Audit Credential Validation is off). Try -AllDomainControllers.' }
        elseif ($fail.Count) {
            $top = ($fail | Group-Object Meaning | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; '
            $ws = (@($fail | ForEach-Object Workstation | Sort-Object -Unique)) -join ', '
            Add-Check -Area 'Events' -Check "NTLM validation failures (4776) for $Sam" -Status Fail -Detail "$top | asked by: $ws | last $(($fail | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated)"
        } else { Add-Check -Area 'Events' -Check "NTLM validation (4776) for $Sam" -Status Pass -Detail "$($v4776.Count) successful validation(s) in window." }
        Add-Check -Area 'Events' -Check "Lockouts (4740) for $Sam" -Status $(if ($v4740.Count) { 'Fail' } else { 'Info' }) -Detail $(if ($v4740.Count) { "$($v4740.Count) lockout(s); caller: " + ((@($v4740 | ForEach-Object CallerComputer | Sort-Object -Unique)) -join ', ') } else { 'None in window on the DCs read (4740 is logged on the PDC emulator).' })
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
        Export-HtmlReport -Path $html -Title "Hybrid move evidence - account $Sam" -Subtitle "$ScriptName $ScriptVersion | $env:COMPUTERNAME | window $($StartTime.ToString('yyyy-MM-dd HH:mm')) - $($EndTime.ToString('yyyy-MM-dd HH:mm')) local | run $($StartRun.ToString('yyyy-MM-dd HH:mm'))"
        Write-Log INFO "HTML report: $html"
    } catch { Write-ErrorDetail -ErrorRecord $_ -Step 'Write report'; if ($ExitCode -eq 0) { $ExitCode = 1 } }
    if ($ExitCode -eq 0 -and $Script:StepFailed -gt 0) { $ExitCode = 1 }
    $c = $Script:Checks; $end = Get-Date
    Write-Log INFO ("End $($end.ToString('o')) | Duration $([int]($end - $StartRun).TotalSeconds)s | steps ok $($Script:StepOk) / failed $($Script:StepFailed) | findings Fail $(@($c | Where-Object Status -EQ 'Fail').Count), Warn $(@($c | Where-Object Status -EQ 'Warn').Count), NotAssessed $(@($c | Where-Object Status -EQ 'NotAssessed').Count) | Exit code $ExitCode")
    Write-Information "Log file: $LogFile" -InformationAction Continue
}
exit $ExitCode
