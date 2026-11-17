<#
.SYNOPSIS
    Export who logged on where (Security event 4624) for CopperHound session data.

.DESCRIPTION
    SharpHound's session collection (NetSessionEnum, NetWkstaUserEnum) is blocked
    by default on current Windows versions. This script reads successful logons
    from the Security log (or from a Windows Event Forwarding collector's
    ForwardedEvents log), keeps the logon types that leave reusable credentials
    on the computer, and writes one record per computer, user and logon type with
    the first and last time seen:

        {"meta": {"type": "copperhound-logons", "version": 1, ...},
         "data": [{"computer": "WS01.CORP.LOCAL", "user": "S-1-5-21-...",
                   "logontype": 10, "first": "...", "last": "...", "count": 3}]}

    Upload the file to CopperHound like any collector output. Each record becomes
    a HasSession edge when CopperHound knows both the computer (by DNS name) and
    the user (by SID); nothing else is created.

    Network logons (type 3) are skipped: they leave no credentials behind.
    Only domain accounts (S-1-5-21-...) are kept; built-in and local accounts are
    dropped by CopperHound anyway.

    Reading the Security log needs local administrator rights on each computer
    (or membership in Event Log Readers) and, for remote computers, the Remote
    Event Log Management firewall rules. On a WEF collector, use
    -LogName ForwardedEvents and leave -ComputerName at its default.

.PARAMETER ComputerName
    Computers to read. Default: this computer.

.PARAMETER LogName
    Security (default) or ForwardedEvents on a Windows Event Forwarding collector.

.PARAMETER Days
    How far back to read. Default: 7.

.PARAMETER LogonTypes
    Logon types to keep. Default: 2, 4, 5, 7, 8, 9, 10, 11, 12, 13.

.PARAMETER OutFile
    Output file. Default: copperhound-logons-<yyyyMMddHHmmss>.json in the current directory.

.EXAMPLE
    .\Export-CopperHoundLogons.ps1 -ComputerName (Get-Content servers.txt) -Days 14

.EXAMPLE
    .\Export-CopperHoundLogons.ps1 -LogName ForwardedEvents -Days 30
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [ValidateSet('Security', 'ForwardedEvents')]
    [string]$LogName = 'Security',
    [ValidateRange(1, 3650)]
    [int]$Days = 7,
    [ValidateRange(0, 15)]
    [int[]]$LogonTypes = @(2, 4, 5, 7, 8, 9, 10, 11, 12, 13),
    [string]$OutFile = ("copperhound-logons-{0}.json" -f (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$since = (Get-Date).AddDays(-$Days)
$sinceMs = [int64]((Get-Date) - $since).TotalMilliseconds
$typeFilter = ($LogonTypes | ForEach-Object { "Data[@Name='LogonType']='$_'" }) -join ' or '
$xpath = "*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= $sinceMs]] and EventData[$typeFilter]]"

# computer|sid|type -> record
$sessions = @{}
$read = 0
$failed = @()

foreach ($computer in $ComputerName) {
    Write-Verbose "Reading $LogName on $computer"
    try {
        $params = @{ LogName = $LogName; FilterXPath = $xpath; ErrorAction = 'Stop' }
        if ($computer -and $computer -ne $env:COMPUTERNAME -and $computer -ne 'localhost' -and $computer -ne '.') {
            $params.ComputerName = $computer
        }
        $events = Get-WinEvent @params
    } catch [System.Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            continue
        }
        Write-Warning "${computer}: $($_.Exception.Message)"
        $failed += $computer
        continue
    }
    foreach ($e in $events) {
        $read++
        $data = @{}
        foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) {
            $data[$d.Name] = $d.'#text'
        }
        $sid = [string]$data['TargetUserSid']
        if (-not $sid.StartsWith('S-1-5-21-')) {
            continue
        }
        $type = [int]$data['LogonType']
        # MachineName is the FQDN of the computer that logged the event (also
        # for forwarded events).
        $host_ = ([string]$e.MachineName).ToUpperInvariant()
        $time = $e.TimeCreated.ToUniversalTime()
        $key = "$host_|$sid|$type"
        $r = $sessions[$key]
        if ($null -eq $r) {
            $sessions[$key] = [ordered]@{ computer = $host_; user = $sid; logontype = $type; first = $time; last = $time; count = 1 }
        } else {
            if ($time -lt $r.first) { $r.first = $time }
            if ($time -gt $r.last) { $r.last = $time }
            $r.count++
        }
    }
}

$data = @(
    $sessions.Values | Sort-Object computer, user, logontype | ForEach-Object {
        [ordered]@{
            computer  = $_.computer
            user      = $_.user
            logontype = $_.logontype
            first     = $_.first.ToString('yyyy-MM-ddTHH:mm:ssZ')
            last      = $_.last.ToString('yyyy-MM-ddTHH:mm:ssZ')
            count     = $_.count
        }
    }
)
$doc = [ordered]@{
    meta = [ordered]@{
        type      = 'copperhound-logons'
        version   = 1
        collected = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        days      = $Days
        log       = $LogName
        count     = $data.Count
    }
    data = $data
}
$json = $doc | ConvertTo-Json -Depth 4 -Compress
$path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
# UTF-8 without a byte order mark.
[System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding $false))
Write-Host ("{0} logon events read, {1} sessions written to {2}" -f $read, $data.Count, $path)
if ($failed.Count -gt 0) {
    Write-Warning ("Could not read: {0}" -f ($failed -join ', '))
}
