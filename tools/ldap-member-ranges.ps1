<#
.SYNOPSIS
  Fetch the remaining `member` ranges of large groups in an LDIF dump.

.DESCRIPTION
  Active Directory returns at most MaxValRange (1500 by default) values of a
  multi-valued attribute per read; ldapsearch / ldifde then write
  `member;range=0-1499: ...` and stop. This script finds every entry of the
  dump that holds such a first range, reads the rest with ranged base reads
  (`member;range=1500-*`, ...) through System.DirectoryServices, and writes
  continuation entries:

    dn:: <base64 DN>
    member;range=1500-2999:: <base64 member DN>

  Put the output next to the dump (same upload / directory): CopperHound adds
  continuation entries to the group's membership (see docs/DATA.md "Importing
  multiple dumps"). Runs on any domain-joined Windows host with Windows
  PowerShell 5.1 or PowerShell 7; no RSAT module needed.

.EXAMPLE
  .\tools\ldap-member-ranges.ps1 -Dump corp-domain.ldif -Server dc01.corp.local -Out corp-member-ranges.ldif

.EXAMPLE
  $c = Get-Credential
  .\tools\ldap-member-ranges.ps1 -Dump corp-domain.ldif -Server dc01.corp.local -Credential $c -Out corp-member-ranges.ldif
#>
param(
    [Parameter(Mandatory = $true)][string]$Dump,
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Out,
    [System.Management.Automation.PSCredential]$Credential
)
$ErrorActionPreference = 'Stop'

function B64([string]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

# Unfold LDIF continuation lines.
$lines = New-Object System.Collections.Generic.List[string]
foreach ($l in [IO.File]::ReadLines((Resolve-Path $Dump))) {
    if ($l.StartsWith(' ') -and $lines.Count -gt 0) { $lines[$lines.Count - 1] += $l.Substring(1) } else { $lines.Add($l) }
}

# DN -> last index of the first range, for entries with `member;range=0-N`.
$groups = [ordered]@{}
$dn = $null
foreach ($l in $lines) {
    if ($l -eq '') { $dn = $null; continue }
    if ($l -match '^dn:: (.*)$') { $dn = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches[1].Trim())); continue }
    if ($l -match '^dn: (.*)$') { $dn = $Matches[1]; continue }
    if ($dn -and $l -match '^(?i)member;range=0-(\d+):' -and -not $groups.Contains($dn)) { $groups[$dn] = [int]$Matches[1] }
}

$w = New-Object IO.StreamWriter($Out, $false, (New-Object Text.UTF8Encoding($false)))
$w.NewLine = "`n"
try {
    foreach ($g in $groups.Keys) {
        $start = $groups[$g] + 1
        $path = "LDAP://$Server/$g"
        $entry = if ($Credential) {
            New-Object DirectoryServices.DirectoryEntry($path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            New-Object DirectoryServices.DirectoryEntry($path)
        }
        while ($true) {
            $s = New-Object DirectoryServices.DirectorySearcher($entry, '(objectClass=*)', @("member;range=$start-*"), 'Base')
            $r = $s.FindOne()
            if (-not $r) { break }
            $name = $r.Properties.PropertyNames | Where-Object { $_ -like 'member;range=*' } | Select-Object -First 1
            if (-not $name) { break }
            $w.WriteLine("dn:: $(B64 $g)")
            foreach ($v in $r.Properties[$name]) { $w.WriteLine("${name}:: $(B64 ([string]$v))") }
            $w.WriteLine('')
            $hi = $name.Split('-')[-1]
            if ($hi -eq '*') { break }
            $start = [int]$hi + 1
        }
    }
} finally {
    $w.Close()
}
Write-Host "ldap-member-ranges: completed $($groups.Count) group(s) -> $Out"
