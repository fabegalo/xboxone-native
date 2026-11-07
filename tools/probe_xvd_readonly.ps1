# SPDX-License-Identifier: BSD-3-Clause
# Explicit host diagnostic. Does not register packages or change permissions.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ImagePath,
    [Parameter(Mandatory=$true)][string]$ProbePath,
    [switch]$MountReadOnly
)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw '64-bit Windows PowerShell required' }
foreach ($supplied in @($ImagePath, $ProbePath)) {
    if (($supplied -split '[\\/]') -contains '..') { throw 'Parent traversal is not accepted' }
    $cursor = Get-Item -LiteralPath $supplied
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked input paths are not accepted' }
        $cursor = if ($cursor -is [IO.DirectoryInfo]) { $cursor.Parent } else { $cursor.Directory }
    }
}
$image = (Get-Item -LiteralPath $ImagePath).FullName
$probe = (Get-Item -LiteralPath $ProbePath).FullName
if ([IO.Path]::GetExtension($image) -ne '.xvd') { throw 'Explicit XVD input required' }
if ($MountReadOnly) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'MountReadOnly requires an elevated Windows PowerShell; no automatic elevation or policy changes'
    }
}
$packages = @(Get-AppxPackage -Name Microsoft.GamingServices)
if ($packages.Count -ne 1 -or $packages[0].PackageFamilyName -ne 'Microsoft.GamingServices_8wekyb3d8bbwe') {
    throw 'One exact installed Microsoft Gaming Services package required'
}
$package = $packages[0]
$provider = Join-Path $package.InstallLocation 'xsapi.dll'
if ((Get-AuthenticodeSignature -LiteralPath $provider).Status -ne 'Valid') { throw 'Provider signature rejected' }
[xml]$manifest = Get-Content -LiteralPath (Join-Path $package.InstallLocation 'AppxManifest.xml') -Raw
$apps = @($manifest.SelectNodes("//*[local-name()='Application']") | Where-Object {
    $_.GetAttribute('Id') -eq 'GamingServices' -and $_.GetAttribute('EntryPoint') -eq 'Windows.FullTrustApplication'
})
if ($apps.Count -ne 1) { throw 'Expected GamingServices desktop application not found; no fallback selected' }
$root = Join-Path (Split-Path $PSScriptRoot -Parent) 'build-xvd-probes'
if ((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Linked diagnostic output root is not accepted'
}
New-Item -ItemType Directory -Path $root -Force | Out-Null

function Invoke-Probe([string]$Mode, [string]$Log, [int]$TimeoutSeconds) {
    $arguments = $Mode + ' "' + $provider + '" "' + $image + '" "' + $Log + '"'
    $started = Get-Date
    Invoke-CommandInDesktopPackage -PackageFamilyName $package.PackageFamilyName -AppId GamingServices -Command $probe -Args $arguments
    for ($iteration = 0; $iteration -lt $TimeoutSeconds * 2; $iteration++) {
        if (Test-Path -LiteralPath $Log) {
            $result = Get-Content -LiteralPath $Log -Raw
            if ($result -match '(?m)^probe_completed=1\r?$') { return $result }
        }
        Start-Sleep -Milliseconds 500
    }
    # Only the exact task executable started during this invocation is eligible.
    Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($probe)) -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $probe -and $_.StartTime -ge $started } | Stop-Process -Force
    throw ('Probe deadline exceeded: ' + $Log)
}

$log = Join-Path $root (([guid]::NewGuid().ToString('N')) + '.log')
$mode = if ($MountReadOnly) { '--mount-readonly' } else { '--diagnose' }
try {
    $result = Invoke-Probe $mode $log 30
} catch {
    if ($MountReadOnly -and (Test-Path -LiteralPath $log) -and
        (Get-Content -LiteralPath $log -Raw) -match '(?m)^mount_started=1\r?$') {
        $cleanup = $log + '.cleanup'
        try { Invoke-Probe '--unmount-owned' $cleanup 10 | Write-Output }
        catch { Write-Warning ('Cleanup unverified; inspect ' + $cleanup) }
    }
    throw
}
Write-Output $result
Write-Output ('provider_package=' + $package.PackageFullName)
Write-Output ('log=' + $log)
if ($MountReadOnly) {
    if ($result -match '(?m)^mount_readonly=0x0;' -and $result -notmatch '(?m)^drive_removed=1\r?$') {
        try { Invoke-Probe '--unmount-owned' ($log + '.cleanup') 10 | Write-Output }
        catch { Write-Warning ('Cleanup unverified; inspect ' + $log + '.cleanup') }
    }
    if ($result -notmatch '(?m)^mount_readonly=0x0;' -or
        $result -notmatch '(?m)^root_readable=1\r?$' -or
        $result -notmatch '(?m)^unmount=0x0\r?$' -or
        $result -notmatch '(?m)^drive_removed=1\r?$') { exit 1 }
} elseif ($result -notmatch '(?m)^provider_loaded=1\r?$') { exit 1 }
exit 0
