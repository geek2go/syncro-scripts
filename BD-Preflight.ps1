<#
  BD-Preflight.ps1 - Defender Exclusion Setup
  Purpose: Add Windows Defender exclusions for Syncro scripts before running BD-Autofix

  Run this BEFORE BD-Autofix-v7.ps1 to prevent false positive blocking.
  This script is intentionally simple to avoid triggering Defender itself.
#>

$ErrorActionPreference = 'SilentlyContinue'

# Paths to exclude from Defender scanning
$exclusionPaths = @(
    "C:\ProgramData\Syncro\bin",
    "C:\ProgramData\SyncroMSP\Scripts"
)

foreach ($path in $exclusionPaths) {
    # Check if exclusion already exists
    $existing = (Get-MpPreference).ExclusionPath
    if ($existing -notcontains $path) {
        Add-MpPreference -ExclusionPath $path
        Write-Output "Added Defender exclusion: $path"
    } else {
        Write-Output "Exclusion already exists: $path"
    }
}

Write-Output ""
Write-Output "Defender exclusions configured. You can now run BD-Autofix-v7.ps1"
