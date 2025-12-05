<#
  BD-Autofix-Launcher.ps1
  Purpose: Add Defender exclusions, then download and run the actual cleanup script.

  This script is intentionally simple to avoid triggering Defender.
  Deploy THIS script in Syncro instead of BD-Autofix-v7.ps1

  Usage in Syncro:
    BD-Autofix-Launcher.ps1 -AutoRebootIfNoUser
    BD-Autofix-Launcher.ps1 -ScheduleRebootIfNeeded "02:00" -HandleMalwarebytes
    BD-Autofix-Launcher.ps1 -ForceReboot -AggressiveBDCleanup
#>

param(
  [switch]$HandleMalwarebytes,
  [switch]$AggressiveBDCleanup,
  [switch]$AutoRebootIfNoUser,
  [string]$ScheduleRebootIfNeeded,
  [switch]$RemoveGenericAVs,
  [switch]$ForceReboot,
  [int]$RebootDelaySeconds = 60,
  [switch]$LogActivity,
  [switch]$CreateTicketOnFail,
  [switch]$CloseAlertOnSuccess,
  [switch]$NoExitZeroOnReboot         # By default, returns 0 on reboot. Set this to return 3010 instead.
)

$ErrorActionPreference = 'Stop'

# URL to the raw cleanup script - UPDATE THIS to your hosted location
# Options:
#   1. GitHub raw URL (public repo)
#   2. Your own web server
#   3. Azure Blob Storage
#   4. Any direct download URL
$CleanupScriptUrl = "https://raw.githubusercontent.com/geek2go/syncro-scripts/main/BD-Autofix-v7.ps1"

# Local paths
$scriptDir = "C:\ProgramData\SyncroMSP\Scripts"
$cleanupScript = Join-Path $scriptDir "BD-Autofix-v7.ps1"
$logFile = Join-Path $scriptDir "bd_launcher.log"

function Log {
  param([string]$msg)
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[$ts] $msg"
  $line | Tee-Object -FilePath $logFile -Append
}

# Create directory if needed
if (-not (Test-Path $scriptDir)) {
  New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
}

Log "=== BD-Autofix Launcher start ==="

# Step 1: Add Defender exclusions
Log "Adding Defender exclusions..."

$exclusionPaths = @(
  "C:\ProgramData\Syncro\bin",
  "C:\ProgramData\SyncroMSP\Scripts",
  $scriptDir
)

foreach ($path in $exclusionPaths) {
  try {
    $existing = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath
    if ($existing -notcontains $path) {
      Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
      Log "Added exclusion: $path"
    } else {
      Log "Exclusion exists: $path"
    }
  } catch {
    Log "Warning: Could not add exclusion for $path - $($_.Exception.Message)"
  }
}

# Brief pause to let Defender update
Start-Sleep -Seconds 2

# Step 2: Download the cleanup script
Log "Downloading cleanup script from: $CleanupScriptUrl"

try {
  # Remove old version if exists
  if (Test-Path $cleanupScript) {
    Remove-Item $cleanupScript -Force
  }

  # Download fresh copy
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $CleanupScriptUrl -OutFile $cleanupScript -UseBasicParsing -TimeoutSec 60

  if (-not (Test-Path $cleanupScript)) {
    throw "Download failed - file not found after download"
  }

  Log "Download complete: $cleanupScript"
} catch {
  Log "ERROR: Failed to download cleanup script - $($_.Exception.Message)"
  Write-Output "ERROR: Failed to download cleanup script. Check URL and network connectivity."
  Write-Output "URL: $CleanupScriptUrl"
  exit 1
}

# Step 3: Build arguments to pass through
$argList = @()

if ($HandleMalwarebytes) { $argList += "-HandleMalwarebytes" }
if ($AggressiveBDCleanup) { $argList += "-AggressiveBDCleanup" }
if ($AutoRebootIfNoUser) { $argList += "-AutoRebootIfNoUser" }
if ($ScheduleRebootIfNeeded) { $argList += "-ScheduleRebootIfNeeded `"$ScheduleRebootIfNeeded`"" }
if ($RemoveGenericAVs) { $argList += "-RemoveGenericAVs" }
if ($ForceReboot) { $argList += "-ForceReboot" }
if ($RebootDelaySeconds -ne 60) { $argList += "-RebootDelaySeconds $RebootDelaySeconds" }
if ($LogActivity) { $argList += "-LogActivity" }
if ($CreateTicketOnFail) { $argList += "-CreateTicketOnFail" }
if ($CloseAlertOnSuccess) { $argList += "-CloseAlertOnSuccess" }
if (-not $NoExitZeroOnReboot) { $argList += "-ExitZeroOnReboot" }

$argString = $argList -join " "
Log "Running cleanup script with args: $argString"

# Step 4: Execute the cleanup script
try {
  $cmd = "& `"$cleanupScript`" $argString"
  Log "Executing: $cmd"

  # Run the script and capture output
  $output = Invoke-Expression $cmd
  $exitCode = $LASTEXITCODE

  # Output results
  $output | ForEach-Object { Write-Output $_ }

  Log "Cleanup script finished with exit code: $exitCode"
  exit $exitCode
} catch {
  Log "ERROR: Failed to execute cleanup script - $($_.Exception.Message)"
  Write-Output "ERROR: Failed to execute cleanup script."
  Write-Output $_.Exception.Message
  exit 1
}
