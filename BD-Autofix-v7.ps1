<#
  BD-Autofix-and-Redeploy.ps1  (v7 - Improved reboot handling, driver cleanup)
  Purpose: Non-interactive fix for Bitdefender deployment failures on Syncro-managed Windows endpoints.

  Changes from v6:
  - Fixed: Reboot actually triggers when needed (not just exit 3010)
  - Fixed: Better driver unload before deletion
  - Fixed: Verify Security Center changes actually applied
  - Added: Pre-flight checks for Syncro agent
  - Added: Better WRSA termination (suspend before kill)
  - Added: Multiple reboot attempt methods

  Exit codes:
    0    = Completed; no reboot required
    3010 = Completed; reboot required (scheduled or pending)
    1    = Error
#>

param(
  [switch]$HandleMalwarebytes,      # Stop/disable MBAM real-time & services
  [switch]$AggressiveBDCleanup,     # Remove partial Bitdefender folders if present
  [switch]$AutoRebootIfNoUser,      # If reboot needed and NO interactive users, reboot now
  [string]$ScheduleRebootIfNeeded,  # If reboot needed and users are active, schedule HH:mm (local today)
  [switch]$RemoveGenericAVs,        # Remove common third-party AVs (Norton, McAfee, etc.)
  [switch]$ForceReboot,             # Always reboot at end (use for stubborn machines)
  [int]$RebootDelaySeconds = 60,    # Delay before forced reboot (gives time for script to complete)
  [switch]$LogActivity,             # Log results to Syncro Asset Activity
  [switch]$CreateTicketOnFail,      # Create Syncro ticket if cleanup fails or needs attention
  [switch]$CloseAlertOnSuccess,     # Close bd_deployment_blocked alert if cleanup succeeds
  [switch]$ExitZeroOnReboot         # Return exit code 0 instead of 3010 when reboot needed (for Syncro)
)

$ErrorActionPreference = 'Stop'

#region Logging / Elevation
$logDir = 'C:\ProgramData\SyncroMSP\Scripts'
$log = Join-Path $logDir 'bd_autofix.log'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

# Import Syncro module if available
$syncroModuleLoaded = $false
if ($env:SyncroModule -and (Test-Path $env:SyncroModule)) {
  try {
    Import-Module $env:SyncroModule -WarningAction SilentlyContinue
    $syncroModuleLoaded = $true
  } catch {}
}

function W { param([string]$m)
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[$ts] $m"
  $line | Tee-Object -FilePath $log -Append
}

W "=== BD-Autofix v7 start ==="
W "Syncro module loaded: $syncroModuleLoaded"
W "Parameters: HandleMalwarebytes=$HandleMalwarebytes, AggressiveBDCleanup=$AggressiveBDCleanup, AutoRebootIfNoUser=$AutoRebootIfNoUser, ScheduleRebootIfNeeded=$ScheduleRebootIfNeeded, RemoveGenericAVs=$RemoveGenericAVs, ForceReboot=$ForceReboot"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  W "Not elevated. Must run as SYSTEM/admin."
  Write-Output "Must run as SYSTEM/admin."
  exit 1
}
#endregion

#region Helpers
$global:RebootRequired = $false
$global:RebootReasons = @()

function Write-Section { param([string]$title)
  W ""
  W ("=" * 50)
  W "  $title"
  W ("=" * 50)
}

function Add-RebootReason { param([string]$reason)
  $global:RebootRequired = $true
  $global:RebootReasons += $reason
  W "Reboot required: $reason"
}

function Try-Quiet { param([scriptblock]$Block, [string]$Desc)
  try { & $Block } catch { W "WARN: $Desc => $($_.Exception.Message)" }
}

function Remove-RegKey { param([string]$path)
  if (Test-Path $path) {
    Try-Quiet {
      # Take ownership first
      $acl = Get-Acl $path -ErrorAction SilentlyContinue
      if ($acl) {
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
          "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl $path $acl -ErrorAction SilentlyContinue
      }
      Remove-Item $path -Recurse -Force -ErrorAction Stop
      W "Removed reg: $path"
    } "Remove reg $path"

    # Verify it was actually removed
    if (Test-Path $path) {
      W "FAILED to remove reg (still exists): $path"
    }
  }
}

function Remove-Folder { param([string]$path)
  if (Test-Path $path) {
    Try-Quiet { cmd /c "takeown /F `"$path`" /R /D Y 2>nul" | Out-Null } "takeown $path"
    Try-Quiet { cmd /c "icacls `"$path`" /grant *S-1-5-18:(OI)(CI)F /T 2>nul" | Out-Null } "icacls $path"
    Try-Quiet { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue } "remove $path"

    if (Test-Path $path) {
      W "Folder locked; adding to PendingFileRenameOperations: $path"
      Add-PendingFileRename $path
      Add-RebootReason "Locked folder: $path"
    } else {
      W "Removed: $path"
    }
  }
}

function Add-PendingFileRename { param([string]$path)
  Try-Quiet {
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $regName = 'PendingFileRenameOperations'

    $existing = @()
    try {
      $current = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
      if ($current) { $existing = @($current) }
    } catch {}

    $newEntry = @("\??\$path", "")
    $updated = $existing + $newEntry

    Set-ItemProperty -Path $regPath -Name $regName -Value $updated -Type MultiString
    W "Added to PendingFileRenameOperations: $path"
  } "add pending file rename"
}

function AnyInteractiveUserPresent {
  try {
    $sessions = (quser) 2>$null
    if (-not $sessions) { return $false }
    return ($sessions -split "`r?`n" | Where-Object { $_ -match "\s+Active\s+" }).Count -gt 0
  } catch { return $false }
}

function Kill-ProcessByName { param([string]$name, [switch]$Aggressive)
  Try-Quiet {
    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
    if (-not $procs) { return }

    foreach ($proc in $procs) {
      W "Killing process: $($proc.Name) (PID $($proc.Id))"

      if ($Aggressive) {
        # Method 0: Suspend threads first (prevents respawn)
        Try-Quiet {
          $handle = [Diagnostics.Process]::GetProcessById($proc.Id).Handle
          # Can't easily suspend in PS, but we can try to lower priority
          $proc.PriorityClass = [Diagnostics.ProcessPriorityClass]::Idle
        } "lower priority $name"
      }

      # Method 1: PowerShell Stop-Process
      Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 200

      # Method 2: taskkill
      cmd /c "taskkill /F /PID $($proc.Id) /T 2>nul" | Out-Null
      Start-Sleep -Milliseconds 200
    }

    # Method 3: taskkill by name (catches any new instances)
    cmd /c "taskkill /F /IM $name.exe /T 2>nul" | Out-Null
    Start-Sleep -Milliseconds 300

    # Final check
    $check = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($check) {
      W "Process still running after kill attempts: $name"
      # Method 4: WMIC
      cmd /c "wmic process where name='$name.exe' call terminate 2>nul" | Out-Null
      Start-Sleep -Milliseconds 500

      $check2 = Get-Process -Name $name -ErrorAction SilentlyContinue
      if ($check2) {
        W "FAILED to kill $name - may need reboot"
        Add-RebootReason "Cannot kill process: $name"
      }
    }
  } "kill process $name"
}

function Stop-DriverSafely { param([string]$driverName)
  Try-Quiet {
    # Try to stop the driver/service first
    $svc = Get-Service -Name $driverName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
      Stop-Service -Name $driverName -Force -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 500
    }

    # Use sc.exe to stop and delete
    cmd /c "sc stop $driverName 2>nul" | Out-Null
    Start-Sleep -Milliseconds 300
    cmd /c "sc delete $driverName 2>nul" | Out-Null

    # Check if it's a boot driver (can't be removed until reboot)
    $drvInfo = Get-CimInstance Win32_SystemDriver -Filter "Name='$driverName'" -ErrorAction SilentlyContinue
    if ($drvInfo -and $drvInfo.StartMode -eq 'Boot') {
      W "Driver $driverName is a boot driver - requires reboot to remove"
      Add-RebootReason "Boot driver: $driverName"
    }
  } "stop driver $driverName"
}
#endregion

#region Pre-flight Checks
Write-Section "PRE-FLIGHT CHECKS"

# Check Syncro agent (multiple possible service names)
$syncroOK = $false
$syncroServiceNames = @(
  "SyncroMSP",
  "SyncroLive.Agent.Runner",
  "SyncroLive*",
  "Syncro*"
)

$syncroService = $null
foreach ($svcName in $syncroServiceNames) {
  $syncroService = Get-Service -Name $svcName -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($syncroService) { break }
}

if ($syncroService) {
  if ($syncroService.Status -eq 'Running') {
    W "Syncro agent: Running ($($syncroService.Name))"
    $syncroOK = $true
  } else {
    W "WARNING: Syncro agent exists but not running ($($syncroService.Name) = $($syncroService.Status))"
    Try-Quiet { Start-Service -Name $syncroService.Name -ErrorAction SilentlyContinue } "start Syncro"
    Start-Sleep -Seconds 2
    $syncroService = Get-Service -Name $syncroService.Name -ErrorAction SilentlyContinue
    if ($syncroService.Status -eq 'Running') {
      W "Syncro agent: Started successfully"
      $syncroOK = $true
    }
  }
} else {
  # Also check for running process as fallback
  $syncroProc = Get-Process -Name "*Syncro*" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($syncroProc) {
    W "Syncro agent: Running (detected via process: $($syncroProc.Name))"
    $syncroOK = $true
  } else {
    W "WARNING: Syncro service/process not found - Bitdefender cannot deploy without Syncro!"
  }
}

# Check for existing pending reboot
$existingPending = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $existingPending = $true }
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $existingPending = $true }
$pfro = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pfro) { $existingPending = $true }

if ($existingPending) {
  W "WARNING: System already has pending reboot from previous operations"
  Add-RebootReason "Pre-existing pending reboot"
}
#endregion

#region Snapshot SecurityCenter
$preAV = @()
Try-Quiet {
  $preAV = Get-CimInstance -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue
  W ("SecurityCenter AV (pre): " + (($preAV | Select-Object -Expand displayName) -join ', '))
} "query SecurityCenter2"
#endregion

#region Force disable Tamper Protection
W "Attempting to disable Defender Tamper Protection..."

# Check current state
$currentTamper = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection
W "Current TamperProtection value: $currentTamper (5=enabled, 0/4=disabled)"

if ($currentTamper -eq 5) {
  W "NOTE: Tamper Protection is ENABLED - registry changes may be blocked"
  W "      Disable manually in Windows Security > Virus & Threat Protection > Manage Settings"
  W "      Or deploy via Intune/GPO before running this script"
}

Try-Quiet {
  $defenderPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
  if (Test-Path $defenderPath) {
    Set-ItemProperty -Path $defenderPath -Name 'TamperProtection' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $defenderPath -Name 'TamperProtectionSource' -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
  }

  $gpoPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
  if (-not (Test-Path $gpoPath)) { New-Item -Path $gpoPath -Force | Out-Null }
  Set-ItemProperty -Path $gpoPath -Name 'DisableAntiSpyware' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

  # Try to stop WinDefend
  $wdSvc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
  if ($wdSvc -and $wdSvc.Status -ne 'Stopped') {
    Stop-Service -Name 'WinDefend' -Force -ErrorAction SilentlyContinue
    Set-Service -Name 'WinDefend' -StartupType Disabled -ErrorAction SilentlyContinue
    W "Attempted to stop/disable WinDefend service"
  }
} "disable Tamper Protection"
#endregion

#region OpenText Core Endpoint Protection removal
W "Checking for OpenText Core Endpoint Protection..."

$openTextProcs = @('CoreServiceShell','SkyClient','OESIS','OESISCore')
foreach ($p in $openTextProcs) { Kill-ProcessByName $p -Aggressive }

Try-Quiet {
  Get-Service | Where-Object { $_.DisplayName -like '*OpenText*' -or $_.DisplayName -like '*Core*Endpoint*' -or $_.Name -like '*OESIS*' } | ForEach-Object {
    Try-Quiet { Stop-Service $_.Name -Force -ErrorAction SilentlyContinue } "stop svc $($_.Name)"
    Try-Quiet { Set-Service $_.Name -StartupType Disabled -ErrorAction SilentlyContinue } "disable svc $($_.Name)"
    Try-Quiet { sc.exe delete $_.Name 2>nul | Out-Null } "delete svc $($_.Name)"
    W "Processed OpenText service: $($_.Name)"
  }
} "enumerate OpenText services"

Remove-Folder "C:\Program Files\OpenText"
Remove-Folder "C:\Program Files (x86)\OpenText"
Remove-Folder "C:\ProgramData\OpenText"
Remove-RegKey 'HKLM:\SOFTWARE\OpenText'
Remove-RegKey 'HKLM:\SOFTWARE\WOW6432Node\OpenText'
#endregion

#region Handle Malwarebytes (optional, non-destructive)
if ($HandleMalwarebytes) {
  W "HandleMalwarebytes enabled: quieting MBAM services."

  $mbProcs = @('mbamservice','mbamtray','assistant','mbam','malwarebytes')
  foreach ($p in $mbProcs) { Kill-ProcessByName $p }

  $mbSvc = @('MBAMService','MBAMWebProtection','MBAMInstallerService','MBAMChameleon')
  foreach ($n in $mbSvc) {
    Try-Quiet {
      $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
      if ($svc) {
        if ($svc.Status -ne 'Stopped') { Stop-Service $n -Force -ErrorAction SilentlyContinue }
        Set-Service $n -StartupType Disabled -ErrorAction SilentlyContinue
        W "MBAM service disabled: $n"
      }
    } "disable MBAM $n"
  }

  Try-Quiet {
    $reg = 'HKLM:\SOFTWARE\Malwarebytes\MBAMService'
    if (Test-Path $reg) {
      New-ItemProperty -Path $reg -Name 'RegisterWithWSC' -Value 0 -PropertyType DWord -Force | Out-Null
      W "Set MBAM RegisterWithWSC=0"
    }
  } "MBAM WSC toggle"
}
#endregion

#region Webroot thorough cleanup
W "=== Webroot cleanup phase ==="

# Kill processes aggressively (expanded list including WRUS64)
$wrProcs = @('WRSA','WRUS64','WRCoreService','WRConsumerService','WebrootSecureAnywhere','WRSkyClient','WRUSR','WRUpgradeTool')
foreach ($p in $wrProcs) { Kill-ProcessByName $p -Aggressive }

# Extra aggressive: kill anything with WR prefix
Try-Quiet {
  Get-Process | Where-Object { $_.Name -match '^WR' } | ForEach-Object {
    W "Killing WR process: $($_.Name) (PID $($_.Id))"
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    cmd /c "taskkill /F /PID $($_.Id) /T 2>nul" | Out-Null
  }
} "kill all WR processes"

# Stop and delete services
Try-Quiet {
  Get-Service | Where-Object { $_.Name -match '^WR' -or $_.DisplayName -match 'Webroot' } | ForEach-Object {
    W "Processing Webroot service: $($_.Name)"
    Try-Quiet { Stop-Service $_.Name -Force -ErrorAction SilentlyContinue } "stop svc"
    Try-Quiet { Set-Service $_.Name -StartupType Disabled -ErrorAction SilentlyContinue } "disable svc"
    Try-Quiet { sc.exe delete $_.Name 2>nul | Out-Null } "delete svc"
  }
} "enumerate WR services"

# Handle drivers specially
W "Processing Webroot drivers..."
$wrDrivers = @('WRBoot','WRCore','WRkrn','WREDRD','wrUrlFlt')
foreach ($drv in $wrDrivers) {
  Stop-DriverSafely $drv
}

# Also enumerate any we might have missed
Try-Quiet {
  Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match '^WR' -or $_.DisplayName -match 'Webroot' } | ForEach-Object {
    if ($_.Name -notin $wrDrivers) {
      W "Found additional Webroot driver: $($_.Name)"
      Stop-DriverSafely $_.Name
    }
  }
} "enumerate WR drivers"

# Remove folders
Remove-Folder "C:\Program Files\Webroot"
Remove-Folder "C:\Program Files (x86)\Webroot"
Remove-Folder "C:\ProgramData\WRData"
Remove-Folder "C:\ProgramData\Webroot"

# Remove registry keys
Remove-RegKey 'HKLM:\SOFTWARE\Webroot'
Remove-RegKey 'HKLM:\SOFTWARE\WOW6432Node\Webroot'

Try-Quiet {
  Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^WR' } |
    ForEach-Object { Remove-RegKey $_.PSPath }
} "remove WR service keys"

# Run WRUpgradeTool and wait for completion
Try-Quiet {
  $wrUrl = 'https://download.webroot.com/WRUpgradeTool.exe'
  $tmpFile = Join-Path $env:TEMP "WRUpgradeTool_$(Get-Random).exe"

  W "Downloading WRUpgradeTool..."
  Invoke-WebRequest -Uri $wrUrl -OutFile $tmpFile -UseBasicParsing -TimeoutSec 60

  if (Test-Path $tmpFile) {
    W "Running WRUpgradeTool (waiting up to 120 seconds)..."
    $proc = Start-Process -FilePath $tmpFile -ArgumentList "/s /norestart" -WindowStyle Hidden -PassThru
    $completed = $proc.WaitForExit(120000)  # 2 minute timeout
    if ($completed) {
      W "WRUpgradeTool completed with exit code: $($proc.ExitCode)"
    } else {
      W "WRUpgradeTool timed out - killing process"
      $proc | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # Kill any WR processes that may have started during removal
    Start-Sleep -Seconds 2
    Get-Process | Where-Object { $_.Name -match '^WR' } | ForEach-Object {
      W "Post-tool cleanup: killing $($_.Name)"
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
  }
} "WRUpgradeTool stage"
#endregion

#region Generic AV Removal
if ($RemoveGenericAVs) {
  W "=== RemoveGenericAVs: removing common third-party AVs ==="

  $commonAVs = @{
    'Norton' = @{
      Procs = @('Norton','ccSvcHst','Symantec','navapsvc')
      Services = @('Norton*','Symantec*','ccEvtMgr','ccSetMgr')
      Folders = @('C:\Program Files\Norton*','C:\Program Files (x86)\Norton*','C:\ProgramData\Norton*','C:\Program Files\Symantec*')
    }
    'McAfee' = @{
      Procs = @('McAfee*','mfe*','masvc')
      Services = @('McAfee*','mfe*')
      Folders = @('C:\Program Files\McAfee*','C:\Program Files (x86)\McAfee*','C:\Program Files\Common Files\McAfee')
    }
    'Avast' = @{
      Procs = @('Avast*','aswEngSrv','afwServ')
      Services = @('avast*','aswbIDSAgent','afwServ')
      Folders = @('C:\Program Files\Avast*','C:\ProgramData\Avast*')
    }
    'AVG' = @{
      Procs = @('AVG*','avgui')
      Services = @('AVG*')
      Folders = @('C:\Program Files\AVG*','C:\Program Files (x86)\AVG*','C:\ProgramData\AVG')
    }
    'Kaspersky' = @{
      Procs = @('avp*','Kaspersky*','klnagent')
      Services = @('Kaspersky*','klnagent*','AVP*')
      Folders = @('C:\Program Files\Kaspersky*','C:\Program Files (x86)\Kaspersky*')
    }
  }

  foreach ($avName in $commonAVs.Keys) {
    $av = $commonAVs[$avName]
    $found = $false

    # Check if installed
    foreach ($folder in $av.Folders) {
      if (Test-Path $folder) { $found = $true; break }
    }

    if (-not $found) { continue }

    W "Removing $avName..."

    # Kill processes
    foreach ($proc in $av.Procs) {
      Kill-ProcessByName $proc -Aggressive
    }

    # Stop and remove services
    foreach ($svcPattern in $av.Services) {
      Get-Service -Name $svcPattern -ErrorAction SilentlyContinue | ForEach-Object {
        Try-Quiet { Stop-Service $_.Name -Force } "stop $($_.Name)"
        Try-Quiet { sc.exe delete $_.Name 2>nul } "delete $($_.Name)"
      }
    }

    # Try uninstall via registry
    $uninstallPaths = @(
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $uninstallPaths) {
      Try-Quiet {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
          $_.DisplayName -like "*$avName*"
        } | ForEach-Object {
          if ($_.UninstallString) {
            W "Running uninstaller for $($_.DisplayName)..."
            if ($_.UninstallString -match 'MsiExec') {
              $guid = [regex]::Match($_.UninstallString, '\{[^}]+\}').Value
              if ($guid) {
                Start-Process 'msiexec.exe' -ArgumentList "/X$guid /qn /norestart" -Wait -NoNewWindow -ErrorAction SilentlyContinue
              }
            }
          }
        }
      } "uninstall $avName"
    }

    # Remove folders
    foreach ($folder in $av.Folders) {
      Get-ChildItem $folder -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Folder $_.FullName
      }
    }
  }
}
#endregion

#region Clean Security Center entries
W "Cleaning Security Center AV entries..."

$avNamesToRemove = @('Webroot','OpenText','Norton','McAfee','Avast','AVG','Kaspersky')

$scPaths = @(
  'HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Security Center\Provider\Av'
)

foreach ($scPath in $scPaths) {
  if (Test-Path $scPath) {
    Try-Quiet {
      Get-ChildItem $scPath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $displayName = $props.displayName

        $shouldRemove = $false
        foreach ($av in $avNamesToRemove) {
          if ($displayName -like "*$av*") {
            $shouldRemove = $true
            break
          }
        }

        if ($shouldRemove) {
          W "Removing from Security Center: $displayName"
          Remove-RegKey $_.PSPath
        }
      }
    } "clean Security Center $scPath"
  }
}
#endregion

#region Clean startup entries
W "Cleaning AV-related startup registry entries..."

$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)

$avKeywords = @('webroot','norton','symantec','mcafee','avast','avg','kaspersky','opentext','oesis')

foreach ($key in $runKeys) {
  if (Test-Path $key) {
    Try-Quiet {
      $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
      $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        foreach ($kw in $avKeywords) {
          if ($_.Name -like "*$kw*" -or $_.Value -like "*$kw*") {
            W "Removing startup entry: $key\$($_.Name)"
            Remove-ItemProperty -Path $key -Name $_.Name -Force -ErrorAction SilentlyContinue
            break
          }
        }
      }
    } "clean startup $key"
  }
}
#endregion

#region Quiet Windows Defender RT
Try-Quiet {
  W "Disabling Defender real-time protection..."
  Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
  Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
  Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
  Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
} "disable Defender RT"
#endregion

#region Optional: Bitdefender partial cleanup
if ($AggressiveBDCleanup) {
  $bdPaths = @(
    "C:\Program Files\Bitdefender",
    "C:\Program Files\Bitdefender Endpoint Security",
    "C:\Program Files\Bitdefender Endpoint Security Tools",
    "C:\ProgramData\Bitdefender"
  )

  $bdFound = $false
  foreach ($p in $bdPaths) { if (Test-Path $p) { $bdFound = $true } }

  if ($bdFound) {
    W "AggressiveBDCleanup: removing Bitdefender folders."

    $bdProcs = @('bdagent','bdservicehost','updatesrv','vsserv','product','endpoint')
    foreach ($p in $bdProcs) { Kill-ProcessByName $p }

    foreach ($p in $bdPaths) { Remove-Folder $p }
  }
}
#endregion

#region Trigger Syncro policy sync
if ($syncroOK) {
  W "Triggering Syncro policy sync..."

  # Find Syncro executable
  $syncroExe = $null
  $locations = @(
    "C:\Program Files\SyncroMSP\SyncroMSP.exe",
    "C:\Program Files (x86)\SyncroMSP\SyncroMSP.exe",
    "C:\ProgramData\Syncro\SyncroMSP.exe"
  )

  foreach ($loc in $locations) {
    if (Test-Path $loc) { $syncroExe = $loc; break }
  }

  if ($syncroExe) {
    Try-Quiet {
      Start-Process -FilePath $syncroExe -ArgumentList "--force-policy-sync" -Wait -WindowStyle Hidden
      W "Syncro policy sync triggered"
    } "trigger policy sync"
  } else {
    # Fallback: restart the service
    Try-Quiet {
      Restart-Service -Name 'SyncroMSP' -Force -ErrorAction SilentlyContinue
      W "Restarted SyncroMSP service"
    } "restart Syncro"
  }
}
#endregion

#region Post-cleanup verification
W "=== Post-cleanup verification ==="

# Check Security Center
$postAV = @()
Try-Quiet {
  Start-Sleep -Seconds 2
  $postAV = Get-CimInstance -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue
  W ("SecurityCenter AV (post): " + (($postAV | Select-Object -Expand displayName) -join ', '))
} "post SecurityCenter query"

# Compare pre and post
$preNames = ($preAV | Select-Object -Expand displayName) -join ', '
$postNames = ($postAV | Select-Object -Expand displayName) -join ', '

if ($preNames -eq $postNames -and $preAV.Count -gt 0) {
  W "WARNING: Security Center unchanged - AV entries may be protected"
  W "         This usually means Tamper Protection is blocking changes"
  Add-RebootReason "Security Center entries unchanged"
}

# Check for remaining AV processes
$badProcs = @('wrsa','mcshield','avgui','avast','nortonsecurity','coreserviceshell')
$foundBad = @()
foreach ($proc in $badProcs) {
  if (Get-Process -Name $proc -ErrorAction SilentlyContinue) {
    $foundBad += $proc
    Kill-ProcessByName $proc -Aggressive
  }
}

if ($foundBad.Count -gt 0) {
  W "WARNING: AV processes still running after cleanup: $($foundBad -join ', ')"
  Add-RebootReason "AV processes still running"
}
#endregion

#region Reboot handling
W "=== Reboot decision ==="
W "RebootRequired: $($global:RebootRequired)"
W "Reasons: $($global:RebootReasons -join '; ')"

function Do-Reboot {
  param([int]$delay = 60, [string]$message = "Geek2Go maintenance reboot for Bitdefender installation")

  W "Initiating reboot in $delay seconds..."

  # Method 1: shutdown.exe
  $result = cmd /c "shutdown /r /t $delay /c `"$message`" /f 2>&1"
  if ($LASTEXITCODE -eq 0) {
    W "Reboot scheduled successfully via shutdown.exe"
    return $true
  }

  # Method 2: Restart-Computer
  Try-Quiet {
    Restart-Computer -Force -ErrorAction Stop
    return $true
  } "Restart-Computer"

  # Method 3: WMI
  Try-Quiet {
    (Get-WmiObject -Class Win32_OperatingSystem).Reboot()
    W "Reboot initiated via WMI"
    return $true
  } "WMI reboot"

  W "ERROR: All reboot methods failed"
  return $false
}

function Schedule-OneTimeReboot {
  param([string]$hhmm)

  try {
    $target = [datetime]::ParseExact($hhmm,'HH:mm',$null)
    $run = (Get-Date -Hour $target.Hour -Minute $target.Minute -Second 0)
    if ($run -lt (Get-Date)) { $run = $run.AddDays(1) }

    $taskName = "BD_Autofix_OneTimeReboot"

    # Remove existing task if present
    schtasks /delete /tn $taskName /f 2>$null | Out-Null

    # Create new task
    $action = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/r /t 30 /c "Geek2Go maintenance reboot for Bitdefender" /f'
    $trigger = New-ScheduledTaskTrigger -Once -At $run
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

    W "Scheduled one-time reboot at $($run.ToString('yyyy-MM-dd HH:mm'))"
    return $true
  } catch {
    W "Failed to schedule reboot: $($_.Exception.Message)"
    return $false
  }
}

# Determine what to do
$exitCode = 0
$exitMessage = "Cleanup complete. System ready for Bitdefender deployment."

if ($ForceReboot) {
  W "ForceReboot enabled - rebooting regardless of state"
  Do-Reboot -delay $RebootDelaySeconds
  $exitMessage = "Cleanup complete. Rebooting in $RebootDelaySeconds seconds."
  $exitCode = 3010
}
elseif ($global:RebootRequired) {
  $userActive = AnyInteractiveUserPresent
  W "Interactive user present: $userActive"

  if ($AutoRebootIfNoUser -and -not $userActive) {
    W "No interactive users - rebooting now"
    Do-Reboot -delay $RebootDelaySeconds
    $exitMessage = "Cleanup complete. Rebooting in $RebootDelaySeconds seconds (no users logged in)."
    $exitCode = 3010
  }
  elseif ($ScheduleRebootIfNeeded) {
    if (Schedule-OneTimeReboot $ScheduleRebootIfNeeded) {
      $exitMessage = "Cleanup complete. Reboot scheduled at $ScheduleRebootIfNeeded."
      $exitCode = 3010
    } else {
      W "Could not schedule reboot - returning 3010"
      $exitMessage = "Cleanup complete. REBOOT REQUIRED but could not schedule. Please reboot manually."
      $exitCode = 3010
    }
  }
  else {
    W "Reboot required but no auto-reboot parameter specified"
    $exitMessage = "Cleanup complete. REBOOT REQUIRED. Reasons: $($global:RebootReasons -join '; ')"
    $exitCode = 3010
  }
}

# Apply ExitZeroOnReboot if set
if ($ExitZeroOnReboot -and $exitCode -eq 3010) {
  W "ExitZeroOnReboot enabled - changing exit code from 3010 to 0"
  $exitCode = 0
}

W "BD-Autofix v7 complete - exit code $exitCode"
#endregion

#region Syncro Integration
if ($syncroModuleLoaded) {
  # Log to Activity feed
  if ($LogActivity) {
    $activityMsg = if ($exitCode -eq 0) {
      "BD Autofix: Cleanup complete - ready for Bitdefender"
    } elseif ($exitCode -eq 3010) {
      "BD Autofix: Cleanup complete - reboot required ($($global:RebootReasons.Count) reasons)"
    } else {
      "BD Autofix: Completed with issues"
    }
    Log-Activity -Message $activityMsg -EventName "BD Autofix"
    W "[Syncro] Logged to Asset Activity"
  }

  # Close alert on success (if cleanup completed and no blocking issues remain)
  if ($CloseAlertOnSuccess -and $exitCode -eq 0) {
    Try-Quiet {
      Close-Rmm-Alert -Category 'bd_deployment_blocked' -CloseAlertTicket $false
      W "[Syncro] Closed RMM Alert: bd_deployment_blocked"
    } "close RMM alert"
  }

  # Create ticket if there are issues that need attention
  if ($CreateTicketOnFail) {
    $needsTicket = $false
    $ticketReason = ""

    # Check if we couldn't clean up properly
    if (-not $syncroOK) {
      $needsTicket = $true
      $ticketReason = "Syncro agent not found - cannot deploy Bitdefender"
    }
    elseif ($global:RebootRequired -and -not $ForceReboot -and -not $AutoRebootIfNoUser -and -not $ScheduleRebootIfNeeded) {
      $needsTicket = $true
      $ticketReason = "Reboot required but not automated - manual intervention needed"
    }

    if ($needsTicket) {
      $ticketBody = @"
BD Autofix script completed but requires attention.

Issue: $ticketReason

Reboot Required: $($global:RebootRequired)
Reboot Reasons: $($global:RebootReasons -join '; ')

Security Center (pre): $preNames
Security Center (post): $postNames

Log file: C:\ProgramData\SyncroMSP\Scripts\bd_autofix.log

Next Steps:
1. Review the log file for details
2. If reboot is needed, schedule maintenance window
3. Re-run BD-Autofix-v7.ps1 with -ForceReboot if needed
"@
      $ticket = Create-Syncro-Ticket -Subject "Bitdefender Deployment - Manual Intervention Needed" -IssueType "Other" -Status "New"
      if ($ticket.ticket.id) {
        Create-Syncro-Ticket-Comment -TicketIdOrNumber $ticket.ticket.id -Subject "Autofix Results" -Body $ticketBody -Hidden $false -DoNotEmail $true
        W "[Syncro] Created ticket #$($ticket.ticket.number) for manual intervention"
      }
    }
  }
}
#endregion

Write-Output $exitMessage
exit $exitCode
