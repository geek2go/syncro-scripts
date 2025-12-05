<#
  BD-Diagnostic.ps1 - Bitdefender Deployment Diagnostic Script
  Purpose: Identify what's blocking Bitdefender installation on Syncro-managed endpoints

  Run this BEFORE the cleanup script to understand the current state.
  Output is formatted for easy reading in Syncro script results.

  Syncro Integration:
  - Logs summary to Asset Activity feed
  - Creates RMM alert if blocking issues found
  - Sets Asset Custom Field with deployment status
#>

param(
  [switch]$CreateAlert,           # Create RMM alert if blocking issues found
  [switch]$LogActivity,           # Log summary to Asset Activity feed
  [switch]$SetAssetField,         # Set custom field with BD deployment status
  [string]$AssetFieldName = "BD Deployment Status"  # Custom field name to use
)

$ErrorActionPreference = 'SilentlyContinue'

# Import Syncro module if available
$syncroModuleLoaded = $false
if ($env:SyncroModule -and (Test-Path $env:SyncroModule)) {
  try {
    Import-Module $env:SyncroModule -WarningAction SilentlyContinue
    $syncroModuleLoaded = $true
  } catch {}
}

# Track issues for Syncro integration
$global:issuesList = @()
$global:blockingCount = 0

function Write-Section { param([string]$title)
  Write-Output ""
  Write-Output ("=" * 60)
  Write-Output "  $title"
  Write-Output ("=" * 60)
}

function Write-Status { param([string]$label, [string]$value, [string]$status = "INFO")
  $icon = switch ($status) {
    "OK"      { "[OK]" }
    "WARN"    { "[!!]" }
    "FAIL"    { "[XX]" }
    "INFO"    { "[--]" }
    default   { "[--]" }
  }
  Write-Output "$icon $label`: $value"
}

Write-Output ""
Write-Output "BITDEFENDER DEPLOYMENT DIAGNOSTIC REPORT"
Write-Output "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Computer: $env:COMPUTERNAME"

#region System Info
Write-Section "SYSTEM INFORMATION"

$os = Get-CimInstance Win32_OperatingSystem
Write-Status "OS" "$($os.Caption) ($($os.Version))"
Write-Status "Architecture" $env:PROCESSOR_ARCHITECTURE

# Check if running as SYSTEM
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$isSystem = $currentUser -eq "NT AUTHORITY\SYSTEM"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Status "Running As" $currentUser $(if ($isSystem -or $isAdmin) { "OK" } else { "WARN" })

# Check for pending reboot
$pendingReboot = $false
$rebootReasons = @()

if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
  $pendingReboot = $true
  $rebootReasons += "CBS"
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
  $pendingReboot = $true
  $rebootReasons += "WindowsUpdate"
}
$pfro = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pfro) {
  $pendingReboot = $true
  $rebootReasons += "PendingFileRename"

  # Count AV-related pending renames
  $avPending = $pfro | Where-Object { $_ -match 'webroot|bitdefender|defender|opentext|norton|mcafee|avast' }
  if ($avPending) {
    Write-Status "Pending AV File Renames" "$($avPending.Count) entries" "WARN"
  }
}

Write-Status "Pending Reboot" $(if ($pendingReboot) { "YES ($($rebootReasons -join ', '))" } else { "No" }) $(if ($pendingReboot) { "WARN" } else { "OK" })
#endregion

#region Security Center
Write-Section "SECURITY CENTER (Registered AV Products)"

$avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue

if ($avProducts) {
  foreach ($av in $avProducts) {
    # Decode productState to determine if enabled/updated
    $state = $av.productState
    $enabled = ($state -band 0x1000) -ne 0
    $upToDate = ($state -band 0x10) -eq 0

    $statusText = ""
    if ($av.displayName -like "*Bitdefender*") {
      $statusText = "OK"
    } elseif ($av.displayName -like "*Windows Defender*") {
      $statusText = if ($enabled) { "WARN" } else { "INFO" }
    } else {
      $statusText = "FAIL"  # Other AV = blocking BD
    }

    Write-Status $av.displayName "Enabled=$enabled, Updated=$upToDate" $statusText
  }

  # Count non-Defender, non-BD products
  $blockingAV = $avProducts | Where-Object {
    $_.displayName -notlike "*Windows Defender*" -and
    $_.displayName -notlike "*Bitdefender*"
  }

  if ($blockingAV) {
    Write-Output ""
    Write-Status "BLOCKING AV COUNT" "$($blockingAV.Count) product(s) may block Bitdefender" "FAIL"
  }
} else {
  Write-Status "Security Center" "No AV products registered or WMI query failed" "WARN"
}
#endregion

#region Syncro Agent
Write-Section "SYNCRO RMM AGENT"

$syncroService = Get-Service -Name "Syncro*" -ErrorAction SilentlyContinue
$syncroMSP = Get-Service -Name "SyncroMSP" -ErrorAction SilentlyContinue

if ($syncroMSP) {
  Write-Status "SyncroMSP Service" "$($syncroMSP.Status) (StartType: $($syncroMSP.StartType))" $(if ($syncroMSP.Status -eq 'Running') { "OK" } else { "FAIL" })
} elseif ($syncroService) {
  foreach ($svc in $syncroService) {
    Write-Status "$($svc.Name)" "$($svc.Status)" $(if ($svc.Status -eq 'Running') { "OK" } else { "WARN" })
  }
} else {
  Write-Status "Syncro Service" "NOT FOUND - Syncro agent may not be installed!" "FAIL"
}

# Find Syncro executable
$syncroExe = $null
$syncroLocations = @(
  "C:\Program Files\SyncroMSP\SyncroMSP.exe",
  "C:\Program Files (x86)\SyncroMSP\SyncroMSP.exe",
  "C:\ProgramData\Syncro\SyncroMSP.exe",
  "C:\Program Files\RepairTech\Syncro\SyncroMSP.exe"
)

foreach ($loc in $syncroLocations) {
  if (Test-Path $loc) {
    $syncroExe = $loc
    break
  }
}

if ($syncroExe) {
  $syncroVersion = (Get-Item $syncroExe).VersionInfo.FileVersion
  Write-Status "Syncro Executable" "$syncroExe (v$syncroVersion)" "OK"
} else {
  Write-Status "Syncro Executable" "NOT FOUND in standard locations" "FAIL"
}

# Check Syncro logs for recent activity
$syncroLogPath = "C:\ProgramData\Syncro\logs"
if (Test-Path $syncroLogPath) {
  $latestLog = Get-ChildItem $syncroLogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($latestLog) {
    $logAge = (Get-Date) - $latestLog.LastWriteTime
    Write-Status "Latest Log Activity" "$($latestLog.Name) - $([math]::Round($logAge.TotalHours, 1)) hours ago" $(if ($logAge.TotalHours -lt 1) { "OK" } else { "WARN" })
  }
}
#endregion

#region Bitdefender Status
Write-Section "BITDEFENDER STATUS"

$bdInstalled = $false
$bdPaths = @{
  "BD Program Files" = "C:\Program Files\Bitdefender"
  "BD Endpoint Security" = "C:\Program Files\Bitdefender Endpoint Security Tools"
  "BD ProgramData" = "C:\ProgramData\Bitdefender"
}

foreach ($name in $bdPaths.Keys) {
  $path = $bdPaths[$name]
  if (Test-Path $path) {
    $bdInstalled = $true
    $size = (Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
    Write-Status $name "EXISTS ($([math]::Round($size, 1)) MB)" "INFO"
  } else {
    Write-Status $name "Not found" "INFO"
  }
}

# Check BD services
$bdServices = Get-Service | Where-Object { $_.Name -like "*Bitdefender*" -or $_.DisplayName -like "*Bitdefender*" }
if ($bdServices) {
  Write-Output ""
  Write-Output "Bitdefender Services:"
  foreach ($svc in $bdServices) {
    Write-Status "  $($svc.DisplayName)" "$($svc.Status)" $(if ($svc.Status -eq 'Running') { "OK" } else { "WARN" })
  }
} else {
  Write-Status "BD Services" "None found" $(if ($bdInstalled) { "FAIL" } else { "INFO" })
}

# Check BD processes
$bdProcs = Get-Process | Where-Object { $_.Name -match 'bdagent|bdservicehost|updatesrv|vsserv|product\.exe|endpoint' }
if ($bdProcs) {
  Write-Output ""
  Write-Output "Bitdefender Processes:"
  foreach ($proc in $bdProcs) {
    Write-Status "  $($proc.Name)" "PID $($proc.Id), Memory $([math]::Round($proc.WorkingSet64/1MB, 1)) MB" "OK"
  }
}

# Check for BD installation errors in Event Log
$bdErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='*Bitdefender*'; Level=2} -MaxEvents 5 -ErrorAction SilentlyContinue
if ($bdErrors) {
  Write-Output ""
  Write-Output "Recent Bitdefender Errors (Event Log):"
  foreach ($evt in $bdErrors) {
    Write-Output "  [$($evt.TimeCreated.ToString('MM/dd HH:mm'))] $($evt.Message.Substring(0, [Math]::Min(100, $evt.Message.Length)))..."
  }
}
#endregion

#region Webroot Status
Write-Section "WEBROOT STATUS"

$wrInstalled = $false
$wrPaths = @{
  "WR Program Files" = "C:\Program Files\Webroot"
  "WR Program Files x86" = "C:\Program Files (x86)\Webroot"
  "WRData" = "C:\ProgramData\WRData"
  "WR ProgramData" = "C:\ProgramData\Webroot"
}

foreach ($name in $wrPaths.Keys) {
  $path = $wrPaths[$name]
  if (Test-Path $path) {
    $wrInstalled = $true

    # Check if folder is locked
    $testFile = Join-Path $path "test_write_$(Get-Random).tmp"
    $locked = $false
    try {
      [IO.File]::Create($testFile).Close()
      Remove-Item $testFile -Force
    } catch {
      $locked = $true
    }

    Write-Status $name $(if ($locked) { "EXISTS (LOCKED!)" } else { "EXISTS" }) "FAIL"
  }
}

if (-not $wrInstalled) {
  Write-Status "Webroot Folders" "None found" "OK"
}

# Check WR services
$wrServices = Get-Service | Where-Object { $_.Name -match '^WR' -or $_.DisplayName -match 'Webroot' }
if ($wrServices) {
  Write-Output ""
  Write-Output "Webroot Services:"
  foreach ($svc in $wrServices) {
    Write-Status "  $($svc.Name)" "$($svc.Status)" "FAIL"
  }
}

# Check WR drivers
$wrDrivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match '^WR' -or $_.DisplayName -match 'Webroot' }
if ($wrDrivers) {
  Write-Output ""
  Write-Output "Webroot Drivers (require reboot to remove):"
  foreach ($drv in $wrDrivers) {
    Write-Status "  $($drv.Name)" "$($drv.State)" "FAIL"
  }
}

# Check WR processes
$wrProcs = Get-Process | Where-Object { $_.Name -match 'WRSA|WRCore|WRConsumer|Webroot' }
if ($wrProcs) {
  Write-Output ""
  Write-Output "Webroot Processes (actively running!):"
  foreach ($proc in $wrProcs) {
    Write-Status "  $($proc.Name)" "PID $($proc.Id)" "FAIL"
  }
}
#endregion

#region OpenText Status
Write-Section "OPENTEXT CORE ENDPOINT PROTECTION"

$otInstalled = $false
$otPaths = @(
  "C:\Program Files\OpenText",
  "C:\Program Files (x86)\OpenText",
  "C:\ProgramData\OpenText"
)

foreach ($path in $otPaths) {
  if (Test-Path $path) {
    $otInstalled = $true
    Write-Status "OpenText Folder" $path "FAIL"
  }
}

$otServices = Get-Service | Where-Object { $_.DisplayName -like '*OpenText*' -or $_.DisplayName -like '*Core*Endpoint*' }
if ($otServices) {
  foreach ($svc in $otServices) {
    Write-Status "OpenText Service" "$($svc.Name) - $($svc.Status)" "FAIL"
  }
}

$otProcs = Get-Process | Where-Object { $_.Name -match 'CoreServiceShell|SkyClient|OESIS' }
if ($otProcs) {
  foreach ($proc in $otProcs) {
    Write-Status "OpenText Process" "$($proc.Name) (PID $($proc.Id))" "FAIL"
  }
}

if (-not $otInstalled -and -not $otServices -and -not $otProcs) {
  Write-Status "OpenText" "Not detected" "OK"
}
#endregion

#region Windows Defender Status
Write-Section "WINDOWS DEFENDER STATUS"

# Check Tamper Protection
$tamperProtection = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection
Write-Status "Tamper Protection" $(if ($tamperProtection -eq 5) { "ENABLED (blocks registry changes!)" } elseif ($tamperProtection -eq 0 -or $tamperProtection -eq 4) { "Disabled" } else { "Unknown ($tamperProtection)" }) $(if ($tamperProtection -eq 5) { "WARN" } else { "OK" })

# Check real-time protection
try {
  $mpStatus = Get-MpComputerStatus -ErrorAction Stop
  Write-Status "Real-Time Protection" $(if ($mpStatus.RealTimeProtectionEnabled) { "ENABLED" } else { "Disabled" }) $(if ($mpStatus.RealTimeProtectionEnabled) { "WARN" } else { "OK" })
  Write-Status "Antivirus Enabled" $(if ($mpStatus.AntivirusEnabled) { "Yes" } else { "No" }) "INFO"
} catch {
  Write-Status "Defender Status" "Could not query (may be disabled or replaced)" "INFO"
}

# Check if Defender is disabled via GPO
$gpoDisabled = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -ErrorAction SilentlyContinue).DisableAntiSpyware
Write-Status "GPO DisableAntiSpyware" $(if ($gpoDisabled -eq 1) { "Set (Defender disabled via policy)" } else { "Not set" }) "INFO"

# Check WinDefend service
$wdService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
if ($wdService) {
  Write-Status "WinDefend Service" "$($wdService.Status) (StartType: $($wdService.StartType))" "INFO"
}
#endregion

#region Other AV Products
Write-Section "OTHER AV PRODUCTS CHECK"

$otherAVs = @{
  "Norton" = @{
    Paths = @("C:\Program Files\Norton*", "C:\Program Files (x86)\Norton*", "C:\ProgramData\Norton*")
    Services = @("Norton*", "Symantec*")
    Procs = @("Norton*", "ccSvcHst")
  }
  "McAfee" = @{
    Paths = @("C:\Program Files\McAfee*", "C:\Program Files (x86)\McAfee*", "C:\Program Files\Common Files\McAfee*")
    Services = @("McAfee*", "mfe*")
    Procs = @("McAfee*", "mfe*")
  }
  "Avast" = @{
    Paths = @("C:\Program Files\Avast*", "C:\Program Files\AVAST*", "C:\ProgramData\Avast*")
    Services = @("avast*", "aswbIDSAgent")
    Procs = @("Avast*", "aswEngSrv")
  }
  "AVG" = @{
    Paths = @("C:\Program Files\AVG*", "C:\Program Files (x86)\AVG*")
    Services = @("AVG*")
    Procs = @("AVG*")
  }
  "Kaspersky" = @{
    Paths = @("C:\Program Files\Kaspersky*", "C:\Program Files (x86)\Kaspersky*")
    Services = @("Kaspersky*", "klnagent")
    Procs = @("avp*", "Kaspersky*")
  }
  "Malwarebytes" = @{
    Paths = @("C:\Program Files\Malwarebytes*", "C:\ProgramData\Malwarebytes*")
    Services = @("MBAMService", "MBAMWebProtection")
    Procs = @("mbam*", "Malwarebytes*")
  }
}

$foundOther = $false
foreach ($avName in $otherAVs.Keys) {
  $av = $otherAVs[$avName]
  $found = $false
  $details = @()

  # Check paths
  foreach ($pathPattern in $av.Paths) {
    if (Test-Path $pathPattern) {
      $found = $true
      $details += "Folder found"
      break
    }
  }

  # Check services
  foreach ($svcPattern in $av.Services) {
    $svc = Get-Service -Name $svcPattern -ErrorAction SilentlyContinue
    if ($svc) {
      $found = $true
      $details += "Service: $($svc.Name)=$($svc.Status)"
    }
  }

  # Check processes
  foreach ($procPattern in $av.Procs) {
    $proc = Get-Process -Name $procPattern -ErrorAction SilentlyContinue
    if ($proc) {
      $found = $true
      $details += "Process running"
    }
  }

  if ($found) {
    $foundOther = $true
    Write-Status $avName ($details -join ", ") "FAIL"
  }
}

if (-not $foundOther) {
  Write-Status "Other AV Products" "None detected" "OK"
}
#endregion

#region Summary and Recommendations
Write-Section "SUMMARY AND RECOMMENDATIONS"

$issues = @()
$recommendations = @()

# Check blocking AVs
$blockingAVCount = ($avProducts | Where-Object {
  $_.displayName -notlike "*Windows Defender*" -and
  $_.displayName -notlike "*Bitdefender*"
}).Count

if ($blockingAVCount -gt 0) {
  $issues += "$blockingAVCount blocking AV product(s) in Security Center"
  $recommendations += "Run BD-Autofix.ps1 with -RemoveGenericAVs if needed"
}

if ($wrInstalled -or $wrServices -or $wrProcs) {
  $issues += "Webroot remnants detected"
  $recommendations += "Run BD-Autofix.ps1, then REBOOT, then run again"
}

if ($otInstalled -or $otServices -or $otProcs) {
  $issues += "OpenText Core Endpoint Protection detected"
  $recommendations += "Deactivate in OpenText GSM portal first, then run cleanup"
}

if (-not $syncroMSP -or $syncroMSP.Status -ne 'Running') {
  $issues += "Syncro agent not running or not found"
  $recommendations += "Reinstall Syncro agent before Bitdefender can deploy"
}

if ($pendingReboot) {
  $issues += "System has pending reboot"
  $recommendations += "REBOOT FIRST before running cleanup scripts"
}

if ($tamperProtection -eq 5) {
  $issues += "Windows Tamper Protection is enabled"
  $recommendations += "Disable Tamper Protection in Windows Security settings or via Intune/GPO"
}

if ($bdInstalled -and -not $bdServices) {
  $issues += "Bitdefender folders exist but services not running"
  $recommendations += "Run BD-Autofix.ps1 with -AggressiveBDCleanup to remove partial install"
}

if ($issues.Count -eq 0) {
  Write-Output ""
  Write-Output "[OK] No blocking issues detected - Bitdefender should install via Syncro policy"
  $statusSummary = "Ready for BD"
} else {
  Write-Output ""
  Write-Output "ISSUES FOUND: $($issues.Count)"
  $i = 1
  foreach ($issue in $issues) {
    Write-Output "  $i. $issue"
    $i++
  }

  Write-Output ""
  Write-Output "RECOMMENDED ACTIONS:"
  $i = 1
  foreach ($rec in $recommendations) {
    Write-Output "  $i. $rec"
    $i++
  }

  $statusSummary = "$($issues.Count) issues: $($issues -join '; ')"
}

Write-Output ""
Write-Output ("=" * 60)
Write-Output "  END OF DIAGNOSTIC REPORT"
Write-Output ("=" * 60)
#endregion

#region Syncro Integration
if ($syncroModuleLoaded) {
  # Log to Activity feed
  if ($LogActivity) {
    $activityMsg = if ($issues.Count -eq 0) {
      "BD Diagnostic: Ready for Bitdefender deployment"
    } else {
      "BD Diagnostic: $($issues.Count) blocking issue(s) found - $($issues -join ', ')"
    }
    Log-Activity -Message $activityMsg -EventName "BD Diagnostic"
    Write-Output ""
    Write-Output "[Syncro] Logged to Asset Activity"
  }

  # Create RMM Alert if issues found
  if ($CreateAlert -and $issues.Count -gt 0) {
    $alertBody = @"
Bitdefender deployment is blocked on this asset.

Issues Found:
$($issues | ForEach-Object { "- $_" } | Out-String)

Recommended Actions:
$($recommendations | ForEach-Object { "- $_" } | Out-String)

Run BD-Autofix-v7.ps1 to resolve.
"@
    Rmm-Alert -Category 'bd_deployment_blocked' -Body $alertBody
    Write-Output "[Syncro] Created RMM Alert: bd_deployment_blocked"
  }

  # Set Asset Custom Field
  if ($SetAssetField) {
    $fieldValue = if ($issues.Count -eq 0) {
      "Ready - $(Get-Date -Format 'MM/dd/yy')"
    } else {
      "Blocked ($($issues.Count) issues) - $(Get-Date -Format 'MM/dd/yy')"
    }
    Set-Asset-Field -Name $AssetFieldName -Value $fieldValue
    Write-Output "[Syncro] Set Asset Field '$AssetFieldName' = '$fieldValue'"
  }
}
#endregion
