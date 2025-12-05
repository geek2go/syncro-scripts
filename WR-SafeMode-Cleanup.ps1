<#
  WR-SafeMode-Cleanup.ps1
  Purpose: Set machine to boot into Safe Mode with Networking, then reboot.
  In Safe Mode, Webroot drivers don't load, allowing cleanup.

  After Safe Mode boot, run WR-SafeMode-Cleanup-Phase2.ps1 to do the actual cleanup,
  then restore normal boot.
#>

param(
    [switch]$Phase2  # Run this after Safe Mode boot to clean up and restore normal boot
)

if (-not $Phase2) {
    # PHASE 1: Set Safe Mode and reboot
    Write-Output "=== Webroot Safe Mode Cleanup - Phase 1 ==="
    Write-Output "Setting machine to boot into Safe Mode with Networking..."
    Write-Output ""

    # Use bcdedit to set Safe Mode with Networking
    $result = bcdedit /set "{current}" safeboot network 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Output "[OK] Safe Mode with Networking enabled for next boot"
    } else {
        Write-Output "[FAIL] Could not set Safe Mode: $result"
        exit 1
    }

    # Create a scheduled task to run Phase 2 after Safe Mode boot
    $scriptPath = "C:\ProgramData\SyncroMSP\Scripts\WR-SafeMode-Cleanup.ps1"

    # Copy this script to the target location if not already there
    $currentScript = $MyInvocation.MyCommand.Path
    if ($currentScript -and $currentScript -ne $scriptPath) {
        Copy-Item -Path $currentScript -Destination $scriptPath -Force -ErrorAction SilentlyContinue
    }

    # Create scheduled task to run at startup in Safe Mode
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" -Phase2"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Unregister-ScheduledTask -TaskName "WR-SafeMode-Cleanup-Phase2" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "WR-SafeMode-Cleanup-Phase2" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    Write-Output "[OK] Scheduled Phase 2 cleanup task"
    Write-Output ""
    Write-Output "Rebooting into Safe Mode in 30 seconds..."
    Write-Output "After cleanup, machine will reboot back to normal mode."

    shutdown /r /t 30 /f /c "Rebooting into Safe Mode for Webroot cleanup"

} else {
    # PHASE 2: We're in Safe Mode - do the cleanup
    Write-Output "=== Webroot Safe Mode Cleanup - Phase 2 ==="
    Write-Output "Running in Safe Mode - Webroot drivers should not be loaded"
    Write-Output ""

    # Verify we're in Safe Mode
    $safeMode = (Get-CimInstance Win32_ComputerSystem).BootupState
    Write-Output "Boot state: $safeMode"
    Write-Output ""

    # Check if WR processes are running (they shouldn't be in Safe Mode)
    $wrProcs = Get-Process | Where-Object { $_.Name -match '^WR' }
    if ($wrProcs) {
        Write-Output "WARNING: Webroot processes are running - may not be in Safe Mode"
        $wrProcs | ForEach-Object { Write-Output "  $($_.Name) (PID $($_.Id))" }
    } else {
        Write-Output "[OK] No Webroot processes running"
    }

    Write-Output ""
    Write-Output "--- Deleting Webroot services ---"
    $services = @('WRCoreService', 'WRSkyClient', 'WRSVC', 'WRkrn', 'WRBoot', 'WRCore', 'WREDRD')
    foreach ($svc in $services) {
        $result = sc.exe delete $svc 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Output "[OK] Deleted service: $svc"
        } else {
            Write-Output "[INFO] $svc - $result"
        }
    }

    Write-Output ""
    Write-Output "--- Deleting Webroot registry keys ---"
    $regKeys = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\WRCoreService',
        'HKLM:\SYSTEM\CurrentControlSet\Services\WRSkyClient',
        'HKLM:\SYSTEM\CurrentControlSet\Services\WRSVC',
        'HKLM:\SYSTEM\CurrentControlSet\Services\WRkrn',
        'HKLM:\SYSTEM\CurrentControlSet\Services\WRBoot',
        'HKLM:\SYSTEM\CurrentControlSet\Services\WRCore',
        'HKLM:\SYSTEM\CurrentControlSet\Services\WREDRD',
        'HKLM:\SOFTWARE\Webroot',
        'HKLM:\SOFTWARE\WOW6432Node\Webroot',
        'HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\{29E48DCA-7235-2710-CF04-B562AD626365}',
        'HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\{6E6D2E8B-F332-149C-090C-C9A3031279B6}',
        'HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\{EFF592AE-53CE-A502-5F80-8D832AB17CC5}'
    )
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-Output "[OK] Deleted: $key"
            } catch {
                Write-Output "[FAIL] $key - $($_.Exception.Message)"
            }
        }
    }

    Write-Output ""
    Write-Output "--- Deleting Webroot folders ---"
    $folders = @(
        'C:\Program Files\Webroot',
        'C:\Program Files (x86)\Webroot',
        'C:\ProgramData\WRData',
        'C:\ProgramData\Webroot'
    )
    foreach ($folder in $folders) {
        if (Test-Path $folder) {
            try {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-Output "[OK] Deleted: $folder"
            } catch {
                Write-Output "[FAIL] $folder - $($_.Exception.Message)"
            }
        }
    }

    Write-Output ""
    Write-Output "--- Restoring normal boot mode ---"
    $result = bcdedit /deletevalue "{current}" safeboot 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Output "[OK] Safe Mode disabled - will boot normally next restart"
    } else {
        Write-Output "[WARN] Could not disable Safe Mode: $result"
        Write-Output "       You may need to run: bcdedit /deletevalue {current} safeboot"
    }

    # Remove the scheduled task
    Unregister-ScheduledTask -TaskName "WR-SafeMode-Cleanup-Phase2" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "[OK] Removed cleanup scheduled task"

    Write-Output ""
    Write-Output "--- Cleanup complete ---"
    Write-Output "Rebooting to normal mode in 60 seconds..."

    # Log results
    $logPath = "C:\ProgramData\SyncroMSP\Scripts\wr_safemode_cleanup.log"
    "Cleanup completed at $(Get-Date)" | Out-File $logPath -Append

    shutdown /r /t 60 /f /c "Webroot cleanup complete - rebooting to normal mode"
}
