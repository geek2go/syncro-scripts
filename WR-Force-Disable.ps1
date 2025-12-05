<#
  WR-Force-Disable.ps1
  Purpose: Forcefully disable Webroot/OpenText services and drivers, then reboot.
  Use this when standard removal methods fail.
#>

Write-Output "=== Webroot Force Disable Script ==="
Write-Output "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Output ""

# Step 1: Disable services
Write-Output "--- Disabling Webroot services ---"
$services = @('WRCoreService', 'WRSkyClient', 'WRSVC')
foreach ($svc in $services) {
    $result = sc.exe config $svc start= disabled 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Output "[OK] Disabled service: $svc"
    } else {
        Write-Output "[FAIL] Could not disable $svc - $result"
    }
}

# Step 2: Disable boot drivers via registry
Write-Output ""
Write-Output "--- Disabling boot drivers via registry ---"
$drivers = @('WRkrn', 'WRBoot', 'WRCore', 'WREDRD', 'wrUrlFlt')
foreach ($drv in $drivers) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$drv"
    if (Test-Path $path) {
        try {
            Set-ItemProperty -Path $path -Name "Start" -Value 4 -Force -ErrorAction Stop
            Write-Output "[OK] Disabled driver: $drv (Start=4)"
        } catch {
            Write-Output "[FAIL] Could not disable $drv - $($_.Exception.Message)"
        }
    } else {
        Write-Output "[SKIP] Driver not found: $drv"
    }
}

# Step 3: Kill processes
Write-Output ""
Write-Output "--- Killing Webroot processes ---"
$procs = Get-Process | Where-Object { $_.Name -match '^WR' }
if ($procs) {
    foreach ($proc in $procs) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-Output "[OK] Killed: $($proc.Name) (PID $($proc.Id))"
        } catch {
            Write-Output "[FAIL] Could not kill $($proc.Name) - $($_.Exception.Message)"
        }
    }
} else {
    Write-Output "[INFO] No WR processes running"
}

# Step 4: Show current state
Write-Output ""
Write-Output "--- Current State ---"
Write-Output "Services:"
Get-Service | Where-Object { $_.Name -match 'WR' } | ForEach-Object {
    Write-Output "  $($_.Name): $($_.Status) (StartType: $($_.StartType))"
}

Write-Output ""
Write-Output "Processes:"
$remaining = Get-Process | Where-Object { $_.Name -match '^WR' }
if ($remaining) {
    $remaining | ForEach-Object { Write-Output "  $($_.Name) (PID $($_.Id))" }
} else {
    Write-Output "  None running"
}

Write-Output ""
Write-Output "Security Center AV:"
Get-CimInstance -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "  $($_.displayName)"
}

# Step 5: Reboot
Write-Output ""
Write-Output "--- Rebooting in 60 seconds ---"
shutdown /r /t 60 /f /c "Webroot cleanup reboot"
Write-Output "Reboot scheduled. Machine will restart shortly."
