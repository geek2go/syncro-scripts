# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

PowerShell scripts for cleaning up conflicting antivirus software and preparing Windows endpoints for Bitdefender installation via Syncro RMM. These scripts are deployed through the Syncro MSP platform.

## Scripts

### BD-Diagnostic.ps1
Diagnostic script to identify what's blocking Bitdefender installation. Run this first to assess system state.

Key parameters:
- `-CreateAlert` - Creates RMM alert if blocking issues found
- `-LogActivity` - Logs summary to Syncro Asset Activity feed
- `-SetAssetField` - Sets custom field with BD deployment status

### BD-Autofix-v7.ps1
Cleanup script that removes blocking AV software (Webroot, OpenText, Norton, McAfee, etc.) and prepares systems for Bitdefender.

Key parameters:
- `-AutoRebootIfNoUser` - Reboot immediately if no interactive user logged in
- `-ScheduleRebootIfNeeded "HH:mm"` - Schedule reboot for specific time
- `-ForceReboot` - Always reboot at end
- `-HandleMalwarebytes` - Stop/disable MBAM services (non-destructive)
- `-AggressiveBDCleanup` - Remove partial Bitdefender folders
- `-RemoveGenericAVs` - Remove Norton, McAfee, Avast, AVG, Kaspersky

Exit codes: 0 = success, 3010 = reboot required, 1 = error

## Architecture

Both scripts share common patterns:
- **Syncro module integration**: Import `$env:SyncroModule` when running in Syncro context for `Log-Activity`, `Rmm-Alert`, `Set-Asset-Field`, `Create-Syncro-Ticket`
- **Logging**: Both log to `C:\ProgramData\SyncroMSP\Scripts\bd_autofix.log`
- **Reboot handling**: Uses `PendingFileRenameOperations` for locked files and multiple reboot methods (shutdown.exe, Restart-Computer, WMI)
- **Driver cleanup**: Boot-start drivers require reboot - script detects this and flags appropriately

## Syncro Workflow

1. Diagnostic creates `bd_deployment_blocked` alert
2. Autofix runs cleanup
3. Autofix closes alert on success via `-CloseAlertOnSuccess`

## Testing

These scripts must be tested on Windows endpoints via Syncro RMM or in an elevated PowerShell session:
```powershell
# Local testing (requires admin)
.\BD-Diagnostic.ps1
.\BD-Autofix-v7.ps1 -HandleMalwarebytes
```

## Key Constraints

- **Tamper Protection**: Scripts cannot disable Windows Tamper Protection if enabled - must be done manually or via Intune/GPO
- **Boot drivers**: Webroot boot drivers (WRBoot, WRCore, etc.) cannot be removed without reboot
- **Syncro agent required**: Bitdefender deploys via Syncro policy - agent must be present and running
