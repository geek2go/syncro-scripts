# Syncro Scripts - Bitdefender Deployment Tools

PowerShell scripts for cleaning up conflicting AV software and preparing Windows endpoints for Bitdefender installation via Syncro RMM.

## The Problem

When migrating from Webroot/OpenText to Bitdefender via Syncro policy:
- Webroot remnants block Bitdefender installation
- OpenText Core Endpoint Protection conflicts
- Windows Defender Tamper Protection blocks registry changes
- Boot-start drivers can't be removed without reboot
- Security Center entries persist even after "removal"

## Scripts

### BD-Diagnostic.ps1

Run this **FIRST** to understand what's installed and what's blocking Bitdefender.

```powershell
# In Syncro, create a new script and paste contents
# Run with no parameters
```

**Output includes:**
- Registered AV products in Security Center
- Syncro agent status
- Bitdefender installation status
- Webroot/OpenText remnants
- Windows Defender Tamper Protection status
- Other AV products detected
- Summary with recommended actions

### BD-Autofix-v7.ps1

The cleanup script. Run after diagnostic to remove blocking software.

```powershell
# Basic run (reports what needs reboot but doesn't reboot)
.\BD-Autofix-v7.ps1

# Auto-reboot if no user is logged in
.\BD-Autofix-v7.ps1 -AutoRebootIfNoUser

# Schedule reboot for 10 PM
.\BD-Autofix-v7.ps1 -ScheduleRebootIfNeeded "22:00"

# Force reboot regardless (for stubborn machines)
.\BD-Autofix-v7.ps1 -ForceReboot -RebootDelaySeconds 120

# Full cleanup including Malwarebytes and other AVs
.\BD-Autofix-v7.ps1 -HandleMalwarebytes -RemoveGenericAVs -AutoRebootIfNoUser

# Clean partial Bitdefender install
.\BD-Autofix-v7.ps1 -AggressiveBDCleanup -ForceReboot
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-HandleMalwarebytes` | Stop/disable Malwarebytes services (non-destructive) |
| `-AggressiveBDCleanup` | Remove partial Bitdefender folders if present |
| `-AutoRebootIfNoUser` | Reboot immediately if no user is logged in |
| `-ScheduleRebootIfNeeded "HH:mm"` | Schedule reboot for specific time |
| `-RemoveGenericAVs` | Remove Norton, McAfee, Avast, AVG, Kaspersky |
| `-ForceReboot` | Always reboot at end of script |
| `-RebootDelaySeconds` | Delay before reboot (default: 60) |
| `-LogActivity` | Log results to Syncro Asset Activity feed |
| `-CreateTicketOnFail` | Create Syncro ticket if manual intervention needed |
| `-CloseAlertOnSuccess` | Close `bd_deployment_blocked` alert on success |

**Exit Codes:**
| Code | Meaning |
|------|---------|
| 0 | Success, no reboot needed |
| 3010 | Success, reboot required/scheduled |
| 1 | Error |

## Typical Workflow

### For machines with Webroot

1. **Run Diagnostic** to see current state
2. **Deactivate Webroot** in OpenText GSM portal (if applicable)
3. **Run Autofix v7** with `-AutoRebootIfNoUser` or `-ScheduleRebootIfNeeded`
4. **After reboot**, run Diagnostic again to verify cleanup
5. **Trigger Syncro policy sync** (Autofix does this automatically)
6. Bitdefender should now install

### For stubborn machines

If Bitdefender still won't install after one pass:

```powershell
# Run with all cleanup options and force reboot
.\BD-Autofix-v7.ps1 -HandleMalwarebytes -RemoveGenericAVs -AggressiveBDCleanup -ForceReboot
```

Then after reboot, run Diagnostic to check status.

### If Tamper Protection is blocking

The script cannot disable Tamper Protection if it's enabled (by design). You must:

1. **Manually disable** in Windows Security > Virus & Threat Protection > Manage Settings
2. Or **Deploy via Intune/GPO** before running the script
3. Or **Use Microsoft Defender for Endpoint** portal to disable

## Syncro Setup

### Creating the Scripts in Syncro

1. Go to **Scripts** in Syncro
2. Click **New Script**
3. Name: `BD-Diagnostic` or `BD-Autofix-v7`
4. Platform: **Windows**
5. Script Type: **PowerShell**
6. Paste the script contents
7. For Autofix, add the parameters you want in the **Script Arguments** field

### Running via Policy

You can attach these scripts to a Syncro policy to run on schedule or on-demand.

### Recommended Parameters for Syncro

For unattended cleanup with full Syncro integration:
```
-AutoRebootIfNoUser -HandleMalwarebytes -LogActivity -CloseAlertOnSuccess
```

For after-hours maintenance window:
```
-ScheduleRebootIfNeeded "02:00" -HandleMalwarebytes -RemoveGenericAVs -LogActivity
```

For creating tickets when manual intervention is needed:
```
-HandleMalwarebytes -CreateTicketOnFail -LogActivity
```

### Syncro Module Integration

Both scripts use the Syncro PowerShell module when available:

**BD-Diagnostic.ps1:**
```powershell
# Run with Syncro integration
-CreateAlert        # Creates RMM alert if blocking issues found
-LogActivity        # Logs summary to Asset Activity feed
-SetAssetField      # Sets "BD Deployment Status" custom field
```

**BD-Autofix-v7.ps1:**
```powershell
# Run with Syncro integration
-LogActivity           # Logs results to Asset Activity feed
-CreateTicketOnFail    # Creates ticket if manual intervention needed
-CloseAlertOnSuccess   # Closes bd_deployment_blocked alert on success
```

### Syncro Alert Flow

1. **Diagnostic creates alert** (`-CreateAlert`): `bd_deployment_blocked`
2. **Autofix runs and cleans up**
3. **Autofix closes alert** (`-CloseAlertOnSuccess`) if successful

## Log Files

Logs are written to:
```
C:\ProgramData\SyncroMSP\Scripts\bd_autofix.log
```

Check this log if the script runs but Bitdefender still doesn't install.

## Common Issues

### Security Center unchanged after cleanup

**Cause:** Windows Tamper Protection is blocking registry changes
**Solution:** Disable Tamper Protection manually or via MDM

### WRSA process keeps respawning

**Cause:** Webroot service is restarting the process
**Solution:** Script now uses aggressive kill methods; if still failing, reboot is required

### Syncro service not found

**Cause:** Syncro agent is not installed or broken
**Solution:** Reinstall Syncro agent before running Bitdefender cleanup

### Folders locked (added to PendingFileRenameOperations)

**Cause:** Files are in use by running processes or drivers
**Solution:** Reboot is required; script sets this up automatically

## Changes from v6

- **Fixed:** Reboot actually triggers (not just exit 3010)
- **Fixed:** Better driver unload before deletion
- **Fixed:** Verify Security Center changes applied
- **Added:** Pre-flight checks for Syncro agent
- **Added:** Better WRSA termination (aggressive mode)
- **Added:** Multiple reboot attempt methods
- **Added:** `-ForceReboot` and `-RebootDelaySeconds` parameters
- **Added:** Detailed reboot reason tracking
