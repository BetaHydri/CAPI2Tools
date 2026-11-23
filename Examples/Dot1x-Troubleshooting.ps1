<#
.SYNOPSIS
    Guided 802.1X (EAP-TLS/PEAP) certificate troubleshooting on an NPS server or a client.

.DESCRIPTION
    Enables CAPI2 logging, waits while you reproduce the failed authentication, then runs
    Get-CapiDot1xDiagnosis and writes an HTML report. Run the script on the NPS server and
    on the affected client to see both sides of the certificate validation.

.PARAMETER ReportPath
    Directory for the HTML report.

.PARAMETER Name
    Optional wildcard filter, for example a client host name, user name or MAC address.

.NOTES
    Author: Jan Tiedemann
    Requires: CAPI2Tools module, Administrator privileges (Security log, CAPI2 log)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = (Join-Path -Path $env:TEMP -ChildPath 'Dot1xReports'),

    [Parameter(Mandatory = $false)]
    [string]$Name
)

#Requires -RunAsAdministrator
#Requires -Modules CAPI2Tools

# 1. Prepare: enable CAPI2 logging and start with a clean log
Write-Host 'Step 1: Preparing CAPI2 log...' -ForegroundColor Cyan
Start-CAPI2Troubleshooting -ClearLog

# 2. Reproduce: trigger the authentication again
Write-Host "`nStep 2: Reproduce the failed 802.1X authentication now." -ForegroundColor Yellow
Write-Host '  Client: disable/enable the network adapter or reconnect to the WLAN.' -ForegroundColor Gray
Write-Host '  NPS:    wait until the client has tried to authenticate.' -ForegroundColor Gray
Read-Host 'Press ENTER when done'

# 3. Diagnose: role (NPS or client) is detected automatically
Write-Host "`nStep 3: Analyzing..." -ForegroundColor Cyan
$DiagnosisParams = @{
    Hours      = 1
    ExportPath = $ReportPath
}
if ($Name) {
    $DiagnosisParams['Name'] = $Name
}
$Diagnosis = Get-CapiDot1xDiagnosis @DiagnosisParams

# 4. Drill down: full CAPI2 chain of the first error
if ($Diagnosis.CapiChains.Count -gt 0) {
    Write-Host "`nStep 4: Event chain of the first CAPI2 error" -ForegroundColor Cyan
    $Diagnosis.CapiChains[0].Events | Get-CapiErrorAnalysis -ShowEventChain
}

# 5. Cleanup
Write-Host "`nStep 5: Cleaning up..." -ForegroundColor Cyan
Stop-CAPI2Troubleshooting -DisableLog
