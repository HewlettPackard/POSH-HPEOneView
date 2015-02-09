##############################################################################
# Alerts_Sample.ps1
# - Example scripts for configuring the CI Manager appliance (networking, NTP, 
#   etc.).
#
#   VERSION 1.1
#
# (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
##############################################################################
<#
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

#>
##############################################################################
Import-Module HPOneView.110

# First connect to the HP OneView appliance.
if (-not $global:cimgmtSessionId) { Connect-HPOVMgmt }

# Make sure we have a local user 'Sally'
$sally = Get-HPOVUser Sally
if (!$sally) {
    New-HPOVUser Sally -fullName "Sally Test User" -password SallyPassword -roleNames ("Network administrator")
}

# Now view the list of alerts
# Note: If there is a large set of alerts on the appliance, calling Get-HPOVAlert (without any filters)
# can take a VERY long time!  This query really needs to be filtered by category, state, etc.
Get-HPOVAlert | Sort-Object created -Descending| ft -AutoSize

# Let's assign any Interconnect Bay alerts to Administrator
$alerts = Get-HPOVAlert -healthCategory Logical-Interconnect -alertState Active
foreach ($alert in $alerts) {
    $updatedAlert = Set-HPOVAlertAssignToUser $alert.uri "Sally"
    Write-Host "Assigned to Sally:" $updatedAlert.description
    }

# Clear any alerts older than one week
$alerts = Get-HPOVAlert -alertState Active
foreach ($alert in $alerts) {
    $created = Get-Date $alert.created

    if ((Get-Date) -gt $created.AddDays(7)) {
        $updatedAlert = Set-HPOVAlertCleared $alert.uri
        Write-Host "Cleared from" $created ":" $updatedAlert.description
    }
}

#Display the active alerts for Sally, most recent first
Write-Host "Sally's active alerts:"
Get-HPOVAlert -assignedToUser Sally -alertState Active | Sort-Object created -Descending | Format-Table -Property created, severity, description, resourceURI -AutoSize
