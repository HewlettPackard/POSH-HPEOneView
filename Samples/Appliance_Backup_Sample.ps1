##############################################################################
# Appliance_Backup_Sample.ps1
# - Example script to automate appliance backup
#
#   VERSION 3.0
#
# (C) Copyright 2013-2022 Hewlett-Packard Development Company, L.P.
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

<#
.SYNOPSIS
Appliance Backup Automation Script

.DESCRIPTION
This PowerShell script will assist in automating the backup of an HP OneView appliance.

.PARAMETER Location
The directory where the appliance generated backup file will be saved to.  If the directory does not exist, 'C:\HPOneView_Backup' will automatically be created.

.INPUTS
None.

.OUTPUTS
System.String

.LINK
None.

.EXAMPLE
PS C:\> .\Appliance_Backup.ps1

Execute the backup of an appliance with default parameters.

.EXAMPLE
PS C:\> .\Appliance_Backup.ps1 C:\Backups\MyAppliance

Execute the backup of an appliance, specifying an alternate directory.

#>

[CmdletBinding()]
Param
(

	[parameter(Mandatory = $false, Position = 0)]
	[String]$Location = 'C:\HPOneView_Backup'

)

#Begin Command Trace for logging purposes
Start-Transcript $Location\Appliance_backup$(get-date -uformat %y%m%d).trace

#Create directory if it doesn't exist
if (-not(Test-Path $Location))
{

    New-Item -ItemType Directory -Path $Location

}

if (-not (get-module HPEOneView.700))
{

    Import-Module HPEOneView.700

}

if (-not $ConnectedSessions)
{

    $Appliance = Read-Host 'ApplianceName'
    $Credential = Get-Credential -UserName Administrator -Message Password

    $ApplianceConnection = Connect-OVMgmt -Hostname $Appliance -Credential $Credential

}

#Execute the backup
New-OVBackup -Location $Location

"Backup Complete $(Get-Date)"

Stop-Transcript