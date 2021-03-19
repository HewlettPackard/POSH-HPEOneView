##############################################################################
# ImportEnclosure_Sample.ps1
# - Example scripts for importing an enclosure to a specific EG.
#
#   VERSION 3.0
#
# (C) Copyright 2013-2021 Hewlett Packard Enterprise Development LP
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

if (-not (get-module HPEOneView.530))
{

    Import-Module HPEOneView.530

}

if (-not $ConnectedSessions)
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-OVMgmt -Hostname $Appliance -Username $Username -Password $Password

}

# Get the OA hostname, user name and password
$myOA          = Read-Host "Enclosure OA hostname or IP address"
$myOAUser      = Read-Host "OA user name"
$myOAPass      = Read-Host "OA password"
$enclGroupName = Read-Host "Enclosure Group name"
$licenseIntent = Read-Host "Licensing intent (OneView or OneViewNoiLO)"
$sppFileName   = Read-Host "SPP file name ('SPP*.iso'), or <Enter> to skip firmware"

# Now import the enclosure using this new enclosure group
New-OVEnclosure -hostname $myOA -enclGroupName $enclGroupName -username $myOAUser -password $myOAPass -licensingIntent $licenseIntent -fwBaselineIsoFilename $sppFileName -ApplianceConnection $ApplianceConnection
