##############################################################################
# BLGen9_Server_Multiconnection_Sample.ps1
#
# Example script to demonstrate creating a Server Profile with the following:
#
# - HP ProLiant BL Gen9
# - Set BootMode to UEFI
# - Set PXEBootPolicy to IPv4ThenIPv6
# - Configure 2 NICs in assigned to Net-41A and Net-41B
# - Set requested bandwidth
#
#   VERSION 1.0
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
Import-Module HPOneView.120

# First connect to the CI Management Appliance
if (!$global:myAppliance) {
    $global:myAppliance = Read-Host "HP OneView Appliance hostname or IP address"
}

Write-Host "Connecting to" $global:myAppliance
Connect-HPOVMgmt -appliance $global:myAppliance

# Now view what enclosures have been imported
Write-Host "Here is the list of enclosures managed by this appliance"
Get-HPOVEnclosure -report

# Now list all the servers that have been imported with their current state
Get-HPOVServer -list

$profileName = "HP ProLiant BL460 Gen 9 UEFI Profile Template"
$bl460SHT = Get-HPOVServerHardwareTypes -name "BL460c Gen9 1"
$eg = Get-HPOVEnclosureGroup "Default EG1"
$net1 = Get-HPOVNetwork "Net-41-A"
$con1 = New-HPOVProfileConnection -network $net1 -connectionType Ethernet -connectionId 1
$net2 = Get-HPOVNetwork "Net-41-B"
$con2 = New-HPOVProfileConnection -network $net2 -connectionType Ethernet -connectionId 2
$conList = @($con1, $con2)
$params = @{
        name               = $profileName;
        server             = "unassigned";
        serverHardwareType = $bl460SHT;
        enclosureGroup     = $eg;
        connections        = $conList
        bootMode           = "UEFI";
        pxeBootPolicy      = "IPv4ThenIPv6";
        bootOrder          = "HardDisk";
        HideUnusedFlexnics = $True
}        

New-HPOVProfile @params | Wait-HPOVTaskComplete