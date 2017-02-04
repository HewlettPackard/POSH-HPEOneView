##############################################################################
# Server_Profile_Template_Multiconnection_Sample.ps1
#
# Example script to demonstrate creating a Server Profile Template
# with the following:
#
# - HP ProLiant BL Gen9
# - Set BootMode to UEFI
# - Set PXEBootPolicy to IPv4ThenIPv6
# - Configure 2 NICs in assigned to VLAN 1-A and VLAN 1-B
# - Local Storage
# - Firmware management
#
# Then create a Server Profile from the Template, assigning to a specific
# server.
#
#   VERSION 3.1
#
# (C) Copyright 2013-2017 Hewlett Packard Enterprise Development LP 
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

if (-not (get-module HPOneview.300)) 
{

    Import-Module HPOneView.300

}

if (-not $ConnectedSessions) 
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-HPOVMgmt -Hostname $Appliance -Username $Username -Password $Password

}

"Connected to appliance: {0} " -f ($ConnectedSessions | ? Default).Name | Write-Host

# Now view what enclosures have been imported
Write-Host "Here is the list of enclosures managed by this appliance:"
Get-HPOVEnclosure

# Now list all the servers that have been imported with their current state
Write-Host "Here is the list of all servers managed by this appliance:"
Get-HPOVServer

$TemplateName = "Hypervisor Cluster Node Template v1"
$BL460Gen9SHT = Get-HPOVServerHardwareTypes -name "BL460c Gen9 1" -ErrorAction Stop

"Showing all {0} SHT without profiles assigned:" -f $BL460Gen9SHT.Name | Write-Host
Get-HPOVServer -ServerHardwareType $BL460Gen9SHT -NoProfile 


$eg                = Get-HPOVEnclosureGroup -Name "Default EG1"
$Baseline          = Get-HPOVBaseline -FileName 'baseline_name.iso' -ErrorAction Stop
$con1              = Get-HPOVNetwork -Name "VLAN 1-A" | New-HPOVServerProfileConnection -ConnectionID 1 -Name 'VLAN 1-A Connection' -Bootable -Priority Primary
$con2              = Get-HPOVNetwork -Name "VLAN 1-B" | New-HPOVServerProfileConnection -ConnectionID 2 -Name 'VLAN 1-B Connection'
$con3              = Get-HPOVNetworkSet -Name 'Prod NetSet A' | New-HPOVProfileConnection -connectionId 3
$con4              = Get-HPOVNetworkSet -Name 'Prod NetSet B' | New-HPOVProfileConnection -connectionId 4
$LogicalDisk1      = New-HPOVServerProfileLogicalDisk -Name 'Disk 1' -RAID RAID1
$StorageController = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $LogicalDisk1

$params = @{
	Name               = $TemplateName;
	ServerHardwareType = $BL460Gen9SHT;
	EnclosureGroup     = $eg;
	Connections        = $con1,$con2,$con3,$con4;
	Firmware           = $true;
	Baseline           = $Baseline;
	FirmwareMode       = 'FirmwareAndSoftware'
	BootMode           = "UEFI";
	PxeBootPolicy      = "IPv4ThenIPv6";
	ManageBoot         = $True;
	BootOrder          = "HardDisk";
	LocalStorage       = $True;
	StorageController  = $StorageController;
	HideUnusedFlexnics = $True
}        

New-HPOVServerProfileTemplate @params | Wait-HPOVTaskComplete

#Display Server Profile Templates that are configured
Get-HPOVServerProfileTemplate -ErrorAction Stop

#Create Server Profile from Server Profile Template to 'Encl1, Bay 1' server resource
$svr = Get-HPOVServer -ServerHardwareType $BL460Gen9SHT -NoProfile -ErrorAction Stop | Select -First 1
$spt = Get-HPOVServerProfileTemplate -Name $TemplateName -ErrorAction Stop
New-HPOVServerProfile -Name "Hyp-Clus-01" -Server $svr -ServerProfileTemplate $spt