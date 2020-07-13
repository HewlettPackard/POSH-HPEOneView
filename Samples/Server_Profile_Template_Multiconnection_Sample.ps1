##############################################################################
# Server_Profile_Template_Multiconnection_Sample.ps1
#
# Example script to demonstrate creating a Server Profile Template
# with the following:
#
# - HPE Synery 480 Gen 10
# - Set BootMode to UEFIOptimized
# - Set PXEBootPolicy to IPv4
# - Configure 2 NICs in assigned to the Management VLAN
# - Configure 2 NICs for VM connectivity
# - Configure 2 HBAs for Shared Storage connectivity
# - Local Storage
# - Firmware management
#
# Then create a Server Profile from the Template, assigning to a specific
# server.
#
#   VERSION 4.0
#
# (C) Copyright 2013-2020 Hewlett Packard Enterprise Development LP
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

$MyConnection = Connect-OVMgmt -Hostname 192.168.19.90 -Credential $HPOVPSCredential

# View the connected HPE OneView appliances from the library by displaying the global $ConnectedSessions variable
$ConnectedSessions

# Now view what enclosures have been imported
Get-OVEnclosure

# Now list all the servers that have been imported with their current state
Get-OVServer

# Next, show the avialble servers from the available Server Hardware Type
$SY480Gen10SHT = Get-OVServerHardwareType -name "SY 480 Gen10 1" -ErrorAction Stop
Get-OVServer -ServerHardwareType $SY480Gen10SHT -NoProfile

$TemplateName        = "Hypervisor Cluster Node Template v1"
$TemplateDescription = "Corp standard hypervisor cluster node, version 1.0"
$eg                  = Get-OVEnclosureGroup -Name "DCS Synergy Default EG"
$Baseline            = Get-OVBaseline -FileName 'SPP_2017_10_20171215_for_HPE_Synergy_Z7550-96455.iso' -ErrorAction Stop
$con1                = Get-OVNetwork -Name "Management Network (VLAN1)" -ErrorAction Stop | New-OVServerProfileConnection -ConnectionID 1 -Name 'Management Network (VLAN1) Connection 1' -Bootable -Priority Primary
$con2                = Get-OVNetwork -Name "Management Network (VLAN1)" -ErrorAction Stop | New-OVServerProfileConnection -ConnectionID 2 -Name 'Management Network (VLAN1) Connection 2'
$con3                = Get-OVNetworkSet -Name 'Prod NetSet' -ErrorAction Stop | New-OVProfileConnection -ConnectionId 3 -Name 'VM Traffic Connection 3'
$con4                = Get-OVNetworkSet -Name 'Prod NetSet' -ErrorAction Stop | New-OVProfileConnection -ConnectionId 4 -Name 'VM Traffic Connection 4'
$con5                = Get-OVNetwork -Name "Prod Fabric A" -ErrorAction Stop | New-OVServerProfileConnection -ConnectionID 5 -Name 'Prod Fabric A Connection 5'
$con6                = Get-OVNetwork -Name "Prod Fabric B" -ErrorAction Stop | New-OVServerProfileConnection -ConnectionID 6 -Name 'Prod Fabric B Connection 6'
$LogicalDisk1        = New-OVServerProfileLogicalDisk -Name 'Disk 1' -RAID RAID1
$StorageController   = New-OVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $LogicalDisk1

$params = @{
	Name               = $TemplateName;
	Description        = $TemplateDescription;
	ServerHardwareType = $SY480Gen10SHT;
	EnclosureGroup     = $eg;
	Connections        = $con1, $con2, $con3 ,$con4, $con5, $con6;
	Firmware           = $true;
	Baseline           = $Baseline;
	FirmwareMode       = 'FirmwareAndSoftware'
	BootMode           = "UEFIOptimized";
	PxeBootPolicy      = "IPv4";
	ManageBoot         = $True;
	BootOrder          = "HardDisk";
	LocalStorage       = $True;
	StorageController  = $StorageController;
	HideUnusedFlexnics = $True
}

# Create Server Profile Template
New-OVServerProfileTemplate @params | Wait-OVTaskComplete

# Get the created Server Profile Template
$spt = Get-OVServerProfileTemplate -Name $TemplateName -ErrorAction Stop

# Create Server Profile from Server Profile Template, searching for a SY480 Gen10 server with at least 4 CPU and 512GB of RAM
Get-OVServer -ServerHardwareType $SY480Gen10SHT -NoProfile -ErrorAction Stop | ? { ($_.processorCount * $_.processorCoreCount) -ge 4 -and $_.memoryMb -ge (512 * 1024) } | Select -First 4 -OutVariable svr

# Make sure servers are powered off
$svr | Stop-OVServer -Confirm:$false

# Create the number of Servers from the $svr collection
1..($svr.Count) | % {

	New-OVServerProfile -Name "Hyp-Clus-0$_" -Assignment Server -Server $svr[($_ - 1)] -ServerProfileTemplate $spt -Async

}

Get-OVTask -State Running | Wait-OVTaskComplete