##############################################################################
# Server_Profile_Template_Rack_Server_Sample.ps1
#
# Example script to demonstrate creating a Server Profile Template
# with the following:
#
# - DL380 Gen10 Plus
# - Set BootMode to UEFIOptimized
# - Set PXEBootPolicy to IPv4
# - Local Storage
# - Firmware management
#
# Then create a Server Profile from the Template, assigning to a specific
# server.
#
#   VERSION 1.0
#
# (C) Copyright 2013-2022 Hewlett Packard Enterprise Development LP
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

if (-not (get-module HPEOneView.700))
{

    Import-Module HPEOneView.700

}

$MyConnection = Connect-OVMgmt -Hostname 192.168.19.90 -Credential (Get-Credential -Username Administrator -Message Password)

# View the connected HPE OneView appliances from the library by displaying the global $ConnectedSessions variable
$ConnectedSessions

# Now list all the servers that have been imported with their current state
Get-OVServer

# Next, show the avialble servers from the available Server Hardware Type
$DL380SHT = Get-OVServerHardwareType -name "DL380 Gen10 Plus" -ErrorAction Stop

Get-OVServer -ServerHardwareType $DL380SHT -NoProfile

$TemplateName        = "Production Node Template v1"
$TemplateDescription = "Enterprise production node, version 1.0"
$Baseline            = Get-OVBaseline -FileName 'P45316_001_gen10spp-2021_10_0-SPP2021100_2021_1012_13.iso' -ErrorAction Stop
$LogicalDisk1        = New-OVServerProfileLogicalDisk -Name 'Boot' -RAID RAID1 -DriveType SATASSD -Bootable $true
$LogicalDisk2        = New-OVServerProfileLogicalDisk -Name 'Data1' -RAID RAID6 -DriveType SAS -NumberofDrives 8
$StorageController   = New-OVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $LogicalDisk1, $LogicalDisk2

$params = @{
    Name               = $TemplateName;
    Description        = $TemplateDescription;
    ServerHardwareType = $DL380SHT;
    Firmware           = $true;
    Baseline           = $Baseline;
    FirmwareMode       = 'FirmwareAndSoftware'
    BootMode           = "BIOS";
    ManageBoot         = $True;
    BootOrder          = "HardDisk";
    LocalStorage       = $True;
    StorageController  = $StorageController
}

# Create Server Profile Template
New-OVServerProfileTemplate @params | Wait-OVTaskComplete

# Get the created Server Profile Template
$spt = Get-OVServerProfileTemplate -Name $TemplateName -ErrorAction Stop

# Create Server Profile from Server Profile Template, searching for a SY480 Gen10 server with at least 32 CPU and 512GB of RAM
Get-OVServer -InputObject $spt -NoProfile | Where-Object { ($_.processorCount * $_.processorCoreCount) -ge 32 -and $_.memoryMb -ge (512 * 1024) } | Select -First 4 -OutVariable svr

# Make sure servers are powered off
$svr | Where-Object powerState -ne "Off" | Stop-OVServer -Confirm:$false

# Create the number of Servers from the $svr collection
1..($svr.Count) | % {

    New-OVServerProfile -Name ("Node {0:000}" -f $_) -Assignment Server -Server $svr[($_ - 1)] -ServerProfileTemplate $spt -Async

}

Get-OVTask -State Running | Wait-OVTaskComplete