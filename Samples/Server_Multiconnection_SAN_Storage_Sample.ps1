﻿##############################################################################
# Server_Multiconnection_SAN_Storage_Sample.ps1
#
# Example script to demonstrate creating a Server Profile with the following:
#
# - Configure 2 NICs in paired with Red
# - Configure 2 NICs in paired with Black
# - Configure 2 NICs in paired with NetworkSet (Production Networks)
# - Configure 2 FC connections to the Production Fabric A and B
# - Set requested bandwidth
# - Attach SAN Storage
#
#   VERSION 3.1
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
if (-not (get-module HPEOneView.540))
{

    Import-Module HPEOneView.540

}

if (-not $ConnectedSessions)
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-OVMgmt -Hostname $Appliance -Username $Username -Password $Password

}

# Now view what enclosures have been imported
Write-Host "Here is the list of enclosures managed by this appliance"
Get-OVEnclosure

# Now list all the servers that have been imported with their current state
$servers = Get-OVServer
Write-Host "There are [$servers.Count] servers managed by this appliance."
Get-OVServer

# Make sure all the servers are powered off
$servers | % {
    if ($_.powerState -ne "Off") {
        Write-Host "Server '$_.name' is ($_.powerState).  Powering off..."
        $Server | Stop-OVServer -Confirm:$false
    }
}

# Now create a server profile for the first available server
$server = Get-OVServer -NoProfile | Select -First 1

$profileName = "Profile-" + $server.serialNumber
Write-Host "Creating" $profileName "for server" $server.name

# Assume that networks "red" and "blue" are available for this server
$netRed = Get-OVNetwork "red"
$conRed1 = New-OVProfileConnection -id 1 -type Ethernet -requestedBW 1000 -network $netRed
$conRed2 = New-OVProfileConnection -id 2 -type Ethernet -requestedBW 1000 -network $netRed

$netProdFCA = Get-OVNetwork "Production Fabric A"
$conFC1 = New-OVProfileConnection -id 3 -type FibreChannel -requestedBW 4000 -network $netProdFCA
$netProdFCB = Get-OVNetwork "Production Fabric B"
$conFC2 = New-OVProfileConnection -id 4 -type FibreChannel -requestedBW 4000 -network $netProdFCB

$netBlack = Get-OVNetwork "black"
$conBlack1 = New-OVProfileConnection -id 5 -type Ethernet -requestedBW 2000 -network $netBlack
$conBlack2 = New-OVProfileConnection -id 6 -type Ethernet -requestedBW 2000 -network $netBlack

$netSetProd = Get-OVNetworkSet "Production Networks"
$conSet1 = New-OVProfileConnection -id 7 -type Ethernet -requestedBW 3000 -network $netSetProd
$conSet2 = New-OVProfileConnection -id 8 -type Ethernet -requestedBW 3000 -network $netSetProd

#Build array of connections for the profile
$conList = @($conRed1, $conRed2, $conBlack1, $conBlack2, $conSet1, $conSet2, $conFC1, $conFC2)

#Attach Volumes
$volume1 = Get-OVStorageVolume -Name Volume1 | Get-OVProfileAttachVolume -volumeid 1
$volume2 = Get-OVStorageVolume -Name SharedVolume1 | Get-OVProfileAttachVolume -volumeid 2
$attachVolumes = @($volume1,$volume2)

#Submit profile to the appliance
$task = New-OVProfile -name $profileName -server $server -connections $conList -SANStorage -HostOsType VMware -StorageVolume $attachVolumes -Async

#Monitor the profile async task progress
Write-Host $task.name $task.taskStatus
$task = $task | Wait-OVTaskComplete


# Change Connection ID 5 and 6 to "green" in the profile we just created
$profile = Send-OVRequest $task.associatedResource.resourceUri
Write-Host "Adding network to" $profile.name

#Validate the Server Power is off prior to modifying Connections (Requirement for 1.00 and 1.01)
if ($server.powerState -ne "Off") {
    Write-Host "Server" $server.name "is" $server.powerState ".  Powering it off..."
    $Server | Stop-OVServer -Confirm:$false
}

$netGreen = Get-OVNetwork "green"
$conGreen1 = New-OVProfileConnection -connectionId 5 -type Ethernet -network $netGreen
$conGreen2 = New-OVProfileConnection -connectionId 6 -type Ethernet -network $netGreen
$profile.connections = $profile.connections + $conGreen1 + $conGreen2
$task = Set-OVResource $profile
$task = Wait-OVTaskComplete -taskUri $task.uri

# Display the connections for our profile
$profile = Send-OVRequest $task.associatedResource.resourceUri
$profile.connections | Format-Table

# ADVANCED SERVER SETTINGS
# First view the capabilities of the server hardware for this profile
$serverType = Send-OVRequest $profile.serverHardwareTypeUri
Write-Host "Boot options for this server:" $serverType.bootCapabilities

# Set the boot order for the server
$profile.boot.order = @("PXE", "HardDisk", "USB", "CD", "Floppy", "FibreChannelHba")
$profile.boot.manageBoot = $true
Write-Host "Set boot order to" $profile.boot.order

#Set the BIOS setting to disable external USB ports
Write-Host "There are" $serverType.biosSettings.Count "possible BIOS settings for this server"
foreach ($setting in $serverType.biosSettings) {
    if ($setting.name.Contains("USB Control")) {
        foreach ($option in $setting.options) {
            if ($option.name.Contains("External")) {
                $profile.bios.manageBios = $true
                $profile.bios.overriddenSettings =
                    @(@{id=$setting.id;value=$option.id})
                Write-Host $setting.name ":" $option.name
                break
            }
        }
        break
        }
    }

# Let's update the profile with boot order and BIOS settings and validate the result
$task = Set-OVResource $profile
$task = Wait-OVTaskComplete -Task $task -timeout (New-TimeSpan -Minutes 20)
$profile = Send-OVRequest $task.associatedResource.resourceUri

# Now update the firmware of the profile.
# List available SPP's on the appliance
Get-OVBaseline

$sppFileName = Read-Host "Which SPP file do you want to select ('SPP*.iso'), or <Enter> to skip firmware"
if ($sppFileName) {
    $fw = Get-OVBaseline -FileName $sppFileName
    # Now select the firmware SPP in the server profile
    if ($serverType.firmwareUpdateSupported) {
        $profile.firmwareSettings.manageFirmware = $true
        $profile.firmwareSettings.firmwareBaselineUri = $fw.uri
        $task = Set-OVResource $profile
        $task = Wait-OVTaskComplete -taskUri $task.uri -timeout (New-TimeSpan -Minutes 30)

    } else {
        Write-Host "Firmware update not supported for" $serverType.model
    }
}