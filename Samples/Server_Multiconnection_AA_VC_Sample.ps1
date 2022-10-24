##############################################################################
# Server_Multiconnection_Sample.ps1
#
# Example script to demonstrate creating a Server Profile with the following:
#
# - Configure 2 NICs in paired with VLAN 10
# - Configure 2 NICs in paired with VLAN 60
# - Configure 2 NICs in paired with Production Networks Network Set (Production Networks)
# - Configure 2 FC connections to the Production Fabric A and B
# - Set requested bandwidth
# - Configures HPE Power Profile to Max Performance, and sets other BIOS Dependancies
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
Write-Host "There are" $servers.Count "servers managed by this appliance."
$servers | Sort-Object name | format-table -Property name, powerState, state, serverProfileUri -AutoSize

# Make sure all the servers are powered off
ForEach ($server in $servers) {
    if ($server.powerState -ne "Off") {
        Write-Host "Server" $server.name "is" $server.powerState ".  Powering it off..."
        Set-OVServerPower -serverUri $server.uri -powerState "Off"
    }
}

# Now create a server profile for the first available server
ForEach ($server in $servers) {
    if (($server.state -eq "NoProfileApplied") -and ($server.powerState -eq "Off")) {
        return;
    }
}

if ($server.state -ne "NoProfileApplied") {
    Write-Host "No suitable server found."
    break;
}

$profileName = "Profile-" + $server.serialNumber
Write-Host "Creating" $profileName "for server" $server.name

# Create Connection ID's 1 and 2
$netVlan10 = Get-OVNetwork "VLAN 10"
$conVlan10A = New-OVProfileConnection -id 1 -type Ethernet -requestedBW 1000 -network $netVlan10
$conVlan10B = New-OVProfileConnection -id 2 -type Ethernet -requestedBW 1000 -network $netVlan10

# Create Connection ID's 3 and 4
$netProdFCA = Get-OVNetwork "Production Fabric A"
$conFC1 = New-OVProfileConnection -id 3 -type FibreChannel -requestedBW 4000 -network $netProdFCA
$netProdFCB = Get-OVNetwork "Production Fabric B"
$conFC2 = New-OVProfileConnection -id 4 -type FibreChannel -requestedBW 4000 -network $netProdFCB

# Create Connection ID's 5 and 6
$netVlan60 = Get-OVNetwork "VLAN 60"
$conVlan60A = New-OVProfileConnection -id 5 -type Ethernet -requestedBW 2000 -network $netVlan60
$conVlan60B = New-OVProfileConnection -id 6 -type Ethernet -requestedBW 2000 -network $netVlan60

# Create Connection ID's 7 and 8
$netSetProd = Get-OVNetworkSet "Production Networks"
$conSetProdA = New-OVProfileConnection -id 7 -type Ethernet -requestedBW 3000 -network $netSetProd
$conSetProdB = New-OVProfileConnection -id 8 -type Ethernet -requestedBW 3000 -network $netSetProd

#Build the connection list
$conList = @($conVlan10A, $conVlan10B, $conVlan60A, $conVlan60B, $conSetProdA, $conSetProdB, $conFC1, $conFC2)

# ADVANCED SERVER SETTINGS
# First view the capabilities of the server hardware for this profile
$serverType = Send-OVRequest $server.serverHardwareTypeUri
Write-Host "Boot options for this server:" $serverType.bootCapabilities

# Set the boot order for the server
$profileBootOrder = @("PXE", "HardDisk", "USB", "CD", "Floppy", "FibreChannelHba")

# Configure some BIOS Settings (HP Power Profile, which will configure HP Power Regulator and other dependancies)
# Define an Array Collection
[System.Collections.ArrayList]$biosSettings = @()

#Search for HP Power Profile BIOS Setting
$powerProfile = $serverType.biosSettings | where { $_.name -match "HPE Power Profile" }

#Get Static High Performance Mode option ID
$maxPower = $powerProfile.options | where { $_.name -match "Maximum Performance" }

#Save the setting
[Void]$biosSettings.add(@{ id = $powerProfile.id ; value = $maxPower.id})

#Check to see if there are additional BIOS Options that should be modified.
#NOTE: Setting the HP Power Profile will modify the HP Power Regulator BIOS Setting.
if ($maxPower.optionLinks) {

    foreach ($option in $maxPower.optionLinks) {

        [Void]$biosSettings.add(@{ id = $option.settingId ; value = $option.optionId})

    }

}

#Create Profile
New-OVProfile -name $profileName -server Unassigned -serverHardwareType $serverType -eg "Prod VC FlexFabric Group 1" -connections $conList -manageBoot -bootOrder $bootOrder -bios -biosSettings $biosSettings | Wait-OVTaskComplete

# Display the connections for our profile
Get-OVProfileConnectionList $profileName

# Now update the firmware of the profile.
# List available SPP's on the appliance
Get-OVBaseline

$sppFileName = Read-Host "Which SPP file do you want to select ('SPP*.iso'), or <Enter> to skip firmware"
if ($sppFileName) {
    $fw = Get-OVSppFile $sppFileName
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