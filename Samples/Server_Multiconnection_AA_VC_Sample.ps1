##############################################################################
# Server_Multiconnection_Sample.ps1
#
# Example script to demonstrate creating a Server Profile with the following:
#
# - Configure 2 NICs in paired with VLAN 10-A and VLAN 10-B
# - Configure 2 NICs in paired with VLAN 60-A and VLAN 60-B
# - Configure 2 NICs in paired with Production Networks-A and Production Networks-B Network Sets (Production Networks)
# - Configure 2 FC connections to the Production Fabric A and B            
# - Set requested bandwidth
# - Configures HP Power Profile to Max Performance, and sets other BIOS Dependancies
#
#   VERSION 1.0
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
AUTHORS OR COPYWRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
#>
##############################################################################
if (-not (get-module HPOneView.410)) 
{

    Import-Module HPOneView.410

}

if (-not $ConnectedSessions) 
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-HPOVMgmt -Hostname $Appliance -Username $Username -Password $Password

}

# Now view what enclosures have been imported
Write-Host "Here is the list of enclosures managed by this appliance"
Get-HPOVEnclosure

# Now list all the servers that have been imported with their current state
$servers = Get-HPOVServer
Write-Host "There are" $servers.Count "servers managed by this appliance."
$servers | Sort-Object name | format-table -Property name, powerState, state, serverProfileUri -AutoSize

# Make sure all the servers are powered off
ForEach ($server in $servers) {
    if ($server.powerState -ne "Off") {
        Write-Host "Server" $server.name "is" $server.powerState ".  Powering it off..."
        Set-HPOVServerPower -serverUri $server.uri -powerState "Off"
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
$netVlan10A = Get-HPOVNetwork "VLAN 10-A"
$netVlan10B = Get-HPOVNetwork "VLAN 10-B"
$conVlan10A = New-HPOVProfileConnection -id 1 -type Ethernet -requestedBW 1000 -network $netVlan10A
$conVlan10B = New-HPOVProfileConnection -id 2 -type Ethernet -requestedBW 1000 -network $netVlan10B

# Create Connection ID's 3 and 4
$netProdFCA = Get-HPOVNetwork "Production Fabric A"
$conFC1 = New-HPOVProfileConnection -id 3 -type FibreChannel -requestedBW 4000 -network $netProdFCA
$netProdFCB = Get-HPOVNetwork "Production Fabric B"
$conFC2 = New-HPOVProfileConnection -id 4 -type FibreChannel -requestedBW 4000 -network $netProdFCB

# Create Connection ID's 5 and 6
$netVlan60A = Get-HPOVNetwork "VLAN 60-A"
$netVlan60B = Get-HPOVNetwork "VLAN 60-B"
$conVlan60A = New-HPOVProfileConnection -id 5 -type Ethernet -requestedBW 2000 -network $netVlan60A
$conVlan60B = New-HPOVProfileConnection -id 6 -type Ethernet -requestedBW 2000 -network $netVlan60B

# Create Connection ID's 7 and 8
$netSetProdA = Get-HPOVNetworkSet "Production Networks-A"
$netSetProdB = Get-HPOVNetworkSet "Production Networks-B"
$conSetProdA = New-HPOVProfileConnection -id 7 -type Ethernet -requestedBW 3000 -network $netSetProdA
$conSetProdB = New-HPOVProfileConnection -id 8 -type Ethernet -requestedBW 3000 -network $netSetProdB

#Build the connection list
$conList = @($conVlan10A, $conVlan10B, $conVlan60A, $conVlan60B, $conSetProdA, $conSetProdB, $conFC1, $conFC2)

# ADVANCED SERVER SETTINGS
# First view the capabilities of the server hardware for this profile
$serverType = Send-HPOVRequest $server.serverHardwareTypeUri
Write-Host "Boot options for this server:" $serverType.bootCapabilities

# Set the boot order for the server
$profileBootOrder = @("PXE", "HardDisk", "USB", "CD", "Floppy", "FibreChannelHba")

# Configure some BIOS Settings (HP Power Profile, which will configure HP Power Regulator and other dependancies)
# Define an Array Collection
[System.Collections.ArrayList]$biosSettings = @()

#Search for HP Power Profile BIOS Setting
$powerProfile = $serverType.biosSettings | where { $_.name -match "HP Power Profile" }

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
New-HPOVProfile -name $profileName -server Unassigned -serverHardwareType $serverType -eg "Prod VC FlexFabric Group 1" -connections $conList -manageBoot -bootOrder $bootOrder -bios -biosSettings $biosSettings | Wait-HPOVTaskComplete

# Display the connections for our profile
Get-HPOVProfileConnectionList $profileName

# Now update the firmware of the profile.  
# List available SPP's on the appliance
Get-HPOVBaseline

$sppFileName = Read-Host "Which SPP file do you want to select ('SPP*.iso'), or <Enter> to skip firmware"
if ($sppFileName) {
    $fw = Get-HPOVSppFile $sppFileName
    # Now select the firmware SPP in the server profile
    if ($serverType.firmwareUpdateSupported) {
        $profile.firmwareSettings.manageFirmware = $true
        $profile.firmwareSettings.firmwareBaselineUri = $fw.uri
        $task = Set-HPOVResource $profile
        $task = Wait-HPOVTaskComplete -taskUri $task.uri -timeout (New-TimeSpan -Minutes 30)

    } else {
        Write-Host "Firmware update not supported for" $serverType.model
    }
}