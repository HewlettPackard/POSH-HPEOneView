##############################################################################
# Server_Multiconnection_Sample.ps1
#
# Example script to demonstrate creating a Server Profile with the following:
#
# - Configure 2 NICs in paired with Red
# - Configure 2 NICs in paired with Black
# - Configure 2 NICs in paired with NetworkSet (Production Networks)
# - Configure 2 FC connections to the Production Fabric A and B            
# - Set requested bandwidth
#
#   VERSION 3.0
#
# (C) Copyright 2013-2019 Hewlett Packard Enterprise Development LP 
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
$servers

# Make sure all the servers are powered off
ForEach ($server in $servers) {
    if ($server.powerState -ne "Off") {
        Write-Host "Server" $server.name "is" $server.powerState ".  Powering it off..."
        $Server | Stop-HPOVServer -Confirm:$false
    }
}

# Now create a server profile for the first available server
$Server = Get-HPOVServer -NoProfile | Select -First 1

$profileName = "Profile-" + $server.serialNumber
Write-Host "Creating" $profileName "for server" $server.name

# Assume that networks "red" and "blue" are available for this server
$netRed = Get-HPOVNetwork "red"
$conRed1 = New-HPOVProfileConnection -id 1 -type Ethernet -requestedBW 1000 -network $netRed
$conRed2 = New-HPOVProfileConnection -id 2 -type Ethernet -requestedBW 1000 -network $netRed

$netProdFCA = Get-HPOVNetwork "Production Fabric A"
$conFC1 = New-HPOVProfileConnection -id 3 -type FibreChannel -requestedBW 4000 -network $netProdFCA
$netProdFCB = Get-HPOVNetwork "Production Fabric B"
$conFC2 = New-HPOVProfileConnection -id 4 -type FibreChannel -requestedBW 4000 -network $netProdFCB

$netBlack = Get-HPOVNetwork "black"
$conBlack1 = New-HPOVProfileConnection -id 5 -type Ethernet -requestedBW 2000 -network $netBlack
$conBlack2 = New-HPOVProfileConnection -id 6 -type Ethernet -requestedBW 2000 -network $netBlack

$netSetProd = Get-HPOVNetworkSet "Production Networks"
$conSet1 = New-HPOVProfileConnection -id 7 -type Ethernet -requestedBW 3000 -network $netSetProd
$conSet2 = New-HPOVProfileConnection -id 8 -type Ethernet -requestedBW 3000 -network $netSetProd

$conList = @($conRed1, $conRed2, $conBlack1, $conBlack2, $conSet1, $conSet2, $conFC1, $conFC2)
$task = New-HPOVProfile -name $profileName -server $server -connections $conList -Async
Write-Host $task.name $task.taskStatus
$task = $task | Wait-HPOVTaskComplete


# Change Connection ID 5 and 6 to "green" in the profile we just created
$profile = Send-HPOVRequest $task.associatedResource.resourceUri
Write-Host "Adding network to" $profile.name
    
#Validate the Server Power is off prior to modifying Connections (Requirement for 1.00 and 1.01)
if ($server.powerState -ne "Off") {
    Write-Host "Server" $server.name "is" $server.powerState ".  Powering it off..."
    $Server | Stop-HPOVServer -Confirm:$false
}

$netGreen = Get-HPOVNetwork "green"
$conGreen1 = New-HPOVProfileConnection -connectionId 5 -type Ethernet -network $netGreen
$conGreen2 = New-HPOVProfileConnection -connectionId 6 -type Ethernet -network $netGreen
$profile.connections = $profile.connections + $conGreen1 + $conGreen2
$task = Set-HPOVResource $profile
$task = Wait-HPOVTaskComplete -taskUri $task.uri

# Display the connections for our profile
$profile = Send-HPOVRequest $task.associatedResource.resourceUri
$profile.connections | Format-Table

# ADVANCED SERVER SETTINGS
# First view the capabilities of the server hardware for this profile
$serverType = Send-HPOVRequest $profile.serverHardwareTypeUri
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
$task = Set-HPOVResource $profile
$task = Wait-HPOVTaskComplete -taskUri $task.uri -timeout (New-TimeSpan -Minutes 20)
$profile = Send-HPOVRequest $task.associatedResource.resourceUri

# Now update the firmware of the profile.  
# List available SPP's on the appliance
Get-HPOVBaseline

$sppFileName = Read-Host "Which SPP file do you want to select ('SPP*.iso'), or <Enter> to skip firmware"
if ($sppFileName) {
    $fw = Get-HPOVBaseline -FileName $sppFileName
    # Now select the firmware SPP in the server profile
    if ($serverType.firmwareUpdateSupported) {
        $profile.firmwareSettings.manageFirmware = $true
        $profile.firmwareSettings.firmwareBaselineUri = $fw.uri
        $task = Set-HPOVResource $profile
        $task = Wait-HPOVTaskComplete -Task $task -timeout (New-TimeSpan -Minutes 30)

    } else {
        Write-Host "Firmware update not supported for" $serverType.model
    }
}