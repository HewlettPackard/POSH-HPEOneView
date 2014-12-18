##############################################################################
# Server_Sample.ps1
# - Example scripts to illustrate usage of server hardware and profile APIs
#
#   VERSION 1.0
#
# (C) Copyright 2014 Hewlett-Packard Development Company, L.P.
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

# First connect to the HP OneView appliance.
if (-not $global:cimgmtSessionId) { Connect-HPOVMgmt }

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
        break; 
        }
    }
if ($server.state -ne "NoProfileApplied") {
    Write-Host "No suitable server found."
    return;
    }

$profileName = "Profile-" + $server.serialNumber
Write-Host "Creating" $profileName "for server" $server.name

# Assume that networks "red" and "blue" are available for this server
$netRed = Get-HPOVNetwork "red"
$conRed = New-HPOVProfileConnection -id 1 -type Ethernet -network $netRed
$netBlue = Get-HPOVNetwork "blue"
$conBlue = New-HPOVProfileConnection -connectionId 2 -type Ethernet -network $netBlue
$conList = @($conRed, $conBlue)

$task = New-HPOVProfile -name $profileName -server $server -connections $conList
Write-Host $task.name $task.taskStatus
$task = Wait-HPOVTaskComplete -taskUri $task.uri

# Add a connection to "green" to the profile we just created
$profile = Send-HPOVRequest $task.associatedResource.resourceUri
Write-Host "Adding network to" $profile.name

$netGreen = Get-HPOVNetwork "green"
$conGreen = New-HPOVProfileConnection -connectionId 3 -type Ethernet -network $netGreen
$profile.connections = $profile.connections + $conGreen
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
Get-HPOVSppFile | sort-object baselineShortName | format-table -property name,baselineShortName,version -autosize

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