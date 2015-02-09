##############################################################################
# ValidateInterconnect_Sample.ps1
# - Example scripts for importing an enclosure to a specific EG.
#
#   VERSION 1.0
#
# (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
##############################################################
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

function AddGroupUri($lu, $luts) {
    # Add the corresponding Group object to the logical uplink object
    Add-Member -InputObject $lu -MemberType NoteProperty -Name UplinkSetGroup -Value $null -Force
    foreach ($lut in $luts) {
        if ($lut.UplinkSetName -eq $lu.name) {
            $lu.UplinkSetGroup = $lut
            break;
        }
    }
}

function GetUplinkSets ([PSCustomObject]$logInterconnect, $logInterconnectGroup) {
    $myLUs = @()
    foreach ($lu in $global:logUplinks) {
        if ($lu.logicalInterconnectUri -eq $logInterconnect.uri) {
            #Write-Host "Match on" $lu.logicalInterconnectUri
            AddGroupUri $lu $logInterconnectGroup.UplinkSetGroups
            $myLUs += $lu
        }
    }
    return $myLUs
}

function GetPortName ($bay, $portNumber) {
    # This function uses the Interconnect map Group set up in CompareInterconnects
    foreach ($entry in $script:swMapTempl) {
        if ($entry.bayNumber -eq $bay) {
            $InterconnectType = $script:InterconnectTypes | Where-Object {$_.uri -eq $entry.InterconnectTypeUri}
            foreach ($portInfo in $InterconnectType.portInfos) {
                if ($portInfo.portNumber -eq $portNumber) {
                    $portInfo.portName
                    return
                }
            }
            return
        }
    }
}

function CompareNetworks ($lu, $lut) {
    if ($lu.networkUris.Count -ne $lut.networkUris.Count) {
        Write-Host $lu.name "currently has" $lu.networkUris.Count "networks, Group has" $lut.networkUris.Count "networks" -ForegroundColor Red
    }

    $diff = Compare-Object -ReferenceObject $lu.networkUris -DifferenceObject $lut.networkUris
    foreach ($d in $diff) {
        $net = Send-HPOVRequest $d.InputObject
        if ($d.SideIndicator -eq "=>") {
            Write-Host $lu.name "is currently missing network" $net.name "VLAN" $net.vlanId -ForegroundColor Red
        } else {
            Write-Host $lu.name "currently has extra network" $net.name "VLAN" $net.vlanId -ForegroundColor Red
        }
    }
}

function ComparePorts ($lu, $lut) {
    if ($lu.portUris.Count -ne $lut.uplinkPorts.Count) {
        Write-Host $lu.name "currently has" $lu.portUris.Count "ports, Group has" $lut.uplinkPorts.Count -ForegroundColor Red
    }
    #Build array of LU ports
    $luPorts = @()
    foreach ($portUri in $lu.portUris) { $luPorts += Send-HPOVRequest $portUri}

    #Build array of LUT ports
    $lutPorts = @()
    foreach ($upPorts in $lut.uplinkPorts) {
        $lutPort = [PSCustomObject]@{bayNumber=$null; portNumber=$null; portName=[string]$null}
        $locEntries = $upPorts.locationEntries
        foreach ($loc in $locEntries) {
            if ($loc.type -eq "BAY") { $lutPort.bayNumber = $loc.relativeValue }
            if ($loc.type -eq "PORT") { $lutPort.portNumber = $loc.relativeValue }
        }
        $portName = GetPortName $lutPort.bayNumber $lutPort.portNumber
        $lutPort.portName = [string]$portName
        $lutPorts += $lutPort
    }

    $diff = Compare-Object -ReferenceObject $luPorts -DifferenceObject $lutPorts -Property bayNumber, portName
    foreach ($d in $diff) {
        if ($d.SideIndicator -eq "=>") {
            Write-Host $lu.name "is currently missing port bay" $d.bayNumber "port" $d.portName -ForegroundColor Red
        } else {
            Write-Host $lu.name "currently has extra port on bay" $d.bayNumber "port" $d.portName -ForegroundColor Red
        }
    }
}

function CompareUplinksWithGroup ($lu) {
    $lut = $lu.UplinkSetGroup
    if (!$lut) {
        Write-Host $lu.name "has no matching logical uplink Group" -ForegroundColor Red
        return
    }

    if ($lu.connectionMode -ne $lut.mode) {
        Write-Host $lu.name "current connectionMode" $lu.connectionMode "differs from Group mode" $lut.mode -ForegroundColor Red
    }
    if ($lu.networkType -ne $lut.networkType) {
        Write-Host $lu.name "current networkType" $lu.networkType "differs from Group networkType" $lut.networkType -ForegroundColor Red
    }
    if ($lu.nativeNetworkUri -ne $lut.nativeNetworkUri) {
        Write-Host $lu.name "current nativeNetworkUri" $lu.nativeNetworkUri "differs from Group nativeNetworkUri" $lut.nativeNetworkUri -ForegroundColor Red
    }

    CompareNetworks $lu $lut

    ComparePorts $lu $lut
}

function GetLocationEntry ($location, $type) {
    foreach ($entry in $location.locationEntries) {
        if ($entry.type -eq $type) { 
            if ($entry.value.GetType) { 
                return $entry.value
            } else { 
                return $entry.relativeValue 
            }
        }
    }
}

function CompareInterconnects ($logInterconnect, $logInterconnectGroup) {
    #Build array of Interconnects in Group
    $script:swMapTempl = @()
    foreach ($swMapEntryGroup in $logInterconnectGroup.InterconnectMapGroup.InterconnectMapEntryGroups) {
        if ($swMapEntryGroup.permittedInterconnectTypeUri) {
            $bay = GetLocationEntry $swMapEntryGroup.logicalLocation "BAY"
            $script:swMapTempl += [PSCustomObject]@{bayNumber=$bay; InterconnectTypeUri=$swMapEntryGroup.permittedInterconnectTypeUri}
        }
    }

    #Build array of Interconnects in logical Interconnect
    $swMap = @()
    foreach ($swMapEntry in $logInterconnect.InterconnectMap.InterconnectMapEntries) {
        if ($swMapEntry.permittedInterconnectTypeUri) {
            $bay = GetLocationEntry $swMapEntry.location "BAY"
            $swMap += [PSCustomObject]@{bayNumber=$bay; InterconnectTypeUri=$swMapEntry.permittedInterconnectTypeUri}
        }
    }

    $diff = Compare-Object -ReferenceObject $swMap -DifferenceObject $script:swMapTempl -Property bayNumber, InterconnectTypeUri -IncludeEqual
    foreach ($d in $diff) {
        $InterconnectType = $script:InterconnectTypes | Where-Object {$_.uri -eq $d.InterconnectTypeUri}
        if ($d.SideIndicator -eq "==") {
            Write-Host $logInterconnect.name "matches Group for Interconnect bay" $d.bayNumber "type" $InterconnectType.InterconnectModel -ForegroundColor Green
        } else {
            if ($d.SideIndicator -eq "=>") {
                Write-Host $logInterconnect.name "is currently missing Interconnect bay" $d.bayNumber "type" $InterconnectType.InterconnectModel -ForegroundColor Red
            } else {
                Write-Host $logInterconnect.name "currently has extra Interconnect in bay" $d.bayNumber "type" $InterconnectType.InterconnectModel -ForegroundColor Red
            }
        }
    }
}

##################################################################
# First connect to the HP OneView
if (!$global:myAppliance) {
    $global:myAppliance = Read-Host "HP OneView hostname or IP address"
    }
Connect-HPOVMgmt -appliance $global:myAppliance

#List all the enclsoures managed by this appliance
$encls = Get-HPOVEnclosure
Write-Host "The following enclosures are managed by this appliance:"
$encls | ft -AutoSize
Write-Host

#Ask user which enclosure to validate
do {
    $enclName = Read-Host "Enter the name of the enclosure you would like to validate"
    $encl = $encls | Where-Object {$_.name -eq $enclName} 
} while (!$encl -or $encl -isnot [PSCustomObject])
Write-Host

#Save list of all logical uplinks
$script:logUplinks = Get-HPOVUplinkSet

#Save list of all Interconnect types
$resp = Send-HPOVRequest /rest/Interconnect-types
$script:InterconnectTypes = $resp.members

#Find all the Interconnects and logical Interconnects used by this enclosure
$logInterconnectUris = @()
$script:Interconnects = @()
foreach ($icBay in $encl.interconnectBays) {
    if ($icBay.InterconnectUri) { $Interconnects += Send-HPOVRequest $icBay.InterconnectUri }
    if (!$logInterconnectUris -contains $icBay.logicalInterconnectUri) { $logInterconnectUris += $icBay.logicalInterconnectUri }
}

#Save list of all Interconnects in enclosure
$Interconnects = Get-HPOVInterconnect

Write-Host $encl.name "has" $encl.interconnectBayCount "interconnect bays which are configured as" $logInterconnectUris.Count "logical Interconnects"

foreach ($lsUri in $logInterconnectUris) {
    $logInterconnect = Send-HPOVRequest $lsuri
    $logInterconnectGroup = Send-HPOVRequest $logInterconnect.logicalInterconnectGroupUri

    Write-Host "Logical Interconnect" $logInterconnect.name "has" $logInterconnect.Interconnects.Count "Interconnects and is based on Group" $logInterconnectGroup.name

    CompareInterconnects $logInterconnect $logInterconnectGroup
    Write-Host

    $lus = GetUplinkSets $logInterconnect $logInterconnectGroup
    foreach ($lu in $lus) {
        CompareUplinksWithGroup $lu
        Write-Host
    }
    Write-Host
}

Disconnect-HPOVMgmt
