##############################################################################
# DefineLogicalInterconnectGroup_Sample.ps1
# - Example script for creating Logical Interconnect Groups.
#
#   VERSION 1.1
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
Import-Module HPOneView.110

# First connect to the HP OneView appliance.
if (-not $global:cimgmtSessionId) { Connect-HPOVMgmt }

$LIGName = "MyLIG" 
$Bays = @{1 = "FlexFabric";2 = "FlexFabric"}
$SNMP = @{readCommunity = "MyTr@p1"; enabled=$True; systemContact = "Network Admin"; snmpAccess = @("192.168.1.2/32","10.1.1.0/24");trapDestinations = @(@{trapDestination="myhost.local";communityString="MyTr@p2";trapFormat="SNMPv1";trapSeverities=@("Critical", "Major", "Minor", "Warning", "Normal", "Info", "Unknown");fcTrapCategories=@("PortStatus", "Other")})}

$task = new-HPOVlogicalinterconnectgroup -name $LIGName -bays $bays -snmp $snmp
$task = Wait-HPOVTaskComplete $task.uri -timeout (New-TimeSpan -Minutes 10)
$newLigUri = $task.associatedResource.resourceUri

Write-Host "New LIG URI: " $newLigUri

#Create Ethernet Uplink Sets on this LIG
$newUT = New-HPOVUplinkSet -ligName $LIGName -usName "LUT1" -usType "Ethernet" -usNetworks "red","blue","green" -usNativeEthNetwork "red" -usUplinkPorts "BAY1:X5","BAY2:X5" -usEthMode "Auto"
$newUT = New-HPOVUplinkSet -ligName $LIGName -usName "Fabric A" -usType "FibreChannel" -usNetworks "Production Fabric A" -usUplinkPorts "BAY1:X1","BAY1:X2"
$newUT = New-HPOVUplinkSet -ligName $LIGName -usName "Fabric B" -usType "FibreChannel" -usNetworks "Production Fabric B" -usUplinkPorts "BAY2:X1","BAY2:X2"
