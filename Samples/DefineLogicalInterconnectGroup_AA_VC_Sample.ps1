##############################################################################
# DefineLogicalInterconnectGroup_AA_VC_Sample.ps1
# - Example script for creating Logical Interconnect Group with A/A VC Networking.
#
#   VERSION 2.0
#
# (C) Copyright 2013-2015 Hewlett Packard Enterprise Development LP 
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
Import-Module HPOneView.200

# First connect to the HP OneView appliance.
if (-not ($global:ConnectionSessions)) { Connect-HPOVMgmt }

$LIGName = "My AA LIG" 
$Bays = @{1 = "FlexFabric";2 = "FlexFabric"}
$SNMP = @{readCommunity = "MyTr@p1"; enabled=$True; systemContact = "Network Admin"; snmpAccess = @("192.168.1.2/32","10.1.1.0/24");trapDestinations = @(@{trapDestination="myhost.local";communityString="MyTr@p2";trapFormat="SNMPv1";trapSeverities=@("Critical", "Major", "Minor", "Warning", "Normal", "Info", "Unknown");fcTrapCategories=@("PortStatus", "Other")})}

$task = New-HPOVLogicalInterconnectGroup -name $LIGName -bays $bays -snmp $snmp
$task = Wait-HPOVTaskComplete $task.uri -timeout (New-TimeSpan -Minutes 10)
$NewLigObject = Send-HPOVRequest $task.associatedResource.resourceUri

Write-Host "New LIG Object: " $NewLigObject

#Create Ethernet Uplink Sets on this LIG
$NewLigObject | New-HPOVUplinkSet -Name "Networks Side A" -Type "Ethernet" -Networks "VLAN 10-A","VLAN 20-A","VLAN 30-A" -NativeEthNetwork "VLAN 10-A" -UplinkPorts "BAY1:X5","BAY1:X6" -EthMode "Auto"
$NewLigObject | New-HPOVUplinkSet -Name "Networks Side B" -Type "Ethernet" -Networks "VLAN 10-B","VLAN 20-B","VLAN 30-B" -NativeEthNetwork "VLAN 10-B" -UplinkPorts "BAY2:X5","BAY2:X6" -EthMode "Auto"
$NewLigObject | New-HPOVUplinkSet -Name "Fabric A" -Type "FibreChannel" -Networks "Production Fabric A" -UplinkPorts "BAY1:X1","BAY1:X2"
$NewLigObject | New-HPOVUplinkSet -Name "Fabric B" -Type "FibreChannel" -Networks "Production Fabric B" -UplinkPorts "BAY2:X1","BAY2:X2"
