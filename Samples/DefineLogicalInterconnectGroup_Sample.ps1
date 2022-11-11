##############################################################################
# DefineLogicalInterconnectGroup_Sample.ps1
# - Example script for creating Logical Interconnect Groups.
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
    $Credential = Get-Credential -UserName Administrator -Message Password

    $ApplianceConnection = Connect-OVMgmt -Hostname $Appliance -Credential $Credential

}

#Verify some Ethernet Networks exist
$networks = Get-OVNetwork -type Ethernet

if ($networks -eq $null)
{

    write-host "There are no defined Ethernet Networks. Please create some.";

    break

}

$LIGName = "LIG Prod"
$Bays = @{1 = "FlexFabric";2 = "FlexFabric"}
$SNMP = @{readCommunity = "MyTr@p1"; enabled=$True; systemContact = "Network Admin"; snmpAccess = @("192.168.1.2/32","10.1.1.0/24");trapDestinations = @(@{trapDestination="myhost.local";communityString="MyTr@p2";trapFormat="SNMPv1";trapSeverities=@("Critical", "Major", "Minor", "Warning", "Normal", "Info", "Unknown");fcTrapCategories=@("PortStatus", "Other")})}

$NewLig = New-OVLogicalInterconnectGroup -Name $LIGName -bays $bays -snmp $snmp | Wait-OVTaskComplete | Get-OVLogicalInterconnectGroup

#Create an Ethernet Uplink Set
$Networks = "red","blue","green" | Get-OVNetwork -Type Ethernet
$FabricA = Get-OVNetwork -Name "Production Fabric A" -Type FibreChannel
$FabricB = Get-OVNetwork -Name "Production Fabric B" -Type FibreChannel
$newUT = $NewLig | New-OVUplinkSet -Name LUT1 -Type "Ethernet" -Networks $Networks -NativeEthNetwork $Networks[0] -UplinkPorts "BAY1:X4","BAY1:X5","BAY2:X4","BAY2:X5" -EthMode "Auto"
$NewLig = Get-OVLogicalInterconnectGroup -Name $LIGName
$newUT = $NewLig | New-OVUplinkSet -Name "Fabric A" -Type "FibreChannel" -Networks $FabricA -UplinkPorts "BAY1:X1,BAY1:X2"
$NewLig = Get-OVLogicalInterconnectGroup -Name $LIGName
$newUT = $NewLig | New-OVUplinkSet -Name "Fabric B" -Type "FibreChannel" -Networks $FabricB -UplinkPorts "BAY2:X1,BAY2:X2"
