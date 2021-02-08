##############################################################################
# DefineLogicalInterconnectGroup_AA_VC_Sample.ps1
# - Example script for creating Logical Interconnect Group with A/A VC Networking.
#
#   VERSION 3.0
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

$LIGName = "My AA Prod"
$Bays = @{1 = "FlexFabric";2 = "FlexFabric"}
$SNMP = @{readCommunity = "MyTr@p1"; enabled=$True; systemContact = "Network Admin"; snmpAccess = @("192.168.1.2/32","10.1.1.0/24");trapDestinations = @(@{trapDestination="myhost.local";communityString="MyTr@p2";trapFormat="SNMPv1";trapSeverities=@("Critical", "Major", "Minor", "Warning", "Normal", "Info", "Unknown");fcTrapCategories=@("PortStatus", "Other")})}

$NewLig = New-HPOVLogicalInterconnectGroup -Name $LIGName -bays $bays -snmp $snmp | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup

#Create an Ethernet Uplink Set
$ANetworks = Get-HPOVNetwork -Name 'Prod Vlan *-A' -Type Ethernet
$BNetworks = Get-HPOVNetwork -Name 'Prod Vlan *-B' -Type Ethernet
$FabricA = Get-HPOVNetwork -Name "Production Fabric A" -Type FibreChannel
$FabricB = Get-HPOVNetwork -Name "Production Fabric B" -Type FibreChannel
$newUT = $NewLig | New-HPOVUplinkSet -Name LUT1 -Type "Side A Uplink Set" -Networks $ANetworks -NativeEthNetwork $ANetworks[0] -UplinkPorts "BAY1:X4","BAY1:X5" -EthMode "Auto"
$NewLig = Get-HPOVLogicalInterconnectGroup -Name $LIGName
$newUT = $NewLig | New-HPOVUplinkSet -Name LUT1 -Type "Side B Uplink Set" -Networks $BNetworks -NativeEthNetwork $BNetworks[0] -UplinkPorts "BAY2:X4","BAY2:X5" -EthMode "Auto"
$NewLig = Get-HPOVLogicalInterconnectGroup -Name $LIGName
$newUT = $NewLig | New-HPOVUplinkSet -Name "Fabric A" -Type "FibreChannel" -Networks $FabricA -UplinkPorts "BAY1:X1,BAY1:X2"
$NewLig = Get-HPOVLogicalInterconnectGroup -Name $LIGName
$newUT = $NewLig | New-HPOVUplinkSet -Name "Fabric B" -Type "FibreChannel" -Networks $FabricB -UplinkPorts "BAY2:X1,BAY2:X2"
