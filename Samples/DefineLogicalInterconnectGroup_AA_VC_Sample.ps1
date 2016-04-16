##############################################################################
# DefineLogicalInterconnectGroup_AA_VC_Sample.ps1
# - Example script for creating Logical Interconnect Group with A/A VC Networking.
#
#   VERSION 2.0
#
# (C) Copyright 2013-2016 Hewlett Packard Enterprise Development LP 
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
$Dest1 = New-HPOVSnmpTrapDestination -Destination mysnmpserver.domain.local -Community MyR3adcommun1ty -SnmpFormat SNMPv1 -TrapSeverities critical,warning
$Dest2 = New-HPOVSnmpTrapDestination 10.44.120.9 MyR3adcommun1ty SNMPv1 critical,warning legacy 'Other','PortStatus','PortThresholds' 'Other','PortStatus'
$SnmpConfig = New-HPOVSnmpConfiguration -ReadCommunity MyR3adC0mmun1ty -AccessList '10.44.120.9/32','172.20.150/22' -TrapDestinations $Dest1,$Dest2

$CreatedLig = New-HPOVLogicalInterconnectGroup -name $LIGName -bays $bays -snmp $SnmpConfig | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup

Write-Host "New LIG Object: " $CreatedLig

# Create an active/active network config
$aNetworks = Get-HPOVNetwork *-A
$bNetworks = Get-HPOVNetwork *-B
$FabricA   = Get-HPOVNetwork -name "3PAR SAN Fabric A"
$FabricB   = Get-HPOVNetwork -name "3PAR SAN Fabric B"
$DAFabricA = Get-HPOVNetwork -name "3PAR SAN DA A"    
$DAFabricB = Get-HPOVNetwork -name "3PAR SAN DA B"  

# Create Ethernet Uplink Sets
$CreatedLig = $CreatedLig | New-HPOVUplinkSet -Name "Uplink Set 1 A" -Type "Ethernet" -Networks $aNetworks -nativeEthNetwork "VLAN 1-A" -UplinkPorts "BAY1:X5","BAY1:X6" -EthMode "Auto" | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup
$CreatedLig = $CreatedLig | New-HPOVUplinkSet -Name "Uplink Set 1 B" -Type "Ethernet" -Networks $bNetworks -nativeEthNetwork "VLAN 1-B" -UplinkPorts "BAY2:X5","BAY2:X6" -EthMode "Auto" | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup
    
# FC Uplink Sets
$CreatedLig = $CreatedLig | New-HPOVUplinkSet -Name "3PAR SAN Fabric A" -Type "FibreChannel" -Networks $FabricA   -UplinkPorts "BAY1:X2" | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup
$CreatedLig = $CreatedLig | New-HPOVUplinkSet -Name "3PAR SAN Fabric B" -Type "FibreChannel" -Networks $FabricB   -UplinkPorts "BAY2:X2" | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup
$CreatedLig = $CreatedLig | New-HPOVUplinkSet -Name "3PAR SAN DA A"     -Type "FibreChannel" -Networks $DAFabricA -UplinkPorts "BAY1:X1" | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup
$CreatedLig = $CreatedLig | New-HPOVUplinkSet -Name "3PAR SAN DA B"     -Type "FibreChannel" -Networks $DAFabricB -UplinkPorts "BAY2:X1" | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup