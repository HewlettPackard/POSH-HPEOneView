##############################################################################
# CreateEnclosureGroupSample.ps1
# - Example script for creating Enclosure Group, Logical Interconnect Group,
#   Logical Uplinks.
#
#   VERSION 2.0
#
# (C) Copyright 2013-2017 Hewlett Packard Enterprise Development LP 
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
if (-not($ConnectSessions))
{
	
	Connect-HPOVMgmt 

}

#Verify some Ethernet Networks exist
$networks = Get-HPOVNetwork -type Ethernet

if ($networks -eq $null) 
{

    write-host "There are no defined Ethernet Networks. Please create some.";

    break

}

#Create the Logical Interconnect Group
$LIGName = "LIG Prod" 
$Bays = @{1 = "FlexFabric";2 = "FlexFabric"}
$Dest1 = New-HPOVSnmpTrapDestination -Destination mysnmpserver.domain.local -Community MyR3adcommun1ty -SnmpFormat SNMPv1 -TrapSeverities critical,warning
$Dest2 = New-HPOVSnmpTrapDestination 10.44.120.9 MyR3adcommun1ty SNMPv1 critical,warning legacy 'Other','PortStatus','PortThresholds' 'Other','PortStatus'
$SnmpConfig = New-HPOVSnmpConfiguration -ReadCommunity MyR3adC0mmun1ty -AccessList '10.44.120.9/32','172.20.150/22' -TrapDestinations $Dest1,$Dest2

$NewLig = New-HPOVLogicalInterconnectGroup -name $LIGName -bays $bays -snmp $SnmpConfig | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup

#Create an Ethernet Uplink Set
$newUT = $NewLig | New-HPOVUplinkSet -usName "LUT1" -usType "Ethernet" -usNetworks "red","blue","green" -usNativeEthNetwork "red" -usUplinkPorts @("BAY1:X1","BAY2:X5") -usEthMode "Auto"
$newUT = $NewLig | New-HPOVUplinkSet -usName "Fabric A" -usType "FibreChannel" -usNetworks "Production Fabric A" -usUplinkPorts "BAY1:X1,BAY1:X2"
$newUT = $NewLig | New-HPOVUplinkSet -usName "Fabric B" -usType "FibreChannel" -usNetworks "Production Fabric B" -usUplinkPorts "BAY2:X1,BAY2:X2"

# Create an enclosure group with this LST
$enclGroup = New-HPOVEnclosureGroup -name "Prod VC FlexFabric Group 1" -logicalInterconnectGroup $NewLig
