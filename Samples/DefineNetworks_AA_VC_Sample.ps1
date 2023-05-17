##############################################################################
# DefineNetworks_AA_VC_Sample.ps1
# - Example scripts for defining A/A networks to be deployed with HP OneView.
#
#   VERSION 3.0
#
# (C) Copyright 2013-2023 Hewlett Packard Enterprise Development LP
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

# List any existing networks and network sets
write-host "Existing Networks:"
write-host "---------------------------"
write-host
Get-OVNetwork
write-host
write-host "Existing Network Sets:"
write-host "---------------------------"
write-host
Get-OVNetworkSet
write-host

# Create some new network definitions:
$status = New-OVNetwork -Type "Ethernet" -Name "VLAN 10" -VlanId 10 -Smartlink $true
Get-OVNetwork -Name "VLAN 10" -Type Ethernet

# Create additional Networks
20,30,40,50,60 | % { New-OVNetwork -Type "Ethernet" -Name "VLAN $_" -VlanId $_ -Smartlink $true }

# Create Network Set, grouping 3 of these networks for convenience:
$network20 = Get-OVNetwork -Name "VLAN 20" -Type "Ethernet"
$network30 = Get-OVNetwork -Name "VLAN 30" -Type "Ethernet"
$network40 = Get-OVNetwork -Name "VLAN 40" -Type "Ethernet"
New-OVNetworkSet -Name "Production Networks" -UntaggedNetwork $network20 -Networks $network20, $network30, $network40

Get-OVNetworkSet -Name "Production Networks"

# Create some FC networks:
New-OVNetwork -Name "Production Fabric A" -Type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-OVNetwork -Name "Production Fabric B" -Type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-OVNetwork -Name "DirectAttach Fabric A" -Type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"
New-OVNetwork -Name "DirectAttach Fabric B" -Type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"

Get-OVNetwork