##############################################################################
# DefineNetworks_AA_VC_Sample.ps1
# - Example scripts for defining A/A networks to be deployed with HP OneView.
#
#   VERSION 3.0
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
if (-not (get-module HPOneview.300)) 
{

    Import-Module HPOneView.300

}

if (-not $ConnectedSessions) 
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-HPOVMgmt -Hostname $Appliance -Username $Username -Password $Password

}

# List any existing networks and network sets
write-host "Existing Networks:"
write-host "---------------------------"
write-host
Get-HPOVNetwork
write-host
write-host "Existing Network Sets:"
write-host "---------------------------"
write-host
Get-HPOVNetworkSet
write-host

# Create some new network definitions:
$status = New-HPOVNetwork -Type "Ethernet" -Name "VLAN 10-A" -VlanId 10 -smartlink $true
$status = New-HPOVNetwork -Type "Ethernet" -Name "VLAN 10-B" -VlanId 10 -smartlink $true
Get-HPOVNetwork -Name "VLAN 10-*" -Type Ethernet

#Create A-Side Networks
20,30,40,50,60 | % { New-HPOVNetwork -Type "Ethernet" -Name "VLAN $_-A" -VlanId $_ -smartlink $true }

#Create B-Side Networks
20,30,40,50,60 | % { New-HPOVNetwork -Type "Ethernet" -Name "VLAN $_-B" -VlanId $_ -smartlink $true }

# Now, create a "A-Side" Network Set, grouping 3 of these networks for convenience:
$network20A = Get-HPOVNetwork -Name "VLAN 20-A" -Type "Ethernet"
$network30A = Get-HPOVNetwork -Name "VLAN 30-A" -Type "Ethernet"
$network40A = Get-HPOVNetwork -Name "VLAN 40-A" -Type "Ethernet"
New-HPOVNetworkSet -Name "Production Networks-A" -UntaggedNetwork $network20A -Networks $network20A,$network30A,$network40A

# Now, create a "B-Side" Network Set, grouping 3 of these networks for convenience:
$network20B = Get-HPOVNetwork -Name "VLAN 20-B" -Type "Ethernet"
$network30B = Get-HPOVNetwork -Name "VLAN 30-B" -Type "Ethernet"
$network40B = Get-HPOVNetwork -Name "VLAN 40-B" -Type "Ethernet"
New-HPOVNetworkSet -Name "Production Networks-B" -UntaggedNetwork $network20B -Networks $network20B,$network30B,$network40B

# Create some FC networks:
New-HPOVNetwork -Name "Production Fabric A" -Type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-HPOVNetwork -Name "Production Fabric B" -Type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-HPOVNetwork -Name "DirectAttach Fabric A" -Type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"
New-HPOVNetwork -Name "DirectAttach Fabric B" -Type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"

Get-HPOVNetwork