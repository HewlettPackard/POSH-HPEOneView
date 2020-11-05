##############################################################################
# DefineNetworks_Sample.ps1
# - Example scripts for defining networks to be deployed with HP OneView.
#
#   VERSION 3.0
#
# (C) Copyright 2013-2020 Hewlett Packard Enterprise Development LP
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
if (-not (get-module HPEOneView.540))
{

    Import-Module HPEOneView.540

}

if (-not $ConnectedSessions)
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-OVMgmt -Hostname $Appliance -Username $Username -Password $Password

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
$status = New-OVNetwork -type "Ethernet" -name "red" -vlanId 10 -smartlink $true
$network10Uri = $status.Details.associatedResource.resourceUri
Write-host "Red URI: $network10Uri"

New-OVNetwork -type "Ethernet" -name "blue" -vlanId 20 -smartlink $true
New-OVNetwork -type "Ethernet" -name "green" -vlanId 30 -smartlink $true
New-OVNetwork -type "Ethernet" -name "yellow" -vlanId 40 -smartlink $true
New-OVNetwork -type "Ethernet" -name "black" -vlanId 50 -smartlink $true

#Use the REST API to bulk create networks
New-OVNetwork -Name "NetSuffix" -vlanRange "100-120,123,135"

$network20 = Get-OVNetwork -name "blue" -type "Ethernet"
$network30 = Get-OVNetwork -name "green" -type "Ethernet"
$network40 = Get-OVNetwork -name "yellow" -type "Ethernet"

# Now, create a "network set", grouping 3 of these networks for convenience:
New-OVNetworkSet -name "Production Networks" -UntaggedNetwork $network20 -Networks $network20,$network30,$network40

# Create some FC networks:
New-OVNetwork -name "Production Fabric A" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-OVNetwork -name "Production Fabric B" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-OVNetwork -name "DirectAttach Fabric A" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"
New-OVNetwork -name "DirectAttach Fabric B" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"

Get-OVNetwork