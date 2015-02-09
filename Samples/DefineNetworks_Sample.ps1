##############################################################################
# DefineNetworks_Sample.ps1
# - Example scripts for defining networks to be deployed with HP OneView.
#
#   VERSION 1.2
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
$status = New-HPOVNetwork -type "Ethernet" -name "red" -vlanId 10 -smartlink $true
$network10Uri = $status.Details.associatedResource.resourceUri
Write-host "Red URI: $network10Uri"

New-HPOVNetwork -type "Ethernet" -name "blue" -vlanId 20 -smartlink $true
New-HPOVNetwork -type "Ethernet" -name "green" -vlanId 30 -smartlink $true
New-HPOVNetwork -type "Ethernet" -name "yellow" -vlanId 40 -smartlink $true
New-HPOVNetwork -type "Ethernet" -name "black" -vlanId 50 -smartlink $true

#Use the REST API to bulk create networks
New-HPOVNetwork -Name "NetSuffix" -vlanRange "100-120,123,135"

$network20 = Get-HPOVNetwork -name "blue" -type "Ethernet"
$network30 = Get-HPOVNetwork -name "green" -type "Ethernet"
$network40 = Get-HPOVNetwork -name "yellow" -type "Ethernet"

# Now, create a "network set", grouping 3 of these networks for convenience:
New-HPOVNetworkSet -name "Production Networks" -untaggedNetworkUri $network20.uri -networkUris $network20.uri,$network30.uri,$network40.uri

# Create some FC networks:
New-HPOVNetwork -name "Production Fabric A" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-HPOVNetwork -name "Production Fabric B" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-HPOVNetwork -name "DirectAttach Fabric A" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"
New-HPOVNetwork -name "DirectAttach Fabric B" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"

Get-HPOVNetwork -list


read-host "Press enter to continue"
