##############################################################################
# DefineNetworks_AA_VC_Sample.ps1
# - Example scripts for defining A/A networks to be deployed with HP OneView.
#
#   VERSION 1.2
#
# (C) Copyright 2014 Hewlett-Packard Development Company, L.P.
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
Get-HPOVNetwork -list
write-host
write-host "Existing Network Sets:"
write-host "---------------------------"
write-host
Get-HPOVNetworkSet -list
write-host

# Create some new network definitions:
$status = New-HPOVNetwork -type "Ethernet" -name "VLAN 10-A" -vlanId 10 -smartlink $true
$network10Uri = $status.Details.associatedResource.resourceUri
Write-host "VLAN 10-A URI: $network10Uri"

$status = New-HPOVNetwork -type "Ethernet" -name "VLAN 10-B" -vlanId 10 -smartlink $true
$network10Uri = $status.Details.associatedResource.resourceUri
Write-host "VLAN 10-B URI: $network10Uri"

#Create A-Side Networks
20,30,40,50,60 | % { New-HPOVNetwork -type "Ethernet" -name "VLAN $_-A" -vlanId $_ -smartlink $true }

#Create B-Side Networks
20,30,40,50,60 | % { New-HPOVNetwork -type "Ethernet" -name "VLAN $_-B" -vlanId $_ -smartlink $true }

# Now, create a "A-Side" Network Set, grouping 3 of these networks for convenience:
$network20A = Get-HPOVNetwork -name "VLAN 20-A" -type "Ethernet"
$network30A = Get-HPOVNetwork -name "VLAN 30-A" -type "Ethernet"
$network40A = Get-HPOVNetwork -name "VLAN 40-A" -type "Ethernet"
New-HPOVNetworkSet -name "Production Networks-A" -untaggedNetworkUri $network20A.uri -networkUris $network20A.uri,$network30A.uri,$network40A.uri

# Now, create a "B-Side" Network Set, grouping 3 of these networks for convenience:
$network20B = Get-HPOVNetwork -name "VLAN 20-B" -type "Ethernet"
$network30B = Get-HPOVNetwork -name "VLAN 30-B" -type "Ethernet"
$network40B = Get-HPOVNetwork -name "VLAN 40-B" -type "Ethernet"
New-HPOVNetworkSet -name "Production Networks-B" -untaggedNetworkUri $network20B.uri -networkUris $network20B.uri,$network30B.uri,$network40B.uri

# Create some FC networks:
New-HPOVNetwork -name "Production Fabric A" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-HPOVNetwork -name "Production Fabric B" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true
New-HPOVNetwork -name "DirectAttach Fabric A" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"
New-HPOVNetwork -name "DirectAttach Fabric B" -type FC -typicalBandwidth 4000 -autoLoginRedistribution $true -fabrictype "DirectAttach"

Get-HPOVNetwork -list


read-host "Press enter to continue"
