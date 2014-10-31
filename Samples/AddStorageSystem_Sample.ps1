##############################################################################
# AddStorageSystem_Sample.ps1
# - Example script for adding a supported Storage System, creating Storage Pools
#   and Storage Volumes
#
#   VERSION 1.1
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

#Connect a Storage System using OneView Expected Connectivity
$myStorageSystem = "HP3Par_1-array.contoso.com"
$myStorageSystemAdmin = "3paradm"
$myStorageSystemPass = "3pardata"

# Now import the enclosure using this new enclosure group
$task = New-HPOVStorageSystem -hostname $myStorageSystem -username $myStorageSystemAdmin -password $myStorageSystemPass
$myStorageSystem1 = Wait-HPOVTaskComplete $task.uri

#Add Storage System specifying the Virtual Domain and Storage Host Ports
$myStorageSystem = "HP3Par_2-array.contoso.com"
$myStorageSystemAdmin = "3paradm"
$myStorageSystemPass = "3pardata"
$myStorageSystemDomain = "VirtualDomain1" #NOTE: The value is case sensitive.
$myStorageSystemPorts = @{"1:1:1" = "Fabric A"; "2:1:1" = "FabricA"; "1:1:2" = "Fabric B"; "2:1:2" = "Fabric B"}

# Now import the enclosure using this new enclosure group
$task = New-HPOVStorageSystem -hostname $myStorageSystem -username $myStorageSystemAdmin -password $myStorageSystemPass -Domain $myStorageSystemDomain -Ports $myStorageSystemPorts
$myStorageSystem2 = Wait-HPOVTaskComplete $task.uri
Get-HPOVStorageSystem -List

#Get Storage System Details
$myStorageSystem1 = Get-HPOVStorageSystem HP3Par_1
$myStorageSystem2 = Get-HPOVStorageSystem HP3Par_2

#Add Storage Pools in order to provision Storage Volumes
#HP3Par_1
$myStorageSystem1 | New-HPOVStoragePool -poolName "FST_CPG1"
$myStorageSystem1 | New-HPOVStoragePool -poolName "FST_CPG2"
#HP3Par_2
$myPools = @("FST_CPG3","FST_CPG4")
$myStorageSystem2 | New-HPOVStoragePool -poolName $myPools
Get-HPOVStoragePool -List

#Create some volumes
1..10 | % { New-HPOVStorageVolume -name Vol$_ -PoolName FST_CPG1 -Size 60 }
1..5 | % { New-HPOVStorageVolume -name SharedVol$_ -PoolName FST_CPG2 -Size 250 -shared }
Get-HPOVStorageVolume -List