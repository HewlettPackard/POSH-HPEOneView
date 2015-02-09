##############################################################################
# Wipe_Appliance.ps1
# - Remove ALL resource from an appliance (useful to clean a system between demos).
#
#   VERSION 0.11
#
# (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
##############################################################################
# The information contained herein is subject to change without notice. 
# The only warranties for HP products and services are set forth in the 
# express warranty statements accompanying such products and services. 
# Nothing herein should be construed as constituting an additional warranty. 
# HP shall not be liable for technical or editorial errors or omissions 
# contained herein.
#
##############################################################################
Import-Module HPOneView.120

# First connect to the CI Management Appliance (if not already connected)
if (!$global:cimgmtSessionId) {
    $myAppliance = Read-Host "CI Management Appliance hostname or IP address"
    Connect-HPOVMgmt -appliance $myAppliance
}

############################################################
#  REMOVE CONFIGURATION (for cleanup after/between demos)  #
############################################################

# Delete ALL Profiles
$tasks = Get-HPOVProfile | Remove-HPOVProfile
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Remove ALL iPDUs
$tasks = Get-HPOVPowerDevice | Remove-HPOVPowerDevice
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Remove ALL Enclosures
$tasks = Get-HPOVEnclosure | Remove-HPOVEnclosure
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 10) }

# Remove ALL Rack Servers
$tasks = Get-HPOVServer | Remove-HPOVServer
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Delete ALL Enclosure Groups:
$tasks = Get-HPOVEnclosureGroup | Remove-HPOVEnclosureGroup
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Delete ALL Logical Interconnect Groups
$tasks = Get-HPOVLogicalInterconnectGroup | Remove-HPOVLogicalInterconnectGroup
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Delete ALL Network-Sets
$tasks = Get-HPOVNetworkSet | Remove-HPOVNetworkSet
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Delete ALL Networks
$tasks = Get-HPOVNetwork | Remove-HPOVNetwork
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }


# Delete ALL Storage Volumes
$tasks = Get-HPOVStorageVolume | Remove-HPOVStorageVolume
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Delete ALL Storage Pools
$tasks = Get-HPOVStoragePool | Remove-HPOVStoragePool
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Delete ALL Storage Systems
$tasks = Get-HPOVStorageSYstem | Remove-HPOVStorageSystem
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }

# Delete ALL Unmanaged Devices
$tasks = Get-HPOVUnmanagedDevice | Remove-HPOVUnmanagedDevice
if ($tasks) { if ($tasks -is [Array]) { $tasks = $tasks.Get($tasks.Count-1); }
    Wait-HPOVTaskComplete $tasks.uri -timeout (New-TimeSpan -Minutes 5) }


# Delete the SPP file uploaded, above:
# $task = Remove-HPOVResource -resource $firmwareResource
# if ($task) { Wait-HPOVTaskComplete $task.uri -timeout (New-TimeSpan -Minutes 5) }
