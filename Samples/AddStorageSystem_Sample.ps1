##############################################################################
# AddStorageSystem_Sample.ps1
# - Example script for adding a supported Storage System, creating Storage Pools
#   and Storage Volumes
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

if (-not (get-module HPEOneView.530))
{

    Import-Module HPEOneView.530

}

if (-not $ConnectedSessions)
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-OVMgmt -Hostname $Appliance -Username $Username -Password $Password

}

#Connect a Storage System using OneView Expected Connectivity
$myStorageSystem      = "HP3Par_1-array.contoso.com"
$myStorageSystemAdmin = "3paradm"
$myStorageSystemPass  = "3pardata"


#Add Storage System specifying the Virtual Domain and Storage Host Ports
$params = @{

    hostname  = $myStorageSystem;
    username  = $myStorageSystemAdmin;
    password  = $myStorageSystemPass;
    domain    = "NODOMAIN"
    Ports = @{

        "0:1:1" = "3PAR SAN DA A";
        "0:1:2" = "3PAR SAN Fabric A";
        "1:1:1" = "3PAR SAN Fabric B";
        "1:1:2" = "3PAR SAN DA B"

    };
	PortGroups = @{

		"0:1:1" = "PG_1";
        "0:1:2" = "PG_2";
        "1:1:1" = "PG_1";
        "1:1:2" = "PG_2"

	}

}

"Importing POD storage array: {0}" -f $params.hostname | Write-Host

Try
{

	Add-OVStorageSystem @params | Wait-OVTaskComplete

	Add-OVStoragePool HP-P7400-1 -poolName R1_FC_CPG | Wait-OVTaskComplete

}

Catch
{

	$PSCMdlet.ThrowTerminatingError($_)

}

#Add a second Storage System specifying the Virtual Domain and Storage Host Ports
$myStorageSystem       = "HP3Par_2-array.contoso.com"
$myStorageSystemAdmin  = "3paradm"
$myStorageSystemPass   = "3pardata"
$myStorageSystemDomain = "VirtualDomain1" #NOTE: The value is case sensitive.
$myStorageSystemPorts  = @{

	"1:1:1" = "Fabric A";
	"2:1:1" = "FabricA";
	"1:1:2" = "Fabric B";
	"2:1:2" = "Fabric B"
}

$myStorageSystemPG     = @{

	"0:1:1" = "PG_1";
    "0:1:2" = "PG_2";
    "1:1:1" = "PG_1";
    "1:1:2" = "PG_2"

}

$params = @{

    hostname   = $myStorageSystem;
    username   = $myStorageSystemAdmin;
    password   = $myStorageSystemPass;
    domain     = $myStorageSystemDomain;
    Ports      = $myStorageSystemPorts;
	PortGroups = $myStorageSystemPG

}

"Importing POD storage array: {0}" -f $params.hostname | Write-Host

Try
{

	Add-OVStorageSystem @params | Wait-OVTaskComplete

	Add-OVStoragePool -StorageSystem $myStorageSystem -PoolName R1_FC_CPG | Wait-OVTaskComplete

}

Catch
{

	$PSCMdlet.ThrowTerminatingError($_)

}

Get-OVStorageSystem

#Get Storage System Details
$myStorageSystem1 = Get-OVStorageSystem -Name HP3Par_1
$myStorageSystem2 = Get-OVStorageSystem -Name HP3Par_2


#Add Storage Pools in order to provision Storage Volumes
#HP3Par_1

Try
{

	$myStorageSystem1 | New-OVStoragePool -PoolName "FST_CPG1"
	$myStorageSystem1 | New-OVStoragePool -PoolName "FST_CPG2"

}

Catch
{

	Write-Error -ErrorRecord $_

}


#HP3Par_2

Try
{

	$myPools = @("FST_CPG3","FST_CPG4")
	$myStorageSystem2 | New-OVStoragePool -PoolName $myPools

}

Catch
{

	Write-Error -ErrorRecord $_

}

Get-OVStoragePool

$StroagePool1 = Get-OVStoragePool -Name FST_CPG1

#Create some volumes

Try
{

	1..10 | % { New-OVStorageVolume -name Vol$_ -Pool $StroagePool1 -Size 60 }

}

Catch
{

	Write-Error -ErrorRecord $_

}

Try
{

	1..5 | % { New-OVStorageVolume -name SharedVol$_ -StoragePool FST_CPG2 -Size 250 -shared }

}

Catch
{

	Write-Error -ErrorRecord $_

}

Get-OVStorageVolume