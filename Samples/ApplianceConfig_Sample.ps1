##############################################################################
# ApplianceConfig_Sample.ps1
# - Example scripts for configuring the HP OneView appliance (networking, NTP, 
#   etc.).
#
#   VERSION 2.1
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

[CmdletBinding()]
param(

        [Parameter(Position = 0, Mandatory = $True, HelpMessage = "Please provide the Appliances DHCP Address.")]
        [string]$vm_ipaddr,

		[Parameter(Position = 1, Mandatory = $True, HelpMessage = "Please provide the Appliances NEW Static IP Address.")]
        [String]$IPAddress
    )

$ErrorActionPreference = "Stop"

#region 

    $csrdir = "C:\Certs\Requests\"
    if (-not(Test-Path $csrdir)) { New-Item -Path $csrdir -ItemType directory | Out-Null }

    $template = "WebServer" # must always use concatenated name format
    $CA = "dc1.domain.local\domain-DC1-CA"

    if (-not (get-module HPOneview.120)) {
       Import-Module HPOneView.120
    }

    $global:hostname = "hpov.domain.local"

    # Accept the EULA
    if (Get-HPOVEulaStatus -appliance $vm_ipaddr) {

        Write-Host "Accepting EULA..."

        $ret = Set-HPOVEulaStatus -supportAccess "yes" -appliance $vm_ipaddr

    }


    # For initial setup, connect first using "default" Administrator credentials:
    Try { Connect-HPOVMgmt -appliance $vm_ipaddr -user "Administrator" -password "admin" }
    catch [HPOneView.Appliance.PasswordChangeRequired] {

        Write-Host "Set initial password"
        Set-HPOVInitialPassword -userName "Administrator" -oldPassword "admin" -newPassword "hpinvent"
    
    }

    Write-Host "Reconnect with new password"
    Connect-HPOVMgmt -appliance $vm_ipaddr -user Administrator -password "hpinvent"

    Write-Host "Set appliance networking configuration"

    $params = @{

        hostname        = $global:hostname ;
        ipv4Type        = "STATIC";
        ipv4Addr        = "$IPAddress";
        ipv4Subnet      = "255.255.0.0";
        ipv4Gateway     = "172.20.0.1";
        ipv6Type        = "UNCONFIGURE";
        ipv6Addr        = "";
        ipv6Subnet      = "";
        ipv6Gateway     = "";
        domainName      = "domain.local"; `
        searchDomains   = "domain.local";
        ipV4nameServers = "172.20.1.23","172.20.1.24";
        ipV6nameServers = @();
        ntpServers      = "172.20.1.23","172.20.1.24"

    }

    $task = Set-HPOVApplianceNetworkConfig @params #-import $global:fts_config
    Wait-HPOVTaskComplete $task

    if (-not($Global:cimgmtSessionId)) { Connect-HPOVMgmt -appliance $global:hostname -user Administrator -password "hpinvent" }

    Write-Host "Completed appliance networking configuration"

    #Process appliance certificate
    $CSR = @{
        
        Country         = "US";
        State           = "California";
        City            = "Palo Alto";
        Organization    = "Hewlett-Packard";
        CommonName      = "hpov.domain.local";
        AlternativeName = "hpov.domain.local,hpov,IPAddress"
    
    }

    $request = New-HPOVApplianceCsr @CSR

    $baseName = "hpov"
    $csrFileName = "hpov.csr"
    $cerFileName = "hpov.cer"

    Set-Content -path (Join-Path $csrdir -ChildPath $csrFileName) -value $request.base64Data -Force

    $csr = Get-ChildItem $csrdir | ? { $_.name -eq $csrFileName}

    $parameters = "-config $CA -submit -attrib CertificateTemplate:$template $csrdir$baseName.csr $csrdir$baseName.cer $csrdir$basename.p7b"

    $request = [System.Diagnostics.Process]::Start( "certreq",$parameters )
    
    $request.WaitForExit()

    $Task = gc $csrdir$cerFileName | Install-HPOVApplianceCertificate | Wait-HPOVTaskComplete

    #Configuring appliance LDAP/AD Security
    $dc1 = New-HPOVLdapServer -Name dc1.domain.local -SSLPort 636 -Certificate C:\Certs\dc1.cer
    $dc2 = New-HPOVLdapServer -Name dc2.domain.local -SSLPort 636 -Certificate C:\Certs\dc2.cer

    $AuthParams = @{

        UserName = "UserAdmin@domain.local"
        password = convertto-securestring -asplaintext "HP1nvent" -force

    }

    New-HPOVLdapDirectory -name Domain1 -AD -rootdn 'dc=domain,dc=local' -SearchContext 'OU=Admins,OU=Corp' -servers $dc1,$dc2 @AuthParams
    New-HPOVLdapGroup -d Domain1 -GroupName "CI Manager Full Admins"    -Roles "Infrastructure administrator" @AuthParams
    New-HPOVLdapGroup -d Domain1 -GroupName "CI Manager Network Admins" -Roles "Network administrator"  @AuthParams
    New-HPOVLdapGroup -d Domain1 -GroupName "CI Manager Server Admins"  -Roles "Server administrator"  @AuthParams
    New-HPOVLdapGroup -d Domain1 -GroupName "CI Manager Storage Admins" -Roles "Storage administrator"  @AuthParams

    #Upload custom SPP Baseline
    Add-HPOVBaseline \\FileServer\shared\HP_Firmware\spp_2015.04.1-Custom.iso

#endregion 

#region 

    write-host "Adding OneView license."
    New-HPOVLicense 'ARTC A9MA H9PA 8HW3 V7V5 HWWB Y9JL KMPL 8Q2E 4CB9 DXAU 2CSM GHTG L762 6BF6 HFN9 KJVT D5KM EFVW DT5J LHTZ PXKC AK2P 3EW2 QKQU HURN TZZ7 9B5X 82Z5 WHEF GE4C LUE3 BKT8 WXDG NK6Y C4GA HZL4 XBE7 3VJ6 2MSU 4ZU9 9WGG CZU7 WE4X YN44 CH55 KZLG 2F4N A8RJ UKEC 3F9V JQY5 "423450022 HPOV-NFR1 HP_OneView_16_Seat_NFR HEUAJUUYTTG3"_3M9BK-DPHH2-LSGC5-NSRB3-7T3H2'
    
    # Create the new users
    New-HPOVUser Nat   -fullName "Nat Network Admin"  -password hpinvent -roles "Network administrator"
    New-HPOVUser Sarah -fullName "Sarah Server Admin" -password hpinvent -roles "Server administrator"
    New-HPOVUser Sandy -fullName "Sandy SAN Admin"    -password hpinvent -roles "Storage administrator"
    New-HPOVUser Rheid -fullName "Rheid Read-Only"	  -password hpinvent -roles "Read only"
    New-HPOVUser Bob   -fullName "Bob Backup"	      -password hpinvent -roles "Backup Administrator"
    New-HPOVUser admin -fullName "admin"              -password hpinvent -roles "Infrastructure Administrator"
    
    $params = @{

        hostname  = "bna.domain.local";
        type = "BNA";
        username = "Administrator";
    	password = "password";
        UseSsl = $True

    }
    
    write-host "Importing BNA SAN Manager"
    Add-HPOVSanManager @params | Wait-HPOVTaskComplete
    
    Write-Host "Creating network resources"
    
    # Management networks
    New-HPOVNetwork -name "VLAN 1-A" -type "Ethernet" -vlanId 1 -smartlink $true -purpose Management
    New-HPOVNetwork -name "VLAN 1-B" -type "Ethernet" -vlanId 1 -smartlink $true -purpose Management
    
    #VMMigration Network
    New-HPOVNetwork -name "VLAN 10-A" -type "Ethernet" -vlanId 10 -smartlink $true -purpose VMMigration
    New-HPOVNetwork -name "VLAN 10-B" -type "Ethernet" -vlanId 10 -smartlink $true -purpose VMMigration
    
    #VM Networks
    20,30,40,50,101,102,103,104,105 | % { New-HPOVNetwork -name "VLAN $_-A" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }
    20,30,40,50,101,102,103,104,105 | % { New-HPOVNetwork -name "VLAN $_-B" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }
    
    $ProdNetsA += (20,30,40,50 | % { Get-HPOVNetwork "VLAN $_-A" })
    $ProdNetsB += (20,30,40,50 | % { Get-HPOVNetwork "VLAN $_-B" })
    $DevNetsA += (101,102,103,104,105 | % { Get-HPOVNetwork "VLAN $_-A" })
    $DevNetsB += (101,102,103,104,105 | % { Get-HPOVNetwork "VLAN $_-B" })
    
    # Create the network sets
    New-HPOVNetworkSet -name "Production Networks A" -networks $ProdNetsA -untaggedNetwork $ProdNetsA[0] -typicalBandwidth 2500 -maximumBandwidth 10000
    New-HPOVNetworkSet -name "Production Networks B" -networks $ProdNetsB -untaggedNetwork $ProdNetsB[0] -typicalBandwidth 2500 -maximumBandwidth 10000
    New-HPOVNetworkSet -name "Test Networks A"       -networks $DevNetsA -untaggedNetwork $DevNetsA[0] -typicalBandwidth 2500 -maximumBandwidth 10000
    New-HPOVNetworkSet -name "Test Networks B"       -networks $DevNetsB -untaggedNetwork $DevNetsB[0] -typicalBandwidth 2500 -maximumBandwidth 10000
    
    # Create the FC networks:
    New-HPOVNetwork -name "3PAR SAN Fabric A" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -managedSan "Fabric_A"
    New-HPOVNetwork -name "3PAR SAN Fabric B" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -managedSan "Fabric_B"
    New-HPOVNetwork -name "3PAR SAN DA A" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -fabricType DirectAttach
    New-HPOVNetwork -name "3PAR SAN DA B" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -fabricType DirectAttach
    
    $lig = "Logical Interconnect Group 1"
    
    $task = New-HPOVLogicalInterconnectGroup -ligName $lig -bays @{1 = "FlexFabric";2 = "FlexFabric"}
    
    # Create an active/active network config
    $aNetworks = Get-HPOVNetwork *-A
    $bNetworks = Get-HPOVNetwork *-B
    New-HPOVUplinkSet -ligName $lig -Name "Uplink Set 1 A" -Type "Ethernet" -Networks $aNetworks -nativeEthNetwork "VLAN 1-A" -UplinkPorts "BAY1:X5","BAY1:X6" -EthMode "Auto" 
    New-HPOVUplinkSet -ligName $lig -Name "Uplink Set 1 B" -Type "Ethernet" -Networks $bNetworks -nativeEthNetwork "VLAN 1-B" -UplinkPorts "BAY2:X5","BAY2:X6" -EthMode "Auto" 
    
    # FC Uplink Sets
    New-HPOVUplinkSet -ligName $lig -Name "3PAR SAN DA A" -Type "FibreChannel" -Networks "3PAR SAN Fabric A" -UplinkPorts "BAY1:X1"
    New-HPOVUplinkSet -ligName $lig -Name "3PAR SAN DA B" -Type "FibreChannel" -Networks "3PAR SAN Fabric B" -UplinkPorts "BAY2:X1"
    New-HPOVUplinkSet -ligName $lig -Name "3PAR SAN Fabric A" -Type "FibreChannel" -Networks "3PAR SAN DA A" -UplinkPorts "BAY1:X2"
    New-HPOVUplinkSet -ligName $lig -Name "3PAR SAN Fabric B" -Type "FibreChannel" -Networks "3PAR SAN DA B" -UplinkPorts "BAY2:X2"
    
    $mylig = Get-HPOVLogicalInterconnectGroup -name $lig
    New-HPOVEnclosureGroup -name "Enclosure Group 1" -logicalInterConnectGroup $mylig.uri -interconnectBayMappingCount 8 -stackingMode "Enclosure"
    
    Write-host "Sleeping 90sec"
    start-sleep -Seconds 90

    $params = @{
    
        username  = "3paradm";
        password  = "3pardata";
        hostname  = "3par-array.domain.local";
        domain    = "NODOMAIN"

        #myArrayPorts = @{
        #
        #    "0:1:1" = "3PAR SAN DA A"; 
        #    "0:1:2" = "3PAR SAN Fabric A"; 
        #    "1:1:1" = "3PAR SAN Fabric B"; 
        #    "1:1:2" = "3PAR SAN DA B"
        #
        #}
    
    }
    
    Write-Host "Importing POD storage array: $($params.hostname)"
    New-HPOVStorageSystem @params | Wait-HPOVTaskComplete
    Add-HPOVStoragePool HP-P7400-1 -poolName R1_FC_CPG | Wait-HPOVTaskComplete

    $sht= '{
    "type":  "server-hardware-type-3",
    "category":  "server-hardware-types",
    "name":  "BL460c Gen8 1",
    "description":  null,
    "model":  "ProLiant BL460c Gen8",
    "formFactor":  "HalfHeight",
    "pxeBootPolicies":  [
                            "IPv4"
                        ],
    "bootModes":  [
                      "BIOS"
                  ],
    "storageCapabilities":  [
                                "RAID0",
                                "RAID1"
                            ],
    "adapters":  [
                     {
                         "model":  "HP FlexFabric 10Gb 2-port 554FLB Adapter",
                         "oaSlotNumber":  9,
                         "ports":  [
                                       {
                                           "mapping":  1,
                                           "maxSpeedMbps":  10000,
                                           "physicalFunctionCount":  4,
                                           "type":  "Ethernet",
                                           "number":  1
                                       },
                                       {
                                           "mapping":  2,
                                           "maxSpeedMbps":  10000,
                                           "physicalFunctionCount":  4,
                                           "type":  "Ethernet",
                                           "number":  2
                                       }
                                   ],
                         "capabilities":  [
                                              "PXE",
                                              "Ethernet",
                                              "FibreChannel"
                                          ],
                         "location":  "Flb",
                         "slot":  1
                     }
                 ],
    "bootCapabilities":  [
                             "CD",
                             "Floppy",
                             "USB",
                             "HardDisk",
                             "FibreChannelHba",
                             "PXE"
                         ],
    "capabilities":  [
                         "ManageBIOS",
                         "VirtualUUID",
                         "ManageLocalStorage",
                         "VirtualWWN",
                         "ManageBootOrder",
                         "VCConnections",
                         "VirtualMAC",
                         "FirmwareUpdate"
                     ]
}'

    Send-HPOVRequest /rest/server-hardware-types POST ($sht | ConvertFrom-Json)

    New-HPOVStorageVolume -volumeName "POD$id ESXi Cluster Shared VMFS 1" -StorageSystem "HP-P7400-1" -StoragePool R1_FC_CPG -capacity 500 -shared | Wait-HPOVTaskComplete

    #Create Server Profiles
    $con1 = New-HPOVProfileConnection -id 1 -type Ethernet -requestedBW 1000 -network "VLAN 1-A" -bootable -priority Primary
    $con2 = New-HPOVProfileConnection -id 2 -type Ethernet -requestedBW 1000 -network "VLAN 1-B" -bootable -priority Secondary

    $conFC1 = New-HPOVProfileConnection -id 3 -type FibreChannel -requestedBW 4000 -network "3PAR SAN Fabric A"
    $conFC2 = New-HPOVProfileConnection -id 4 -type FibreChannel -requestedBW 4000 -network "3PAR SAN Fabric B"

    $con5 = New-HPOVProfileConnection -id 5 -type Ethernet -requestedBW 2000 -network "VLAN 10-A"
    $con6 = New-HPOVProfileConnection -id 6 -type Ethernet -requestedBW 2000 -network "VLAN 10-A"

    $con7 = New-HPOVProfileConnection -id 7 -type Ethernet -requestedBW 3000 -network "Production Networks A"
    $con8 = New-HPOVProfileConnection -id 8 -type Ethernet -requestedBW 3000 -network "Production Networks B"

    #Attach Volumes
    $volume1 = Get-HPOVStorageVolume "POD$id ESXi Cluster Shared VMFS 1" | New-HPOVProfileAttachVolume -volumeid 1

    #Submit profile to the appliance
    $params = @{

        name               = "vSphere 5 Compute Node Template"
        description        = "vSphere 5 Compute Node"
        server             = "Unassigned"  
        serverHardwareType = "BL460c Gen8 1" 
        enclosureGroup     = "HOL Enclosure Group" 
        connections        = $con1, $con2, $conFC1, $conFC2, $con5, $con6, $con7, $con8
        localStorage       = $true
        initialize         = $true
        RaidLevel          = "RAID1"
        Bootable           = $true
        SANStorage         = $True
        HostOStype         = "VMware"
        StorageVolume      = $volume1 
        hideUnusedFlexNics = $True
        manageBoot         = $True
        bootOrder          = ’PXE’,‘CD’,’Floppy’,’USB’,’HardDisk’
        bios               = $True
        biosSettings       = @(@{id=210;value=3},@{id=140;value=3},@{id=208;value=2},@{id=204;value=4},@{id=247;value=3},@{id=308;value=3},@{id=293;value=1})

    }

    New-HPOVProfile @Params | Wait-HPOVTaskComplete

    Disconnect-HPOVMgmt

#endregion