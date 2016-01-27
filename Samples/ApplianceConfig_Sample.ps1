##############################################################################
# ApplianceConfig_Sample.ps1
# - Example scripts for configuring the HP OneView appliance (networking, NTP, 
#   etc.).
#
#   VERSION 2.2
#
# (C) Copyright 2013-2016 Hewlett Packard Enterprise Development LP 
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
param
(

    [Parameter(Position = 0, Mandatory, HelpMessage = "Please provide the Appliances DHCP Address.")]
    [ValidateNotNullorEmpty()]
	[string]$vm_ipaddr,

	[Parameter(Position = 1, Mandatory, HelpMessage = "Please provide the Appliances NEW Hostname or FQDN.")]
	[String]$Hostname = "hpov.domain.local",

	[Parameter(Position = 2, Mandatory, HelpMessage = "Provide a [SecureString] object representing the new appliance Administrator password.")]
	[ValidateNotNullorEmpty()]
	[SecureString]$NewPassword,

	[Parameter(Position = 3, Mandatory, HelpMessage = "Please provide the Appliances NEW Static IP Address.")]
    [ValidateNotNullorEmpty()]
	[String]$IPv4Address,

	[Parameter(Position = 4, Mandatory, HelpMessage = "Please provide the Appliances NEW Static IP Address.")]
    [ValidateNotNullorEmpty()]
	[String]$IPv4SubnetMask,

	[Parameter(Position = 5, Mandatory, HelpMessage = "Please provide the Appliances NEW Static IP Address.")]
    [ValidateNotNullorEmpty()]
	[String]$IPv4Gateway,

	[Parameter(Position = 6, Mandatory, HelpMessage = "Please provide the Appliances NEW Static IP Address.")]
    [ValidateNotNullorEmpty()]
	[Array]$IPv4DnsServers,

	[Parameter(Position = 6, Mandatory, HelpMessage = "Please provide the Appliances NEW Static IP Address.")]
    [ValidateNotNullorEmpty()]
	[Array]$IPv4NtpServer

)

if (-not (get-module HPOneview.200)) 
{

    Import-Module HPOneView.200

}

#region 

	#Core Appliance Setup

    # Accept the EULA
    if (Get-HPOVEulaStatus -Appliance $vm_ipaddr) 
	{

        Write-Host "Accepting EULA..."

		Try
		{

			$ret = Set-HPOVEulaStatus -SupportAccess "yes" -Appliance $vm_ipaddr

		}

		Catch
		{


			$PSCMdlet.ThrowTerminatingError($_)
		}
        
    }

    # For initial setup, connect first using "default" Administrator credentials:
    Try 
	{ 
		
		Connect-HPOVMgmt -appliance $vm_ipaddr -user "Administrator" -password "admin"
	
	}

    catch [HPOneView.Appliance.PasswordChangeRequired] 
	{

        Write-Host "Set initial password"

		Try
		{

			Set-HPOVInitialPassword -UserName "Administrator" -OldPassword "admin" -NewPassword "hpinvent" -Appliance $vm_ipaddr

		}

		Catch
		{

			$PSCMdlet.ThrowTerminatingError($_)

		}

    
    }

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Write-Host "Reconnect with new password"

	Try
	{

		Connect-HPOVMgmt -appliance $vm_ipaddr -user Administrator -password "hpinvent"

	}
    
	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Write-Host "Set appliance networking configuration"

    $params = @{

        hostname        = $Hostname;
        ipv4Type        = "STATIC";
        ipv4Addr        = $IPv4Address;
        ipv4Subnet      = $IPv4SubnetMask;
        ipv4Gateway     = $IPv4Gateway;
        ipv6Type        = "UNCONFIGURE";
        ipv6Addr        = "";
        ipv6Subnet      = "";
        ipv6Gateway     = "";
        domainName      = "domain.local";
        searchDomains   = "domain.local";
        ipV4nameServers = $IPv4DnsServers;
        ipV6nameServers = @();
        ntpServers      = $IPv4NtpServer

    }

	Try
	{

		$task = Set-HPOVApplianceNetworkConfig @params -ApplianceConnection $vm_ipaddr | Wait-HPOVTaskComplete

	}
    
	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    if (-not($Global:ConnectedSessions | ? Name -EQ $Hostname)) 
	{ 
	
		Try
		{

			$ApplianceConnection = Connect-HPOVMgmt -appliance $Hostname -user Administrator -password "hpinvent" 

		}	
		
		Catch
		{

			$PSCMdlet.ThrowTerminatingError($_)

		}
	
	}

    Write-Host "Completed appliance networking configuration"

    $template = "WebServer" # must always use concatenated name format
    $CA       = "MyCA.domain.local\domain-MyCA-CA"  
	$csrdir   = "C:\Certs\Requests"

    if (-not(Test-Path $csrdir)) 
	{ 
		
		New-Item -Path $csrdir -ItemType directory | Out-Null 
	
	} 

    #Process appliance certificate
    $CSR = @{
        
        Country         = "US";
        State           = "California";
        City            = "Palo Alto";
        Organization    = "Hewlett-Packard";
        CommonName      = $Hostname;
        AlternativeName = "$Hostname,hpov,$IPv4Address"
    
    }

	Try
	{

		$request = New-HPOVApplianceCsr @CSR -ApplianceConnection $ApplianceConnection

	}
    
	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    $baseName = $Hostname
    $csrFileName = "$Hostname.csr"
    $cerFileName = "$Hostname.cer"

    Set-Content -path (Join-Path $csrdir -ChildPath $csrFileName) -value $request.base64Data -Force

    $csr = Get-ChildItem $csrdir | ? name -eq $csrFileName

    $parameters = "-config $CA -submit -attrib CertificateTemplate:$template $csrdir\$baseName.csr $csrdir\$baseName.cer $csrdir\$basename.p7b"

    $request = [System.Diagnostics.Process]::Start( "certreq",$parameters )
    
    $request.WaitForExit()

    $Task = gc $csrdir\$cerFileName | Install-HPOVApplianceCertificate -ApplianceConnection $ApplianceConnection | Wait-HPOVTaskComplete

    #Configuring appliance LDAP/AD Security
    $dc1 = New-HPOVLdapServer -Name dc1.domain.local
    $dc2 = New-HPOVLdapServer -Name dc2.domain.local

    $AuthParams = @{

        UserName = "UserAdmin@domain.local"
        password = convertto-securestring -asplaintext "HP1nvent" -force

    }

	Try
	{

		New-HPOVLdapDirectory -name Domain1 -AD -rootdn 'dc=domain,dc=local' -SearchContext 'OU=Admins,OU=Corp' -servers $dc1,$dc2 @AuthParams
		New-HPOVLdapGroup -d Domain1 -GroupName "CI Manager Full Admins"    -Roles "Infrastructure administrator" @AuthParams
		New-HPOVLdapGroup -d Domain1 -GroupName "CI Manager Network Admins" -Roles "Network administrator"  @AuthParams
		New-HPOVLdapGroup -d Domain1 -GroupName "CI Manager Server Admins"  -Roles "Server administrator"  @AuthParams
		New-HPOVLdapGroup -d Domain1 -GroupName "CI Manager Storage Admins" -Roles "Storage administrator"  @AuthParams

	}
    
	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

	Try
	{

		#Upload custom SPP Baseline
	    Add-HPOVBaseline \\FileServer\shared\HP_Firmware\spp_2015.04.1-Custom.iso

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Try
	{

		write-host "Adding OneView license."
		New-HPOVLicense 'ARTC A9MA H9PA 8HW3 V7V5 HWWB Y9JL KMPL 8Q2E 4CB9 DXAU 2CSM GHTG L762 6BF6 HFN9 KJVT D5KM EFVW DT5J LHTZ PXKC AK2P 3EW2 QKQU HURN TZZ7 9B5X 82Z5 WHEF GE4C LUE3 BKT8 WXDG NK6Y C4GA HZL4 XBE7 3VJ6 2MSU 4ZU9 9WGG CZU7 WE4X YN44 CH55 KZLG 2F4N A8RJ UKEC 3F9V JQY5 "423450022 HPOV-NFR1 HP_OneView_16_Seat_NFR HEUAJUUYTTG3"_3M9BK-DPHH2-LSGC5-NSRB3-7T3H2' -ApplianceConnection $ApplianceConnection

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}
    
	# Create the new users
    New-HPOVUser Nat   -fullName "Nat Network Admin"  -password hpinvent -roles "Network administrator"
    New-HPOVUser Sarah -fullName "Sarah Server Admin" -password hpinvent -roles "Server administrator"
    New-HPOVUser Sandy -fullName "Sandy SAN Admin"    -password hpinvent -roles "Storage administrator"
    New-HPOVUser Rheid -fullName "Rheid Read-Only"	  -password hpinvent -roles "Read only"
    New-HPOVUser Bob   -fullName "Bob Backup"	      -password hpinvent -roles "Backup Administrator"
    New-HPOVUser admin -fullName "admin"              -password hpinvent -roles "Infrastructure Administrator"

#endregion 

#region 

	#Resource Configuration    

    $params = @{

        hostname  = "bna.domain.local";
        type = "BNA";
        username = "Administrator";
    	password = "password";
        UseSsl = $True

    }
    
    write-host "Importing BNA SAN Manager"
	Try
	{

		Add-HPOVSanManager @params | Wait-HPOVTaskComplete

	}
    
	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}
    
    Write-Host "Creating network resources"
    
    # Management networks
	Try
	{

		New-HPOVNetwork -name "VLAN 1-A" -type "Ethernet" -vlanId 1 -smartlink $true -purpose Management
		New-HPOVNetwork -name "VLAN 1-B" -type "Ethernet" -vlanId 1 -smartlink $true -purpose Management
		# VMMigration Network
		New-HPOVNetwork -name "VMMigration Network" -type "Ethernet" -vlanId 10 -smartlink $true -purpose VMMigration
    
		# VM Networks
		20,30,40,50,101,102,103,104,105 | % { New-HPOVNetwork -name "VLAN $_-A" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }
		20,30,40,50,101,102,103,104,105 | % { New-HPOVNetwork -name "VLAN $_-B" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }
    
		$ProdNetsA = 20,30,40,50 | % { Get-HPOVNetwork "PROD VLAN $_-A" }
		$ProdNetsB = 20,30,40,50 | % { Get-HPOVNetwork "PROD VLAN $_-B" }
		$DevNetsA  = 101,102,103,104,105 | % { Get-HPOVNetwork "DEV VLAN $_-A" }
		$DevNetsB  = 101,102,103,104,105 | % { Get-HPOVNetwork "DEV VLAN $_-B" }
    
		# Create the network sets
		New-HPOVNetworkSet -name "Production Networks A" -networks $ProdNetsA -untaggedNetwork $ProdNetsA[0] -typicalBandwidth 2500 -maximumBandwidth 10000 -ApplianceConnection $ApplianceConnection
		New-HPOVNetworkSet -name "Production Networks B" -networks $ProdNetsB -untaggedNetwork $ProdNetsB[0] -typicalBandwidth 2500 -maximumBandwidth 10000 -ApplianceConnection $ApplianceConnection
		New-HPOVNetworkSet -name "Dev Networks A"       -networks $DevNetsA  -untaggedNetwork $DevNetsA[0]  -typicalBandwidth 2500 -maximumBandwidth 10000 -ApplianceConnection $ApplianceConnection
		New-HPOVNetworkSet -name "Dev Networks B"       -networks $DevNetsB  -untaggedNetwork $DevNetsB[0]  -typicalBandwidth 2500 -maximumBandwidth 10000 -ApplianceConnection $ApplianceConnection
    
		# Create the FC networks:
		New-HPOVNetwork -name "3PAR SAN Fabric A" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -managedSan "Fabric_A"
		New-HPOVNetwork -name "3PAR SAN Fabric B" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -managedSan "Fabric_B"
		New-HPOVNetwork -name "3PAR SAN DA A"     -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -fabricType DirectAttach
		New-HPOVNetwork -name "3PAR SAN DA B"     -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -fabricType DirectAttach

	}
    
    Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}   
    
	Try
	{

		$LigName = "VC FF Virt Prod"

		$CreatedLig = New-HPOVLogicalInterconnectGroup -Name $LigName -bays @{1 = "FlexFabric";2 = "FlexFabric"} -EnableIgmpSnooping $True -InternalNetworks 'VMMigration Network' | Wait-HPOVTaskComplete | Get-HPOVLogicalInterconnectGroup

		# Create an active/active network config
		$aNetworks = Get-HPOVNetwork *-A
		$bNetworks = Get-HPOVNetwork *-B

		# Get FC Network Objects
		$FabricA   = Get-HPOVNetwork -name "3PAR SAN Fabric A"
		$FabricB   = Get-HPOVNetwork -name "3PAR SAN Fabric B"
		$DAFabricA = Get-HPOVNetwork -name "3PAR SAN DA A"    
		$DAFabricB = Get-HPOVNetwork -name "3PAR SAN DA B"    

		# Create Ethernet Uplink Sets
		$CreatedLig | New-HPOVUplinkSet -Name "Uplink Set 1 A" -Type "Ethernet" -Networks $aNetworks -nativeEthNetwork "VLAN 1-A" -UplinkPorts "BAY1:X5","BAY1:X6" -EthMode "Auto" | Wait-HPOVTaskComplete
		$CreatedLig | New-HPOVUplinkSet -Name "Uplink Set 1 B" -Type "Ethernet" -Networks $bNetworks -nativeEthNetwork "VLAN 1-B" -UplinkPorts "BAY2:X5","BAY2:X6" -EthMode "Auto" | Wait-HPOVTaskComplete
    
		# FC Uplink Sets
		$CreatedLig | New-HPOVUplinkSet -Name "3PAR SAN Fabric A" -Type "FibreChannel" -Networks $FabricA   -UplinkPorts "BAY1:X2" | Wait-HPOVTaskComplete
		$CreatedLig | New-HPOVUplinkSet -Name "3PAR SAN Fabric B" -Type "FibreChannel" -Networks $FabricB   -UplinkPorts "BAY2:X2" | Wait-HPOVTaskComplete
		$CreatedLig | New-HPOVUplinkSet -Name "3PAR SAN DA A"     -Type "FibreChannel" -Networks $DAFabricA -UplinkPorts "BAY1:X1" | Wait-HPOVTaskComplete
		$CreatedLig | New-HPOVUplinkSet -Name "3PAR SAN DA B"     -Type "FibreChannel" -Networks $DAFabricB -UplinkPorts "BAY2:X1" | Wait-HPOVTaskComplete

	}

	Catch
	{

		$PSCMdlet.ParameterSetName

		$PSCMdlet.ThrowTerminatingError($_)

	}
	
	Try
	{

		$EGParams = @{

			Name                     = "Prod Enclosure Group 1"
			LogicalInterConnectGroup = $CreatedLig
			ConfigurationScript      = '#Configure Insight Remote Support CentralConnect
ENABLE REMOTE_SUPPORT IRS 80.80.1.14 7906'
			ApplianceConnection      = $ApplianceConnection

		}

		$eg = New-HPOVEnclosureGroup @EGParams

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}
    
    Write-host "Sleeping 90sec"
    start-sleep -Seconds 90

    $params = @{
    
        username  = "3paradm";
        password  = "3pardata";
        hostname  = "3par-array.domain.local";
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
    
    Write-Host "Importing POD storage array: $($params.hostname)"
	Try
	{

		Add-HPOVStorageSystem @params | Wait-HPOVTaskComplete

		Add-HPOVStoragePool HP-P7400-1 -poolName R1_FC_CPG | Wait-HPOVTaskComplete

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

	#Create a base Server Hardware Type    
	Try
	{

		$sht = '{
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

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}
    
	Write-Host "Creating vSphere Server Profile Template"

	Try
	{

		New-HPOVStorageVolume -volumeName "VMware Hypervisor Cluster Shared Disk 1" -StorageSystem "HP-P7400-1" -StoragePool R1_FC_CPG -capacity 500 -shared | Wait-HPOVTaskComplete

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
		$VMwareSharedVolume = Get-HPOVStorageVolume "VMware Hypervisor Cluster Shared VMFS 1" | New-HPOVProfileAttachVolume -volumeid 1

		#Submit profile to the appliance
		$params = @{

			name               = "vSphere Compute Node Template"
			description        = "vSphere Compute Node"
			serverHardwareType = "BL460c Gen8 1" 
			enclosureGroup     = $eg
			connections        = $con1, $con2, $conFC1, $conFC2, $con5, $con6, $con7, $con8
			localStorage       = $true
			initialize         = $true
			RaidLevel          = "RAID1"
			Bootable           = $true
			SANStorage         = $True
			HostOStype         = "VMware"
			StorageVolume      = $VMwareSharedVolume 
			hideUnusedFlexNics = $True
			manageBoot         = $True
			bootOrder          = ’PXE’,‘CD’,’Floppy’,’USB’,’HardDisk’
			bios               = $True
			biosSettings       = @(@{id=210;value=3},@{id=140;value=3},@{id=208;value=2},@{id=204;value=4},@{id=247;value=3},@{id=308;value=3},@{id=293;value=1})

		}

		New-HPOVServerProfileTemplate @Params | Wait-HPOVTaskComplete

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}
    
	Write-Host "Creating Windows Server 2012 R2 Hyper-V Server Profile Template"

	Try
	{

		New-HPOVStorageVolume -volumeName "Hyper-V Hypervisor Cluster Shared Disk 1" -StorageSystem "HP-P7400-1" -StoragePool R1_FC_CPG -capacity 500 -shared | Wait-HPOVTaskComplete

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
		$HyperVSharedVolume = Get-HPOVStorageVolume "Hyper-V Hypervisor Cluster Shared VMFS 1" | New-HPOVProfileAttachVolume -volumeid 1

		#Submit profile to the appliance
		$params = @{

			name               = "Hyper-V Compute Node Template"
			description        = "Hyper-V Compute Node"
			serverHardwareType = "BL460c Gen8 1" 
			enclosureGroup     = $eg
			connections        = $con1, $con2, $conFC1, $conFC2, $con5, $con6, $con7, $con8
			localStorage       = $true
			initialize         = $true
			RaidLevel          = "RAID1"
			Bootable           = $true
			SANStorage         = $True
			HostOStype         = "VMware"
			StorageVolume      = $HyperVSharedVolume 
			hideUnusedFlexNics = $True
			manageBoot         = $True
			bootOrder          = ’PXE’,‘CD’,’Floppy’,’USB’,’HardDisk’
			bios               = $True
			biosSettings       = @(@{id=210;value=3},@{id=140;value=3},@{id=208;value=2},@{id=204;value=4},@{id=247;value=3},@{id=308;value=3},@{id=293;value=1})

		}

		New-HPOVServerProfileTemplate @Params | Wait-HPOVTaskComplete

	}
	
	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Disconnect-HPOVMgmt

	Remove-Module HPOneView.200

#endregion