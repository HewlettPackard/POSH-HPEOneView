##############################################################################
# ApplianceConfig_Sample.ps1
# - Example scripts for configuring an HPE OneView appliance (networking, NTP,
#   etc.).
#
#   VERSION 3.0
#
# (C) Copyright 2013-2022 Hewlett Packard Enterprise Development LP
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

    [Parameter (Mandatory, HelpMessage = "Please provide the Appliances DHCP Address.")]
    [ValidateNotNullorEmpty()]
	[IPAddress]$vm_ipaddr,

	[Parameter (Mandatory, HelpMessage = "Please provide the Appliances NEW Hostname or FQDN.")]
	[String]$Hostname,

	[Parameter (Mandatory, HelpMessage = "Provide a [SecureString] pr [String] object representing the new appliance Administrator password.")]
	[ValidateNotNullorEmpty()]
	[Object]$NewPassword,

	[Parameter (Mandatory, HelpMessage = "Please provide the Appliances NEW Static IPv4 Address.")]
    [ValidateNotNullorEmpty()]
	[IPAddress]$IPv4Address,

	[Parameter (Mandatory, HelpMessage = "Please provide the Appliances NEW IPv4 Subnet.")]
    [ValidateNotNullorEmpty()]
	[String]$IPv4SubnetMask,

	[Parameter (Mandatory, HelpMessage = "Please provide the Appliances NEW IPv4 Default Gateway.")]
    [ValidateNotNullorEmpty()]
	[IPAddress]$IPv4Gateway,

	[Parameter (Mandatory, HelpMessage = "Please provide the Appliances NEW IPv4 DNS Servers.")]
    [ValidateNotNullorEmpty()]
	[Array]$IPv4DnsServers,

	[Parameter (Mandatory, HelpMessage = "Please provide the Appliances NEW DNS Domain Name.")]
    [ValidateNotNullorEmpty()]
	[String]$DnsDomainName,

	[Parameter (Mandatory = $false, HelpMessage = "Please provide the Appliances NEW IPv4 NTP Servers.")]
    [ValidateNotNullorEmpty()]
	[Array]$IPv4NtpServers,

    [Parameter (Mandatory = $False, HelpMessage = "Please provide the Appliances NEW IPv6 Static Address.")]
    [ValidateNotNullorEmpty()]
    [IPAddress]$IPv6Address,

    [Parameter (Mandatory = $False, HelpMessage = "Please provide the Appliances NEW IPv6 Static Address CIDR Subnet Mask.")]
    [ValidateNotNullorEmpty()]
    [Int]$IPv6CidrMask

)

if (-not (get-module HPEOneView.700))
{

    Import-Module HPEOneView.700

}

#region

	Write-Host 'Waiting for appliance to respond to network test.' -NoNewline

	While (-not (Test-Connection -ComputerName $vm_ipaddr.IPAddressToString -Quiet))
	{

		Write-Host '.' -NoNewline

	}

	Write-Host ""

	#Core Appliance Setup

    # Accept the EULA
    if (-not (Get-OVEulaStatus -Appliance $vm_ipaddr.IPAddressToString).Accepted )
	{

        Write-Host "Accepting EULA..."

		Try
		{

			$ret = Set-OVEulaStatus -SupportAccess "yes" -Appliance $vm_ipaddr.IPAddressToString

		}

		Catch
		{

			$PSCMdlet.ThrowTerminatingError($_)
		}

    }

    # For initial setup, connect first using "default" Administrator credentials:
    Try
	{

		Connect-OVMgmt -appliance $vm_ipaddr.IPAddressToString -user "Administrator" -password "admin"

	}

    catch [HPEOneView.Appliance.PasswordChangeRequired]
	{

        Write-Host "Set initial password"

		Try
		{

			Set-OVInitialPassword -OldPassword "admin" -NewPassword $NewPassword -Appliance $vm_ipaddr.IPAddressToString

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

		$ApplianceConnection = Connect-OVMgmt -appliance $vm_ipaddr.IPAddressToString -user Administrator -password $NewPassword

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Write-Host "Set appliance networking configuration"

    $params = @{

        Hostname        = $Hostname;
        IPv4Addr        = $IPv4Address.IPAddressToString;
        IPv4Subnet      = $IPv4SubnetMask;
        IPv4Gateway     = $IPv4Gateway.IPAddressToString;
        DomainName      = $DnsDomainName;
        IPv4NameServers = $IPv4DnsServers

    }

	if ($IPv6Address)
    {

		$params.Add('IPv6Type','STATIC')
        $params.Add('IPv6Addr', $IPv6Address)
		$params.Add('IPv6Subnet', $IPv6CidrMask)

    }

	Try
	{

		$task = Set-OVApplianceNetworkConfig @params

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    if (-not($Global:ConnectedSessions | ? Name -EQ $Hostname))
	{

		Try
		{

			$ApplianceConnection = Connect-OVMgmt -appliance $Hostname -user Administrator -password $NewPassword

		}

		Catch
		{

			$PSCMdlet.ThrowTerminatingError($_)

		}

	}

	try
	{

		Write-Host 'Setting Appliance NTP Servers'

        $Results = Set-OVApplianceDateTime -NtpServers $IPv4NtpServers

	}

	catch
	{

		$PSCmdlet.ThrowTerminatingError($_)

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

		$request = New-OVApplianceCsr @CSR -ApplianceConnection $ApplianceConnection

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    $baseName    = $Hostname
    $csrFileName = "$Hostname.csr"
    $cerFileName = "$Hostname.cer"

    Set-Content -path (Join-Path $csrdir -ChildPath $csrFileName) -value $request.base64Data -Force

    $csr = Get-ChildItem $csrdir | ? name -eq $csrFileName

    $parameters = "-config {0} -submit -attrib CertificateTemplate:{1} {2}\{3}.csr {2}\{3}.cer {2}\{3}.p7b" -f $CA, $template, $csrdir, $baseName

    $request = [System.Diagnostics.Process]::Start("certreq", $parameters)

    $request.WaitForExit()

    $Task = gc $csrdir\$cerFileName | Install-OVApplianceCertificate -ApplianceConnection $ApplianceConnection | Wait-OVTaskComplete

    #Configuring appliance LDAP/AD Security
    $dc1 = New-OVLdapServer -Name dc1.domain.local
    $dc2 = New-OVLdapServer -Name dc2.domain.local

    $AuthParams = @{

        UserName = "ftoomey@domain.local"
        Password = convertto-securestring -asplaintext "HPinv3nt" -force

    }

	Try
	{

		$LdapAuthDirectory = New-OVLdapDirectory -Name 'domain.local' -AD -BaseDN 'dc=domain,dc=local' -servers $dc1,$dc2 @AuthParams
		$LdapGroups = $LdapAuthDirectory | Show-OVLdapGroups @AuthParams
		$InfrastructureAdminGroup = $LdapGroups | ? Name -match 'CI Manager Full'
		$ServerAdminGroup = $LdapGroups | ? Name -match 'CI Manager Server'
		$StorageAdminGroup = $LdapGroups | ? Name -match 'CI Manager Storage'
		$NetworkAdminGroup = $LdapGroups | ? Name -match 'CI Manager Network'
		New-OVLdapGroup -d $LdapAuthDirectory -GroupName $InfrastructureAdminGroup -Roles "Infrastructure administrator" @AuthParams
		New-OVLdapGroup -d $LdapAuthDirectory -GroupName $NetworkAdminGroup -Roles "Network administrator"  @AuthParams
		New-OVLdapGroup -d $LdapAuthDirectory -GroupName $ServerAdminGroup  -Roles "Server administrator"  @AuthParams
		New-OVLdapGroup -d $LdapAuthDirectory -GroupName $StorageAdminGroup -Roles "Storage administrator"  @AuthParams

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

	Try
	{

		#Upload custom SPP Baseline
	    gci \\Server\SPP\bp-Default-Baseline-0-1.iso | Add-OVBaseline

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Try
	{

		write-host "Adding OneView license."
		New-OVLicense -License '9CDC D9MA H9P9 KHVY V7B5 HWWB Y9JL KMPL FE2H 5BP4 DXAU 2CSM GHTG L762 EG4Z X3VJ KJVT D5KM EFVW DW5J G4QM M6SW 9K2P 3E82 AJYM LURN TZZP AB6X 82Z5 WHEF D9ED 3RUX BJS2 XFXC T84U R42A 58S5 XA2D WXAP GMTQ 4YLB MM2S CZU7 2E4X E8EW BGB5 BWPD CAAR YT9J 4NUG 2NJN J9UF "424710048 HPOV-NFR1 HP_OneView_16_Seat_NFR 64HTAYJH92EY"_3KB73-R2JV9-V9HS6-LYGTN-6RLYW'

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

	# Create the new users
    New-OVUser Nat   -fullName "Nat Network Admin"  -password hpinvent -roles "Network administrator"
    New-OVUser Sally -fullName "Sally Server Admin" -password hpinvent -roles "Server administrator"
    New-OVUser Sandy -fullName "Sandy SAN Admin"    -password hpinvent -roles "Storage administrator"
    New-OVUser Rheid -fullName "Rheid Read-Only"	  -password hpinvent -roles "Read only"
    New-OVUser Bob   -fullName "Bob Backup"	      -password hpinvent -roles "Backup administrator"
    New-OVUser admin -fullName "admin"              -password hpinvent -roles "Infrastructure administrator"

#endregion

#region

	#Resource Configuration

    $params = @{

        hostname  = "172.18.15.1";
        type      = "BNA";
        username  = "administrator";
    	password  = "password";
        UseSsl    = $True

    }

    write-host "Importing BNA SAN Manager"

	Try
	{

		Add-OVSanManager @params | Wait-OVTaskComplete

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Write-Host "Creating network resources"

    # Management networks
	Try
	{

		New-OVNetwork -Name "VLAN 1-A" -type "Ethernet" -vlanId 1 -smartlink $true -purpose Management
		New-OVNetwork -Name "VLAN 1-B" -type "Ethernet" -vlanId 1 -smartlink $true -purpose Management

        # Internal Networks
		New-OVNetwork -Name "Live Migration" -type "Ethernet" -vlanId 100 -smartlink $true -purpose VMMigration
        New-OVNetwork -Name "Heartbeat" -type "Ethernet" -vlanId 101 -smartlink $true -purpose Management
        New-OVNetwork -Name "iSCSI Network" -type "Ethernet" -vlanId 3000 -smartlink $true -purpose ISCSI

		# VM Networks
		10,20,30,40,50 | % { New-OVNetwork -Name "VLAN $_-A" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }
		10,20,30,40,50 | % { New-OVNetwork -Name "VLAN $_-B" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }
		101,102,103,104,105 | % { New-OVNetwork -Name "Dev VLAN $_-A" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }
		101,102,103,104,105 | % { New-OVNetwork -Name "Dev VLAN $_-B" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }

        #Misc networks
        New-OVNetwork -Name "My Vlan 501" -type "Ethernet" -vlanId 3000 -smartlink $true -purpose General

		$ProdNetsA = Get-OVNetwork -Name "VLAN *0-A" -ErrorAction Stop
		$ProdNetsB = Get-OVNetwork -Name "VLAN *0-B" -ErrorAction Stop
		$DevNetsA  = Get-OVNetwork -Name "Dev VLAN *-A" -ErrorAction Stop
		$DevNetsB  = Get-OVNetwork -Name "Dev VLAN *-B" -ErrorAction Stop
        $InternalNetworks = 'Live Migration','Heartbeat' | % { Get-OVNetwork -Name $_ -ErrorAction Stop }

		# Create the network sets
		New-OVNetworkSet -Name "Prod NetSet1 A" -networks $ProdNetsA -untaggedNetwork $ProdNetsA[0] -typicalBandwidth 2500 -maximumBandwidth 10000
		New-OVNetworkSet -Name "Prod NetSet1 B" -networks $ProdNetsB -untaggedNetwork $ProdNetsB[0] -typicalBandwidth 2500 -maximumBandwidth 10000
		New-OVNetworkSet -Name "Dev Networks A" -networks $DevNetsA  -untaggedNetwork $DevNetsA[0]  -typicalBandwidth 2500 -maximumBandwidth 10000
		New-OVNetworkSet -Name "Dev Networks B" -networks $DevNetsB  -untaggedNetwork $DevNetsB[0]  -typicalBandwidth 2500 -maximumBandwidth 10000

		# Create the FC networks:
		New-OVNetwork -Name "Fabric A" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -managedSan "SAN1_0"
		New-OVNetwork -Name "Fabric B" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -managedSan "SAN1_1"
		New-OVNetwork -Name "DirectAttach A" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -fabricType DirectAttach
		New-OVNetwork -Name "DirectAttach B" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -fabricType DirectAttach

	}

    Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

	Try
	{

		$LigName = "Default VC FF LIG"
		$Bays = @{ 1 = 'Flex2040f8'; 2 = 'Flex2040f8'}

		$SnmpDest1 = New-OVSnmpTrapDestination -Destination mysnmpserver.domain.local -Community MyR3adcommun1ty -SnmpFormat SNMPv1 -TrapSeverities critical,warning
		$SnmpDest2 = New-OVSnmpTrapDestination -Destination 10.44.120.9 -Community MyR3adcommun1ty -SnmpFormat SNMPv1 -TrapSeverities critical,warning -VCMTrapCategories legacy -EnetTrapCategories Other,PortStatus,PortThresholds -FCTrapCategories Other,PortStatus
		$SnmpConfig = New-OVSnmpConfiguration -ReadCommunity MyR3adC0mmun1ty -AccessList '10.44.120.9/32','172.20.148.0/22' -TrapDestinations $SnmpDest1,$SnmpDest2

		$CreatedLig = New-OVLogicalInterconnectGroup -Name $LigName -Bays $Bays -Snmp $SnmpConfig -EnableIgmpSnooping $True -InternalNetworks $InternalNetworks | Wait-OVTaskComplete | Get-OVLogicalInterconnectGroup

		# Get FC Network Objects
		$FabricA   = Get-OVNetwork -Name "Fabric A" -ErrorAction Stop
		$FabricB   = Get-OVNetwork -Name "Fabric B" -ErrorAction Stop
		$DAFabricA = Get-OVNetwork -Name "DirectAttach A" -ErrorAction Stop
		$DAFabricB = Get-OVNetwork -Name "DirectAttach B" -ErrorAction Stop

		# Create Ethernet Uplink Sets
		$CreatedLig = $CreatedLig | New-OVUplinkSet -Name "Uplink Set 1" -Type "Ethernet" -Networks $ProdNetsA -nativeEthNetwork $ProdNetsA[0] -UplinkPorts "BAY1:X1","BAY1:X2" -EthMode "Auto" | Wait-OVTaskComplete | Get-OVLogicalInterconnectGroup -ErrorAction Stop
		$CreatedLig = $CreatedLig | New-OVUplinkSet -Name "Uplink Set 2" -Type "Ethernet" -Networks $ProdNetsB -nativeEthNetwork $ProdNetsB[0] -UplinkPorts "BAY2:X1","BAY2:X2" -EthMode "Auto" | Wait-OVTaskComplete | Get-OVLogicalInterconnectGroup -ErrorAction Stop

		# FC Uplink Sets
		$CreatedLig = $CreatedLig | New-OVUplinkSet -Name "FC Fabric A" -Type "FibreChannel" -Networks $FabricA   -UplinkPorts "BAY1:X7" | Wait-OVTaskComplete | Get-OVLogicalInterconnectGroup -ErrorAction Stop
		$CreatedLig = $CreatedLig | New-OVUplinkSet -Name "FC Fabric B" -Type "FibreChannel" -Networks $FabricB   -UplinkPorts "BAY2:X7" | Wait-OVTaskComplete | Get-OVLogicalInterconnectGroup -ErrorAction Stop
		$CreatedLig = $CreatedLig | New-OVUplinkSet -Name "DA Fabric A" -Type "FibreChannel" -Networks $DAFabricA -UplinkPorts "BAY1:X3",'BAY1:X4' | Wait-OVTaskComplete | Get-OVLogicalInterconnectGroup -ErrorAction Stop
		$CreatedLig = $CreatedLig | New-OVUplinkSet -Name "DA Fabric B" -Type "FibreChannel" -Networks $DAFabricB -UplinkPorts "BAY2:X3",'BAY2:X4' | Wait-OVTaskComplete | Get-OVLogicalInterconnectGroup -ErrorAction Stop

	}

	Catch
	{

		$PSCMdlet.ParameterSetName

		$PSCMdlet.ThrowTerminatingError($_)

	}

	Try
	{

		$EGParams = @{

			Name                     = "Default EG 1"
			LogicalInterConnectGroup = $CreatedLig
			ConfigurationScript      = 'ADD USER "admin" "Supersecretpassword"
SET USER CONTACT "admin" ""
SET USER FULLNAME "admin" ""
SET USER ACCESS "admin" ADMINISTRATOR
ASSIGN SERVER 1-16 "admin"
ASSIGN INTERCONNECT 1-8 "admin"
ASSIGN OA "admin"
ENABLE USER "admin"
hponcfg all >> end_marker
<RIBCL VERSION="2.0">
   <LOGIN USER_LOGIN="admin" PASSWORD="passthrough">
      <USER_INFO MODE="write">
         <ADD_USER
           USER_NAME="admin"
           USER_LOGIN="admin"
           PASSWORD="Supersecretpassword">
            <ADMIN_PRIV value ="N"/>
            <REMOTE_CONS_PRIV value ="Y"/>
            <RESET_SERVER_PRIV value ="N"/>
            <VIRTUAL_MEDIA_PRIV value ="N"/>
            <CONFIG_ILO_PRIV value="Yes"/>
         </ADD_USER>
      </USER_INFO>
   </LOGIN>
</RIBCL>
end_marker'
		}

		$EnclosureGroup = New-OVEnclosureGroup @EGParams

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Write-host "Sleeping 30 seconds"
    start-sleep -Seconds 30

    $params = @{

        username  = "3paradm";
        password  = "3pardata";
        hostname  = "172.18.11.11";
        domain    = "NO DOMAIN"

    }

    Write-Host "Importing storage array: $($params.hostname)"
	Try
	{

		$Results = Add-OVStorageSystem @params | Wait-OVTaskComplete

        $Results = Get-OVStorageSystem -ErrorAction Stop | Add-OVStoragePool -Pool 'FST_CPG1','FST_CPG2' | Wait-OVTaskComplete

		$StorageVolume = Get-OVStoragePool -Pool 'FST_CPG1' -ErrorAction Stop | New-OVStorageVolume -Name 'DO NOT DELETE' -Capacity 1

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    #Add Encl1
    Try
    {

        $EnclosureAddParams = @{

            Hostname       = '172.18.1.11';
            Username       = 'administrator';
            Password       = 'password';
            EnclosureGroup = $EnclosureGroup

        }

		$Results = Add-OVEnclosure @EnclosureAddParams

    }

    Catch
    {

        $PSCMdlet.ThrowTerminatingError($_)

    }

    Disconnect-OVMgmt

	Remove-Module HPEOneView.630

#endregion