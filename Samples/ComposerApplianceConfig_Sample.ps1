##############################################################################
# ComposerApplianceConfig_Sample.ps1
# - Example scripts for configuring an HPE OneView appliance (networking, NTP,
#   etc.).
#
#   VERSION 3.0
#
# (C) Copyright 2013-2021 Hewlett Packard Enterprise Development LP
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

    [Parameter (Mandatory, HelpMessage = "Provide the Appliances DHCP Address.")]
	[Alias('vm_ipaddr')]
    [ValidateNotNullorEmpty()]
	[IPAddress]$DhcpAddress,

	[Parameter (Mandatory, HelpMessage = "Provide the Appliances NEW Hostname or FQDN.")]
	[String]$Hostname,

	[Parameter (Mandatory, HelpMessage = "Provide a [SecureString] pr [String] object representing the new appliance Administrator password.")]
	[ValidateNotNullorEmpty()]
	[Object]$NewPassword,

	[Parameter (Mandatory, HelpMessage = "Provide the Composer Primary Virtual IP.")]
    [ValidateNotNullorEmpty()]
	[IPAddress]$IPv4Address,

	[Parameter (Mandatory, HelpMessage = "Provide the Appliances NEW IPv4 Subnet.")]
    [ValidateNotNullorEmpty()]
	[String]$IPv4SubnetMask,

	[Parameter (Mandatory, HelpMessage = "Provide the Appliances NEW IPv4 Default Gateway.")]
    [ValidateNotNullorEmpty()]
	[IPAddress]$IPv4Gateway,

	[Parameter (Mandatory, HelpMessage = "Provide the Appliances NEW IPv4 DNS Servers.")]
    [ValidateNotNullorEmpty()]
	[Array]$IPv4DnsServers,

	[Parameter (Mandatory, HelpMessage = "Provide the Appliances NEW DNS Domain Name.")]
    [ValidateNotNullorEmpty()]
	[String]$DnsDomainName,

    [Parameter (Mandatory, HelpMessage = "Provide the Appliances NEW DNS Domain Name.")]
    [ValidateNotNullorEmpty()]
    [IPAddress]$ServiceIPv4Node1,

    [Parameter (Mandatory, HelpMessage = "Provide the Appliances NEW DNS Domain Name.")]
    [ValidateNotNullorEmpty()]
    [IPAddress]$ServiceIPv4Node2,

	[Parameter (Mandatory = $false, HelpMessage = "Provide the Appliances NEW IPv4 NTP Servers.")]
    [ValidateNotNullorEmpty()]
	[Array]$IPv4NtpServers,

    [Parameter (Mandatory = $False, HelpMessage = "Provide the Appliances NEW IPv6 Static Address.")]
    [ValidateNotNullorEmpty()]
    [IPAddress]$IPv6Address,

    [Parameter (Mandatory = $False, HelpMessage = "Provide the Appliances NEW IPv6 Static Address.")]
    [ValidateNotNullorEmpty()]
    [Int]$IPv6CidrMask,

    [Parameter (Mandatory = $False, HelpMessage = "Provide the Service IP for Node 1 NEW IPv6 Static Address.")]
    [ValidateNotNullorEmpty()]
    [IPAddress]$ServiceIPv6Node1,

    [Parameter (Mandatory = $False, HelpMessage = "Provide the Service IP for Node 2 NEW IPv6 Static Address.")]
    [ValidateNotNullorEmpty()]
    [IPAddress]$ServiceIPv6Node2

)

if (-not (Get-Module HPEOneView.540))
{

    Import-Module HPEOneView.540

}

#region

	Write-Host 'Waiting for appliance to respond to network test.' -NoNewline

	While (-not (Test-Connection -ComputerName $DhcpAddress.IPAddressToString -Quiet))
	{

		Write-Host '.' -NoNewline

	}

	Write-Host ""

	#Core Appliance Setup

    # Accept the EULA
    if (-not (Get-OVEulaStatus -Appliance $DhcpAddress.IPAddressToString).Accepted )
	{

        Write-Host "Accepting EULA..."

		Try
		{

			$ret = Set-OVEulaStatus -SupportAccess "yes" -Appliance $DhcpAddress.IPAddressToString

		}

		Catch
		{

			$PSCMdlet.ThrowTerminatingError($_)
		}

    }

    # For initial setup, connect first using "default" Administrator credentials:
    Try
	{

		Connect-OVMgmt -appliance $DhcpAddress.IPAddressToString -user "Administrator" -password "admin"

	}

    catch [HPEOneView.Appliance.PasswordChangeRequired]
	{

        Write-Host "Set initial password"

		Try
		{

			Set-OVInitialPassword -OldPassword "admin" -NewPassword $NewPassword -Appliance $DhcpAddress.IPAddressToString

		}

		Catch
		{

			$PSCMdlet.ThrowTerminatingError($_)

		}

    }

	catch [HPEOneView.Appliance.AuthSessionException]
	{

		Write-Host "Default password was already changed."

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Write-Host "Reconnect with new password"

	Try
	{

		$ApplianceConnection = Connect-OVMgmt -appliance $DhcpAddress.IPAddressToString -user Administrator -password $NewPassword

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

    Write-Host "Set appliance networking configuration"

    $params = @{

        Hostname         = $Hostname;
        IPv4Addr         = $IPv4Address.IPAddressToString;
        IPv4Subnet       = $IPv4SubnetMask;
        IPv4Gateway      = $IPv4Gateway.IPAddressToString;
        DomainName       = $DnsDomainName;
        IPv4NameServers  = $IPv4DnsServers;
        ServiceIPv4Node1 = $ServiceIPv4Node1;
        ServiceIPv4Node2 = $ServiceIPv4Node2

    }

    if ($IPv6Address)
    {

		$params.Add('IPv6Type','STATIC')
        $params.Add('IPv6Addr', $IPv6Address)
		$params.Add('IPv6Subnet', $IPv6CidrMask)
        $params.Add('ServiceIPv6Node1', $ServiceIPv6Node1)
        $params.Add('ServiceIPv6Node2', $ServiceIPv6Node2)

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
		$ServerAdminGroup  = $LdapGroups | ? Name -match 'CI Manager Server'
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
	    gci \\Server\software\SPP\bp-2016-07-11-00.iso | Add-OVBaseline

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}


	# Create the new users
    New-OVUser Nat   -fullName "Nat Network Admin"  -password hpinvent -roles "Network administrator"
    New-OVUser Sarah -fullName "Sarah Server Admin" -password hpinvent -roles "Server administrator"
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
    	password  = "pasword";
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

		New-OVNetwork -Name "MLAG VLAN 10" -type "Ethernet" -vlanId 10 -smartlink $true -purpose Management

        # Internal Networks
		New-OVNetwork -Name "Internal Live Migration" -type "Ethernet" -vlanId 100 -smartlink $true -purpose VMMigration
        New-OVNetwork -Name "Internal Heartbeat" -type "Ethernet" -vlanId 101 -smartlink $true -purpose Management
        New-OVNetwork -Name "iSCSI Network" -type "Ethernet" -vlanId 3000 -smartlink $true -purpose ISCSI

		# VM Networks
        20,30,40,50 | % { New-OVNetwork -Name "MLAG Prod VLAN $_" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }
		101,102,103,104,105 | % { New-OVNetwork -Name "MLAG Dev VLAN $_" -type "Ethernet" -vlanId $_ -smartlink $true -purpose General }

		$AllMlagDevNetworks = Get-OVNetwork -Name "MLAG Dev VLAN"
		$AllMlagNetworks    = Get-OVNetwork -Name "MLAG VLAN*"
        $InternalNetworks   = Get-OVNetwork -Name Internal*

		# Create the network sets
		New-OVNetworkSet -Name "Prod NetSet" -networks $AllMlagNetworks -untaggedNetwork $AllMlagNetworks[0] -typicalBandwidth 2500 -maximumBandwidth 10000
		New-OVNetworkSet -Name "Dev Networks A" -networks $AllMlagDevNetworks -untaggedNetwork $AllMlagDevNetworks[0]  -typicalBandwidth 2500 -maximumBandwidth 10000

		# Create the FC networks:
		New-OVNetwork -Name "Fabric A" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true #-managedSan "SAN1_0"
		New-OVNetwork -Name "Fabric B" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true #-managedSan "SAN1_1"
		New-OVNetwork -Name "DirectAttach A" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -fabricType DirectAttach
		New-OVNetwork -Name "DirectAttach B" -type "FibreChannel" -typicalBandwidth 4000 -autoLoginRedistribution $true -fabricType DirectAttach

	}

    Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

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

        $Results = Get-OVStorageSystem | Add-OVStoragePool -Pool 'FST_CPG1','FST_CPG2' | Wait-OVTaskComplete

	}

	Catch
	{

		$PSCMdlet.ThrowTerminatingError($_)

	}

	$SynergyLigParams = @{

		Name               = 'Default Synergy LIG';
		InterconnectBaySet = 3;
		FabricModuleType   = 'SEVC40F8';
		FrameCount         = 3;
		InternalNetworks   = $InternalNetworks;
		FabricRedundancy   = 'HighlyAvailable'
		Bays               = @{
								Frame1 = @{Bay3 = 'SEVC40f8'; Bay6 = 'SE20ILM' };
								Frame2 = @{Bay3 = 'SE20ILM'; Bay6 = 'SEVC40f8'};
								Frame3 = @{Bay3 = 'SE20ILM'; Bay6 = 'SE20ILM'}
								}

	}

	$CreatedLogicalInterconnectObject = New-OVLogicalInterconnectGroup @SynergyLigParams | Get-OVLogicalInterconnectGroup

	$UplinkSetParams = @{

		InputObject = $CreatedLogicalInterconnectObject;
		Name        = 'MLag UplinkSet';
		Type        = 'Ethernet';
		Networks    = $AllMlagNetworks;
		UplinkPorts = "Enclosure1:Bay3:Q1","Enclosure1:Bay3:Q2","Enclosure2:Bay6:Q1","Enclosure2:Bay6:Q2"

	}

	$CreateUplinkSetResults = New-OVUplinkSet @UplinkSetParams

	$LIG = Get-OVLogicalInterconnectGroup -Name 'Default Synergy LIG'

	$EgParams = @{

		Name                            = 'Synergy Default EG';
		EnclosureCount                  = 3;
		LogicalInterconnectGroupMapping = $LIG;
		IPv4AddressType                 = 'DHCP'

	}

    $CreateEGResults = New-OVEnclosureGroup @EgParams

    Disconnect-OVMgmt

	Remove-Module HPEOneView.540

#endregion