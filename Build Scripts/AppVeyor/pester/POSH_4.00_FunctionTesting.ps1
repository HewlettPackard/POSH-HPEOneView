# Use to hide Welcome Banner when module loads.
$LibraryModuleName = 'HPOneView.400'
$global:TOT = $false

if (Get-Module -Name $LibraryModuleName)
{

    Remove-Module -Name $LibraryModuleName

    Write-Warning 'Another $LibraryModuleName module was previously loaded.  Runspace is not cleared if testing New Class Objects.'

}

Write-Host ('Pester version on PC: {0}' -f (Get-Module -Name Pester).Version) -ForegroundColor Cyan
Write-Host 'PSVersionTable:' -ForegroundColor Cyan
$PSVersionTable | Out-String | Write-Host -ForegroundColor Cyan

New-Variable -Name Alltags -Value All,Smoke,Baseline,DirectoryAuthentication,EthernetNetwork,Networking,FibreChannelNetwork,FCoENetwork,LogicalSwitch,Storage,StorageVolume,Comet,BladeSystemPolicies,SynergyPolicies,ServerHardware,Rackmount,BladeSystem,ServerProfile,ApplianceAlerting,LocalAuthentication, PowerDevice

function GetRandom {

    $Characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $Chars      = [char[]]::New(8)
    $random     = New-object System.Random
    $String     = $null

    for ($i = 0; $i -lt $Chars.Length; $i++)
    {

        $String += $Characters.Substring($random.Next($Characters.Length),1)
        
    }

    Return $String

    #Replace above with the following if Random is not generating quickly enough or truly random enough:
    #Return [Guid]::NewGuid().ToString().Replace("-", [string]::Empty).Substring(0, 8)

}

function DisplayTaskError ([Object]$Task) {

    if ($Task.category -ne 'tasks') {

        Microsoft.PowerShell.Utility\write-host 'Resource object was not a task:' -ForegroundColor Yellow 
        Microsoft.PowerShell.Utility\write-host ($Task | Out-String) -ForegroundColor Yellow 

    }

    else {

        Microsoft.PowerShell.Utility\write-host ('Task state: {0}' -f $Task.taskState) -ForegroundColor Yellow 
        Microsoft.PowerShell.Utility\write-host ('Task URI: {0}' -f $Task.uri) -ForegroundColor Yellow 
        Microsoft.PowerShell.Utility\write-host ('Task errors: {0}' -f ($Task.taskErrors | Format-List * -force)) -ForegroundColor Yellow 

    }
    
}

# Init Variables
    
    $DnsDomainName  = 'doctors-lab.local'
    $ApplianceConfig = Invoke-RestMethod http://fileserver.doctors-lab.local/config.json
    $Appliance1Name = $ApplianceConfig."4.00".Appliance1
    $Appliance2Name = $ApplianceConfig."4.00".Appliance2
    $Appliance3Name = $ApplianceConfig."4.00".Appliance3
    $FexName        = $ApplianceConfig."4.00".Appliance4

    # Refresh the DCS ServerName values for each appliance
    $Appliance1Name, $Appliance2Name, $Appliance3Name | ForEach-Object { Set-DcsServerHostname -Appliance $_ }

    $Appliance1     = '{0}.{1}' -f $Appliance1Name, $DnsDomainName
    $Appliance2     = '{0}.{1}' -f $Appliance2Name, $DnsDomainName
    $Appliance3     = '{0}.{1}' -f $Appliance3Name, $DnsDomainName
    $Appliance1IPv4 = (Resolve-DnsName $Appliance1 -Type A -ErrorAction Stop).IPAddress
    $Appliance2IPv4 = (Resolve-DnsName $Appliance2 -Type A -ErrorAction Stop).IPAddress
    $Appliance3IPv4 = (Resolve-DnsName $Appliance3 -Type A -ErrorAction Stop).IPAddress
    $IPv6Appliance1 = '{0}-ipv6.{1}' -f $Appliance1Name, $DnsDomainName
    $IPv6Appliance2 = '{0}-ipv6.{1}' -f $Appliance2Name, $DnsDomainName
    $IPv6Appliance3 = '{0}-ipv6.{1}' -f $Appliance3Name, $DnsDomainName
    $FexAppliance   = '{0}.{1}' -f $FexName, $DnsDomainName

    $LabPC = $false

    if ($env:computername -match 'Desktop' -or ((hostname) -match '-worker')) {

        $LabPC = $true

    }

    $DC1                           = 'dc1.doctors-lab.local'
    $DC2                           = 'dc2.doctors-lab.local'
    $DC1IPv6                       = 'dc1-ipv6.doctors-lab.local'
    $DC2IPv6                       = 'dc2-ipv6.doctors-lab.local'
    $DirectoryDomainName           = 'doctors-lab.local'
    $Appliance1EmailAddress        = 'hpov1@doctors-lab.local'
    $Appliance2EmailAddress        = 'hpov2@doctors-lab.local'
    $Recipient1EmailAddress        = 'admin1@doctors-lab.local'
    $Recipient2EmailAddress        = 'admin2@doctors-lab.local'
    $Recipient3EmailAddress        = 'group-dl@doctors-lab.local'
    $SmtpRelayServerAddress        = 'mail.doctors-lab.local'
    $SmtpRelayServerTcpPort        = 25
    $RemoteSyslogIPv4Address       = '192.168.19.2'
    $CleanupIndexUri               = "/rest/index/resources?filter=category != 'tasks'&filter=category != 'alerts'&query=name=/.*{0}.*/" -f $PesterTestRandomName
    $PCDefaultWebBrowserEnum       = @{
        'AppXq0fevzme2pys62n3e0fbqa7peapykr8v' = [PSCustomObject]@{ Name = 'Microsoft Edge'; ProcessName = 'microsoftedge'}; 
        'IE.HTTP'                              = [PSCustomObject]@{ Name = 'Internet Explorer'; ProcessName = 'iexplore'}; 
        'FirefoxURL'                           = [PSCustomObject]@{ Name = 'Firefox'; ProcessName = 'firefox'}; 
        'ChromeHTML'                           = [PSCustomObject]@{ Name = 'Google Chrome'; ProcessName = 'chrome'}
    }
    $PCDefaultWebBrowser           = $PCDefaultWebBrowserEnum[(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice').ProgId]
    $ApplianceDefaultUsername      = 'Administrator'
    $AppliancePasswordSecureString = ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force
    $AppliancePSCredential         = New-Object System.Management.Automation.PSCredential ($ApplianceDefaultUsername, $AppliancePasswordSecureString)
    $DcsHeaders                    = @{ Accept = 'text/html, application/xhtml+xml, image/jxr, */*'}
# endregion

# region Setup Resource Names and variables

        $PesterTestRandomName = GetRandom
        $InvalidName = 'Foo'        

    # Region Appliance
        $CommonPassword                    = $ApplianceConfig.Config.CommonPassword
        $RemoteBackupHostname              = 'fileserver.doctors-lab.local'
        $RemoteBackupUsername              = 'backupadmin'
        $RemoteBackupPassword              = ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force
        $RemoteBackupPublicKey             = $ApplianceConfig.Config.RemoteBackupPublicKey
        $ExternalRepositoryName            = '{0}-ExtRepo' -f $PesterTestRandomName
        $ExternalRepositoryHostname        = 'fileserver.doctors-lab.local'
        $ExternalRepositoryDirectory       = 'OneViewExternalRepo'
        $ExternalAnonymousRepoDirectory    = 'OneViewExtRepoNoAuth'
        $ExternalRepositoryBase64Cert      = Get-Content \\fileserver\software\AppVeyor\pester\fileserver_ssl_cert.txt -raw -ErrorAction Stop
        $ExternalRepositoryUsername        = $RemoteBackupUsername
        $ExternalRepositoryPassword        = ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force
        $ExternalRepositoryPSCredential    = New-Object System.Management.Automation.PSCredential ($ExternalRepositoryUsername, $ExternalRepositoryPassword)
        $DC1CACertificate                  = '\\fileserver\software\AppVeyor\pester\dc1-CA-base64-cert.cer'
        $CIManagerServerAdmins             = 'CI Manager Server Admins'
        $CIManagerNetworkAdmins            = 'CI Manager Network Admins'
        $CIManagerStorageAdmins            = 'CI Manager Storage Admins'
        $CIManagerFullAdmins               = 'CI Manager Full Admins'
        $DC1CACononicalName                = 'doctors-lab-dc1-ca'
        $DefaultLdapDirectoryName          = 'doctors-lab.local'
        $LdapUser                          = 'LdapUser@doctors-lab.local'
        $InfraAdminUserUpn                 = 'FToomey@doctors-lab.local'
        $InfraAdminUserNt                  = 'Doctors-lab\FToomey'
        $ServerAdminUserUpn                = 'sharrison@doctors-lab.local'
        $StorageAdminUserUpn               = 'srousey@doctors-lab.local'
        $NetworkAdminUserUpn               = 'nyoung@doctors-lab.local'
        $InvalidLdapUserUpn                = 'foo@doctors-lab.local'
        $LdapSecurePassword                = ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force
        $LdapPSPSCredential                = New-Object System.Management.Automation.PSCredential ($LdapUser, $LdapSecurePassword)
        $LdapIPv4DirectoryName             = '{0}-IPv4-LdapDirectory.local' -f $PesterTestRandomName
        $LdapIPv6DirectoryName             = '{0}-IPv6-LdapDirectory.local' -f $PesterTestRandomName
        $CommonNamePattern                 = '^CN=(.+?),(?:CN|OU)=.+'
        $SppFile                           = Get-ChildItem '\\fileserver\software\SPP\bp-Fusion_31_Default-1-0.iso'
        $ExistingBaselineName              = 'bp-HPE_OneView_Baseline-1-0.iso'
        $ExistingSynergyBaselineName       = 'bp-Synergy20170701Baseline-1-0.iso'
        $HotfixToUpload                    = Get-ChildItem '\\fileserver\Software\Spp\hp-firmware-ilo4-2.44-1.1.i386.rpm'
        $CustomBaselineName                = '{0}-CustomBaseline' -f $PesterTestRandomName
        $CustomMacAddressPoolStart         = 'A6:14:10:F0:00:00'
        $CustomMacAddressPoolEnd           = 'A6:14:10:F0:00:7F'
        $TotalCustomMacAddresses           = 128
        $IPv4SubnetID                      = '192.168.30.0'
        $IPv4SubnetMaskID                  = '23'
        $IPv4SubnetMask                    = '255.255.254.0'
        $IPv4SubnetGateway                 = '192.168.30.1'
        $IPv4SubnetDns1                    = '192.168.19.11'
        $IPv4SubnetDns2                    = '192.168.19.12'
        $IPv4SubnetDomainName              = 'Doctors-lab.local'
        $IPv4SubnetStartAddress            = '192.168.30.100'
        $IPv4SubnetEndAddress              = '192.168.31.254'
        $IPv4SubnetInvalidStartAddress     = '192.168.40.200'
        $IPv4SubnetInvalidEndAddress       = '192.168.35.254'
        $IPv4EthernetNetworkName           = '{0}-Management Network' -f $PesterTestRandomName
        $IPv4EthernetNetworkVlanID         = Get-Random -Minimum 2 -Maximum 3967
        $I3SIPv4SubnetName                 = 'I3S Deployment Subnet'
        $I3SIPv4SubnetId                   = '192.168.29.0'
        $I3SIPv4SubnetMaskID               = '24'
        $I3SIPv4SubnetGateway              = '192.168.29.1'
        $I3SIPv4PoolName                   = '{0}-Deployment Pool' -f $PesterTestRandomName
        $I3SIPv4PoolStartAddress           = '192.168.29.240'
        $I3SIPv4PoolEndAddress             = '192.168.29.254'
        $I3SDeploymentNetworkName          = '{0}-I3S Deployment Network' -f $PesterTestRandomName
        $I3SDeploymentNetworkVlanID        = Get-Random -Minimum 2 -Maximum 3967
        $I3SApplianceName                  = '{0}-I3S Appliance 1' -f $PesterTestRandomName
        $TestEmailAlertSubject             = 'Test Email Message {0}' -f $PesterTestRandomName
        $TestEmailAlertHtmlBody            = "<html><head><title>Test Email Alert</title></head><body><h1>Sample message</h1><p>This is a sample test HTML message</p></body></html>"
        $NewLabel1Name                     = 'Label1{0}' -f $PesterTestRandomName
        $NewLabel2Name                     = 'Label2{0}' -f $PesterTestRandomName
        $TrustedCertificateDnsName         = 'myhost1.doctors-lab.local'
        $TrustedCertificateDnsName2        = 'myhost_1.doctors-lab.local'
        $TrustedCertificateFriendlyName    = '{0}-myhost1' -f $PesterTestRandomName
        $SnmpV1TrapDestinationAddress      = '1.1.1.1'
        $SnmpV1Community                   = '{0}' -f $PesterTestRandomName
        $SnmpV3TrapDestinationAddress      = '2.2.2.2'
        $SnmpV1TrapDestinationPort         = 162
        $SnmpV3UserName                    = '{0}-SnmpUser' -f $PesterTestRandomName
        $SnmpV3UserSecurity                = 'AuthAndPriv'
        $SnmpV3UserAuthProtocol            = 'SHA512'
        $SnmpV3UserPrivProtocol            = 'AES192'
        $SnmpV3AuthPassword                = ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force
        $SnmpV3PrivPassword                = ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force
        $ApplianceProxyAddress             = 'firewall.doctors-lab.local'
        $ApplianceProxyHttpTCPPort         = 3128
        $ApplianceProxyHttpsTCPPort        = 3129
    # endregion

    # Appliance Security region
        $MySbacScope1Name                  = '{0}-SBAC Scope 1' -f $PesterTestRandomName
        $MySbacScope2Name                  = '{0}-SBAC Scope 2' -f $PesterTestRandomName
        $SbacEthernetNetwork               = '{0}-SBAC Net1' -f $PesterTestRandomName
        $NewLocalAccountUsername           = 'User{0}' -f $PesterTestRandomName
        $NewLocalAccountFullname           = 'Pester User'
        $ExistingScopeName                 = 'Site A Admins'
    # endregion

    # L2 Networking Names & Prefixes
        $EthernetNetworkVlan              = Get-Random -Maximum 4094
        $FCoENetworkVlan                  = Get-Random -Minimum 2 -Maximum 4094
        $IscsiEthernetNetworkVlan         = Get-Random -Maximum 4094
        $EthernetNetworkVlanForNetSet     = Get-Random -Maximum 4094
        $InvalidEthernetVlan              = Get-Random -Minimum 4095 -Maximum 9999
        $BulkEthernetVlanIds              = (1..10 | ForEach-Object { Get-Random -Minimum 1 -Maximum 4094 } | Sort-Object) -Join ","
        $EthernetNetworkPrefix            = $PesterTestRandomName
        $FCNetworkPrefix                  = $PesterTestRandomName
        $EthernetNetworkName              = "{0}-VLAN {1}" -f $PesterTestRandomName, $EthernetNetworkVlan
        $IscsiEthernetNetworkName         = "{0}-IscsiVLAN {1}" -f $PesterTestRandomName, $IscsiEthernetNetworkVlan
        $BulkEthernetNetworkNamePrefix    = '{0}-BulkVlan' -f $PesterTestRandomName
        $NetworkSetName                   = "{0}-NetworkSet" -f $PesterTestRandomName
        $EthernetNetworkNameForNetSet     = "{0}-Vlan {1}" -f $PesterTestRandomName,$EthernetNetworkVlanForNetSet
        $NonexistantEthernetNetworkName   = "Foo Ethernet Network {0}" -f (GetRandom)
        $NewFabricAttachNetworkName       = "{0}-Fabric Attach" -f $PesterTestRandomName
        $NewFabricAttachNetworkFabricType = 'FabricAttach'
        $NewFabricAttachNetworkManagedSAN = 'SAN1_0'
        $NewFCoENetworkName               = '{0}-FCoE Network {1}' -f $PesterTestRandomName, $FCoENetworkVlan
        $NetworksToImport                 = '[{"type":"ethernet-networkV4","ethernetNetworkType":"Tagged","vlanId":99,"smartLink":true,"purpose":"ISCSI","privateNetwork":false,"fabricUri":"/rest/fabrics/bd9ce6a6-7bbd-4561-8ee3-a2db8c8ae730","connectionTemplateUri":"/rest/connection-templates/1fd68c1d-9dd1-482e-b5e8-82d5268faed4","subnetUri":"/rest/id-pools/ipv4/subnets/b672d179-aa22-40c1-807e-5eadfc4acac0","scopeUris":[],"description":null,"name":"{0}-deployment","state":"Active","status":"OK","created":"2017-03-08T16:09:18.164Z","eTag":"5e3de383-5f27-44b6-ae06-8dd61d34b796","modified":"2017-03-08T16:09:18.165Z","category":"ethernet-networks","uri":"/rest/ethernet-networks/dfdd40e9-2bdb-48e5-a84f-f7d3df4b1c4d","ApplianceConnection":{"Name":"169.254.24.30","ConnectionId":2},"defaultMaximumBandwidth":20000,"defaultTypicalBandwidth":2500},{"type":"ethernet-networkV4","ethernetNetworkType":"Tagged","vlanId":200,"smartLink":true,"purpose":"General","privateNetwork":false,"fabricUri":"/rest/fabrics/bd9ce6a6-7bbd-4561-8ee3-a2db8c8ae730","connectionTemplateUri":"/rest/connection-templates/d30e63fb-db95-4bed-b46c-1800fe3da517","subnetUri":null,"scopeUris":[],"description":null,"name":"{0}-Dev-Test_200","state":"Active","status":"OK","created":"2017-03-08T16:10:08.864Z","eTag":"8509d5e2-c6a1-4fb1-be71-df4f79203b69","modified":"2017-03-08T16:10:08.867Z","category":"ethernet-networks","uri":"/rest/ethernet-networks/3fd83af5-f7dd-4a20-a40d-eae627860661","ApplianceConnection":{"Name":"169.254.24.30","ConnectionId":2},"defaultMaximumBandwidth":20000,"defaultTypicalBandwidth":2500}]' -Replace '\{0\}',$PesterTestRandomName
    # endregion

    # BladeSystem/Synergy Policies
        $LogicalInterconnectGroupName         = '{0}-LogicalInterconnectGroup' -f $PesterTestRandomName
        $CiscoFexLogicalInterconnectGroupName = '{0}-FEXLogicalInterconnectGroup' -f $PesterTestRandomName
        $LIGUplinkSet1Name                    = '{0}-Uplink Set 1' -f $PesterTestRandomName
        $LIGUplinkSet2Name                    = '{0}-Uplink Set 2' -f $PesterTestRandomName
        $LIGUplinkSet3Name                    = '{0}-Uplink Set 3' -f $PesterTestRandomName
        $SynergyVCSE40F8LIGName               = '{0}-VCSE40F8LIG' -f $PesterTestRandomName
        $SynergyVCSE40F8i3SLIGName            = '{0}-VCSE40F8i3SLIG' -f $PesterTestRandomName
        $MLAGUplinkSetName                    = '{0}-MLAG UplinkSet' -f $PesterTestRandomName
        $MLAGUplinkSetUplinkPorts             = "Enclosure1:Bay3:Q1","Enclosure1:Bay3:Q2","Enclosure2:Bay6:Q1","Enclosure2:Bay6:Q2"
        $i3SUplinkSetName                     = '{0}-Deployment UplinkSet' -f $PesterTestRandomName
        $i3SUplinkSetUplinkPorts              = "Enclosure1:Bay3:Q3.1","Enclosure1:Bay3:Q4.1","Enclosure2:Bay6:Q3.1","Enclosure2:Bay6:Q4.1"
        $SynergyEg1Name                       = '{0}-EG1' -f $PesterTestRandomName      #Basic 3-Frame LIG
        $SynergyEg2Name                       = '{0}-EG2' -f $PesterTestRandomName      #Will use with Image Streamer configuration
        $SynergyEgi3SName                     = '{0}-i3SEG1' -f $PesterTestRandomName      #Will use with Image Streamer configuration
        $SynergySASLigName                    = '{0}-SAS LIG1' -f $PesterTestRandomName
        $SynergyVCFCLigName                   = '{0}-VCFC LIG1' -f $PesterTestRandomName
        $DCSDefaultLIGName                    = 'DCS Default VC FF LIG'
        $DCSDefaultEGName                     = 'DCS Default EG 1'
        $SynergyDCSDefaultEGName              = 'DCS Synergy Default EG'  
        $EnclosureGroupName                   = '{0}-EnclosureGroup' -f $PesterTestRandomName
        $EnclosureGroupConfigScript           = 'ADD USER "admin" "*********"
            SET USER CONTACT "admin" "MySecretPassword"
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
        $ExistingEnclosureName                = 'Encl1'
        $ExistingEnclosureIPAddress           = '172.18.1.11'
        $ExistingEnclosureUsername            = 'dcs'
        $ExistingEnclosurePassword            = ConvertTo-SecureString -String 'dcs' -AsPlainText -Force
        $ExistingLogicalInterconnectName      = 'Encl1-DCS Default VC FF LIG'
        $NewUplinkSetforLIName                = 'My Vlan 501'
    # endregion
    
    # Logical Switch Region
        $LogicalSwitchGroup1Name          = '{0}-LogicalSwitchGroup1' -f $PesterTestRandomName
        $LogicalSwitchGroup1Type          = 'Cisco Nexus 600x'
        $LogicalSwitchGroup2Name          = '{0}-LogicalSwitchGroup2' -f $PesterTestRandomName
        $LogicalSwitchGroup2Type          = 'Cisco Nexus 56xx'
        $LogicalSwitch1Name               = '{0}-Nexus600x-LogicalSwitch1' -f $PesterTestRandomName
        $LogicalSwitch2Name               = '{0}-Nexus56xx-LogicalSwitch2' -f $PesterTestRandomName
        $NexusSwitch1DCSIPv4Address       = '172.18.17.1' #Nexus 6001
        $NexusSwitch2DCSIPv4Address       = '172.18.17.2' #Nexus 6001
        $NexusSwitch3DCSIPv4Address       = '172.18.16.91' #Nexus 56128p
        $NexusSwitch4DCSIPv4Address       = '172.18.16.92' #Nexus 56128p
        $NexusSwitchDcsSshUsername        = 'root'
        $NexusSwitchDcsSshPassword        = ConvertTo-SecureString -String 'dcs123' -AsPlainText -Force
        $NexusSwitchDcsSnmpCommunityName  = 'public'
        $NexusSwitchSnmpv3Username        = 'OneView'
        $NexusSwitchSnmpv3AuthProtocol    = 'SHA'
        $NexusSwitchSnmpv3AuthPassword    = ConvertTo-SecureString -String 'hpvse123' -AsPlainText -Force
        $NexusSwitchSnmpv3PrivProtocol    = 'AES128'
        $NexusSwitchSnmpv3PrivPassword    = ConvertTo-SecureString -String 'hpvse123' -AsPlainText -Force
    # endregion

    # Storage Region

        ##STORESERV
        $StorageSystemAddress             = '172.18.11.12'
        $StorageSystemSerialNumber        = 'TXQ1010307'
        $StorageSystem1Name               = 'ThreePAR-1'
        $StorageSystem2Name               = 'ThreePAR-2'
        $StorageSystemUsername            = 'dcs'
        $StorageSystemPassword            = ConvertTo-SecureString -String 'dcs' -AsPlainText -Force
        $StorageSystemPSCredential        = New-Object System.Management.Automation.PSCredential ($StorageSystemUsername, $StorageSystemPassword)
        $StorageSystemInvalidDomainName   = 'foo'
        $StorageSystemDomainName          = 'ScaleTestingDomain'
        $StorageSystemPoolName1           = 'ScaleTestingDomain_CPG_1'
        $StorageSystemPoolName2           = 'ScaleTestingDomain_CPG_2'
        $StorageSystemPoolName3           = 'ScaleTestingDomain_CPG_3'
        $NewDirectAttachNetworkName       = "Direct Attach {0}" -f $PesterTestRandomName
        $NewDirectAttachNetworkFabricType = 'DirectAttach'
        $StorageVolumeName                = '{0}-StorageVolume' -f $PesterTestRandomName
        $StorageVolumeTPDDName            = '{0}-TPDD-StorageVolume' -f $PesterTestRandomName
        $DeviceVolumeName                 = $StorageVolumeName.Replace(' ', $null)
        $SharedStorageVolumeName          = '{0}-New-Shared-StorageVolume' -f $PesterTestRandomName
        $StorageVolumeTemplateName        = '{0}-StorageVolumeTemplate' -f $PesterTestRandomName
        $StorageVolumeTemplateLockedName  = '{0}-LockedStorageVolumeTemplate' -f $PesterTestRandomName
        $StorageVolumeTemplateNewName     = '{0}-Updated' -f $StorageVolumeTemplateName
        $StoreServeSSDPoolName            = 'CPG-SSD'
        $StorageVolumeTPDDVolumeName      = '{0}-TPDD-Volume' -f $StorageVolumeTemplateName

        ##STOREVIRTUAL
        $StoreVirtual1Address             = '172.18.30.1'
        $StoreVirtual1Name                = 'Cluster-1'
        $StoreVirtual1SystemPoolName      = $StoreVirtual1Name.Clone()
        $StoreVirtual2Address             = '172.18.30.2'
        $StoreVirtual2Name                = 'Cluster-2'
        $StoreVirtual2SystemPoolName      = $StoreVirtual2Name.Clone()
        $StoreVirtual3Address             = '172.18.30.3'
        $StoreVirtual3Name                = 'Cluster-3'
        $StoreVirtual3SystemPoolName      = $StoreVirtual3Name.Clone()
        $StoreVirtualTemplateName         = '{0}-StorageVirtualVolumeTemplate' -f $PesterTestRandomName
        $DataProtectionLevel              = 'NetworkRaid10Mirror2Way'

        ##SAN MANAGERS
        $BNASanManagerHostName            = 'bna1401.doctors-lab.local'
        $BNASanManagerUsername            = 'Administrator'
        $BNASanManagerPassword            = ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force
        $UpdatedSanManagerUsername        = 'StorageAdmin'
        $UpdatedSanManagerPassword        = ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force
        $CiscoSanManagerHostname          = '172.18.20.1'
        $CiscoSanManagerSnmpUserName      = 'dcs-SHA-AES128'
        $CiscoSanManagerSnmpAuthLevel     = 'AuthAndPriv'
        $CiscoSanManagerSnmpAuthProtocol  = 'SHA'
        $CiscoSanManagerSnmpAuthPassword  = ConvertTo-SecureString -String 'dcsdcsdcs' -AsPlainText -Force
        $CiscoSanManagerSnmpPrivProtocol  = 'aes-128'
        $CiscoSanManagerSnmpPrivPassword  = ConvertTo-SecureString -String 'dcsdcsdcs' -AsPlainText -Force
        
    # endregion

    # Server Resources Region
        $ServerName                       = 'Server-1'
        $ServerNameFqdn                   = 'Server-1.domain.com'
        $DL360pGen8_2253                  = '172.18.6.14'
        $DL360Gen9_4341                   = '172.18.6.30'
        $DL360Gen10_2500                  = '172.18.31.3'
        $DL380pGen8_2320                  = '172.18.6.16'
        $DL380pGen8_4408                  = '172.18.6.32'
        $ServeriLOUsername                = 'dcs'
        $ServeriLOPassword                = ConvertTo-SecureString -String 'dcs' -AsPlainText -Force
        $Enclosure1Address                = '172.18.1.11'
        $Enclosure1Name                   = 'Encl1'
        $Enclosure2Address                = '172.18.1.13'
        $Enclosure2Name                   = 'Encl2'
        $EnclosureUsername                = 'dcs'
        $EnclosurePassword                = ConvertTo-SecureString -String 'dcs' -AsPlainText -Force
    # endregion

    # Server Profile Region
        $Dl360Gen9ServerProfileName            = "{0}-DL360Gen9 ServerProfile" -f $PesterTestRandomName
        $Dl360Gen9TemplateName                 = "{0}-DL360Gen9 Template" -f $PesterTestRandomName
        $Dl360Gen9MLDTemplateName              = "{0}-DL360Gen9 Multiple Logical Disks Template" -f $PesterTestRandomName
        $SynergyServerProfileTemplateName      = '{0}-SY480 Server Profile Template D3940 Storage' -f $PesterTestRandomName
        $SynergyServerProfileName              = '{0}-SY480 Server Profile D3940 Storage' -f $PesterTestRandomName
        $OSDeploymentPlanName                  = 'HPE-Support 1.0-Network Deployment Test'
        $OSDeploymentServerName                = 'OSDS1'
        $Synergyi3SSPTName                     = '{0}-i3S SY480 {1} Template' -f $PesterTestRandomName, $OSDeploymentPlanName
        $ServerProfileTemplateName             = "{0}-ServerProfileTemplate" -f $PesterTestRandomName
        $ServerProfileFromTemplateName         = "{0}-ServerProfileFromTemplate" -f $PesterTestRandomName
        $BasicServerProfileName                = "{0}-BasicServerProfile" -f $PesterTestRandomName
        $AdvancedServerProfileName             = "{0}-AdvancedServerProfile" -f $PesterTestRandomName
        $BfSAdvancedServerProfileName          = "{0}-BFSAdvancedServerProfile" -f $PesterTestRandomName
        $ServerProfileScheduledFirmwareName    = "{0}-ServerProfileScheduledFirmware" -f $PesterTestRandomName
        $ServerProfileUnmanagedConnectionsName = "{0}-ServerProfileUnmanagedConnections" -f $PesterTestRandomName
        $BasicIscsiServerProfileName           = "{0}_Iscsi" -f $BasicServerProfileName
        $SANAttachIscsiServerProfileName       = "{0}_Iscsi SAN Attach" -f $BasicServerProfileName
        $IscsiServerProfileTemplateName        = "{0}_Iscsi" -f $ServerProfileTemplateName
        $Con1IscsiIPv4Address                  = '192.168.1.{0}' -f (Get-Random -Minimum 1 -Maximum 250)
        $Con1IscsiIPv4SubnetMask               = '255.255.255.0'
        $Con1IscsiBootTargetIqn                = 'iqn.1998-01.com.hp.iscsi:host1'
        $Con2IscsiIPv4Address                  = '192.168.1.{0}' -f (Get-Random -Minimum 1 -Maximum 250)
        $Con2IscsiIPv4SubnetMask               = '24'
        $Con2IscsiIPv4Gateway                  = '192.168.1.254'
        $Con2IscsiBootTargetIqn                = 'eui.0123456789ABCDEF'
        $IscsiPrimaryBootTargetAddress         = '192.168.1.251'
        $IscsiSecondaryBootTargetAddress       = '192.168.1.252'
        $IscsiAuthenticationProtocol           = 'MutualCHAP'
        $ChapName                              = 'Foo'
        $ChapSecret                            = (ConvertTo-SecureString 'ABGCACACACACACAC' -AsPlainText -Force)
        $MutualChapName                        = 'foo2'
        $MutualChapSecret                      = (ConvertTo-SecureString 'ABGCACACACACACAC' -AsPlainText -Force)
        $ServerProfileConnection1NetName       = 'VLAN 1-A'
        $ServerProfileConnection1Type          = 'Ethernet'
        $ServerProfileConnection2NetName       = 'VLAN 1-B'
        $ServerProfileConnection2Type          = 'Ethernet'
        $ServerProfileConnection3NetName       = 'Fabric A'
        $ServerProfileConnection3Type          = 'FibreChannel'
        $ServerProfileConnection4NetName       = 'Fabric B'
        $ServerProfileConnection4Type          = 'FibreChannel'
        $ServerProfileConnection5NetName       = 'Prod NetSet1 A'
        $ServerProfileConnection5Type          = 'Ethernet'
        $ServerProfileConnection6NetName       = 'Prod NetSet1 B'
        $ServerProfileConnection6Type          = 'Ethernet'
        $ServerProfileConnection7NetName       = 'Live Migration'
        $ServerProfileConnection7Type          = 'Ethernet'
        $ServerProfileConnection8NetName       = 'Live Migration'
        $ServerProfileConnection8Type          = 'Ethernet'
        $Gen9BiosSettings                      = @(
                                                @{
                                                    id = "PowerProfile";
                                                    value = "MaxPerf"
                                                },
                                                @{
                                                    id = "PowerRegulator";
                                                    value = "StaticHighPerf"
                                                },
                                                @{
                                                    id = "MinProcIdlePower";
                                                    value = "NoCStates"
                                                },
                                                @{
                                                    id = "MinProcIdlePkgState";
                                                    value = "NoState"
                                                },
                                                @{
                                                    id = "IntelQpiPowerManagement";
                                                    value = "Disabled"
                                                },
                                                @{
                                                    id = "EnergyPerfBias";
                                                    value = "MaxPerf"
                                                }
                                            )

        $NewGen9BiosSettings                   = @(
                                                @{
                                                    id = "PowerProfile";
                                                    value = "MaxPerf"
                                                },
                                                @{
                                                    id = "PowerRegulator";
                                                    value = "StaticHighPerf"
                                                },
                                                @{
                                                    id = "MinProcIdlePower";
                                                    value = "NoCStates"
                                                },
                                                @{
                                                    id = "MinProcIdlePkgState";
                                                    value = "NoState"
                                                },
                                                @{
                                                    id = "IntelQpiPowerManagement";
                                                    value = "Disabled"
                                                },
                                                @{
                                                    id = "EnergyPerfBias";
                                                    value = "MaxPerf"
                                                },
                                                @{
                                                    id = 'CustomPostMessage';
                                                    value = 'PESTER'
                                                }
                                            )

    # endregion

    # Facilities Region
        $DataCenter1Name            = '{0}-DataCenter1' -f $PesterTestRandomName
        [int]$DataCenter1Width      = 30
        [int]$DataCenter1Depth      = 30
        $DataCenter1Voltage         = 220
        $DataCenter1PowerCosts      = 0.07
        $DataCenter1CoolingCapacity = 250
        $DataCenter2Name            = '{0}-DataCenter2' -f $PesterTestRandomName
        $DataCenter2Width           = 10668
        $DataCenter2Depth           = 13716
        $DataCenter2Voltage         = 240
        $DataCenter2PowerCosts      = 0.10
        $DataCenter2CoolingCapacity = 350
        $DataCenter2Address1        = '123 Main Place'
        $DataCenter2Address2        = 'Suite 400'
        $DataCenter2City            = 'Irvine'
        $DataCenter2State           = 'California'
        $DataCenter2Country         = 'US'
        $DataCenter2Zip             = '91618'
        $DataCenter2TimeZone        = 'US/Pacific'
        $DataCenter2Contact1Name    = 'Chris Lynch'
        $DataCenter2Contact2Name    = 'Phil Marshall'
        $Rack1Name                  = '{0}-Rack1' -f $PesterTestRandomName
        $Rack1Model                 = 'HPE 42U 600mm x 1075mm Standard Pallet Rack'
        $Rack1ThermalLimit          = 10000
        $Rack1SerialNumber          = 'AABB1122CCDD'
        $Rack1PartNumber            = 'AF046A'
        $Rack1Depth                 = 1075
        $Rack1Height                = 2032
        $Rack1UHeight               = 42
        $Rack1Width                 = 600
        $Rack1XCordinate            = 5
        $Rack1YCordinate            = 12
        $Rack1UnmanagedDevice1Name = 'DL380Gen7_1-{0}' -f $PesterTestRandomName
        $Rack1UnmanagedDevice2Name = 'DL380Gen7_2-{0}' -f $PesterTestRandomName
        $Rack1UnmanagedDevice3Name = 'DL380Gen7_3-{0}' -f $PesterTestRandomName
        $Rack1UnmanagedDevice4Name = 'DL380Gen7_4-{0}' -f $PesterTestRandomName
        $Rack1UnmanagedDevice5Name = 'C3000_1-{0}' -f $PesterTestRandomName
        $Rack1UnmanagedDevice6Name = 'C3000_2-{0}' -f $PesterTestRandomName
        $Rack1UnmanagedDevice7Name = 'C3000_3-{0}' -f $PesterTestRandomName
        $Rack1UnmanagedDevices      = @(

            @{Name = $Rack1UnmanagedDevice1Name; Model = "DL380 G7"; Height = 2; MaxPower = 400},
            @{Name = $Rack1UnmanagedDevice2Name; Model = "DL380 G7"; Height = 2; MaxPower = 400},
            @{Name = $Rack1UnmanagedDevice3Name; Model = "DL380 G7"; Height = 2; MaxPower = 400},
            @{Name = $Rack1UnmanagedDevice4Name; Model = "DL380 G7"; Height = 2; MaxPower = 400},
            @{Name = $Rack1UnmanagedDevice5Name; Model = "HPE BladeSystem c3000 Enclosure"; Height = 6; MaxPower = 2800},
            @{Name = $Rack1UnmanagedDevice6Name; Model = "HPE BladeSystem c3000 Enclosure"; Height = 6; MaxPower = 2800},
            @{Name = $Rack1UnmanagedDevice7Name; Model = "HPE BladeSystem c3000 Enclosure"; Height = 6; MaxPower = 2800}

        )
        $ExistingRackName = 'Rack-221'

    # endregion

    # PowerDevice Regiion

        $PowerDevice1Address     = '172.18.8.11'
        $PowerDevice1Name        = '{0}, PDU 1' -f $PowerDevice1Address
        $PowerDevice2Address     = '172.18.8.12'
        $PowerDevice2Name        = '{0}, PDU 1' -f $PowerDevice2Address
        $PowerDevice3Address     = '172.18.8.13'
        $PowerDevice3Name        = '{0}, PDU 1' -f $PowerDevice3Address
        $PowerDevice4Address     = '172.18.8.14'
        $PowerDevice4Name        = '{0}, PDU 1' -f $PowerDevice4Address
        $PowerDeviceUsername     = 'dcs'
        $PowerDevicePassword     = 'dcs'
        $PowerDevicePSCredential = New-Object System.Management.Automation.PSCredential ($PowerDeviceUsername, (ConvertTo-SecureString -String $PowerDevicePassword -AsPlainText -Force))

    # endregion
    
# endregion

# SMOKE Tests
Describe "Perform Regression Smoke Tests: Basic authentication, unauth API calls, support file download and file upload." -Tag All, ApplianceBase, Smoke {

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Test library components" {

        It "Will verify library loads successfully" {

            #Needed for CLYNCH test lab
            if ($env:COMPUTERNAME -ne 'DESKTOP2') {

                { Import-Module $LibraryModuleName } | Should -Not -Throw

            }
        
            else {

                lsvn400

            }

            #Need to look how to stop Pester tests if this fails
            # https://github.com/pester/Pester/issues/360
            #if (-not(get-command $LibraryModuleName -ErrorAction SilentlyContinue)) { Throw 'Module not successfully loaded. Stopping all tests.' }
        
        }
    
        It "Will verify Get-Help does not generate an error" {
    
            #Needed to hide Get-Helps broken use of Write-Progress
            $OriginalProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            { Get-Help *HPOV* -Full -ErrorAction Stop | Out-Null } | Should -Not -Throw
            $ProgressPreference = $OriginalProgressPreference
    
        }

        It "Will verify random help topic does not contain null value" {

            $Commands = Get-Command -Module $LibraryModuleName -ErrorAction SilentlyContinue
            $RandomHelpTopicName = (($Commands | Where-Object CommandType -eq 'Function') | Sort-Object {Get-Random} | Select-Object -First 1).Name
            $RandomHelpTopic = Get-Help -Name $RandomHelpTopicName -Full

            if ($RandomHelpTopic.Synopsis -Match $RandomHelpTopic.Name) { 
                
                'Help Topic Name: {0}' -f $RandomHelpTopic.Name | Microsoft.PowerShell.Utility\write-host
                'Help Topic Synopsis: {0}' -f $RandomHelpTopic.Synopsis | Microsoft.PowerShell.Utility\write-host

                'Help Topic Synopsis match Name: {0}' -f ($RandomHelpTopic.Synopsis -Match $RandomHelpTopic.Name) | Microsoft.PowerShell.Utility\write-host

                Microsoft.PowerShell.Utility\write-host ('Help Topic that needs to be fixed: {0}' -f $RandomHelpTopic.Name) -ForegroundColor Yellow 
        
            }
            
            $RandomHelpTopic.Synopsis -Match $RandomHelpTopic.Name | Should -Be $false
            
        }

        It 'Will verify the $PSLibraryVersion global variable exists' {

            { Get-Variable -Name PSLibraryVersion -Scope Global -ErrorAction Stop } | Should -Not -Throw

        }

        It 'Will verify the $PSLibraryVersion object type' {

            $PSLibraryVersion | Should -BeOfType HPOneView.Library.Version

        }

        It 'Will verify the $PSLibraryVersion object version property' {

            $LibraryVersion = (Get-Module -Name $LibraryModuleName).Version
            $PSLibraryVersion.LibraryVersion | Should -Be $LibraryVersion

        }
    
    }

    Context "Will test connection to $Appliance1 using Connect-HPOVMgmt (SecureString Password)"  {

        BeforeAll {

            $Connection = Connect-HPOVMgmt -Hostname $Appliance1 -Username $ApplianceDefaultUsername -Password $AppliancePasswordSecureString -LoginAcknowledge

        }

        It 'Will validate TLS is enforced, and SSLv3 is not allowed in [System.Net.ServicePointManager]::SecurityProtocol' {

            [System.Net.ServicePointManager]::SecurityProtocol -Match 'SSLv3' | Should -Be $false

        }

        It "Will validate [HPOneView.Appliance.Connection] object type" {
            
            $Connection | Should -BeOfType HPOneView.Appliance.Connection

        }

        It "Will validate connection object contains the username" {

            $Connection.Username | Should -Be $ApplianceDefaultUsername

        }   

        It "Will validate connection object contains a SessionID" {

            $Connection.SessionID | Should -Not -BeNullOrEmpty

        }

        It "Will validate the connection object contains ActivePermissions property and data type" {

            $Connection.ActivePermissions -is [System.Collections.IEnumerable] | Should -Be $true
            $Connection.ActivePermissions.Count | Should -Be 1
            $Connection.ActivePermissions[0] -is [HPOneView.Appliance.ConnectionPermission] | Should -Be $true
            $Connection.ActivePermissions[0].Active | Should -BeOfType System.Boolean

        }

        It "Will validate the connection object contains ApplianceSecurityRoles property and data type" {

            $Connection.ApplianceSecurityRoles -is [System.Collections.IEnumerable] | Should -Be $true
            $Connection.ApplianceSecurityRoles.Count | Should -BeGreaterThan 1
            $Connection.ApplianceSecurityRoles[0] | Should -BeOfType System.String

        }

        It "Will validate connection exists in the Global `$ConnectedSession tracker variable" {
            
            $ConnectedSessions | Where-Object Name -eq $Connection.Name | Should -BeOfType HPOneView.Appliance.Connection
            
        }

        It "Will validate PSLibraryVersion contains the connected appliance" {

            $PSLibraryVersion.$Appliance1 | Should -BeOfType HPOneView.Appliance.NodeInfo

        }

        It "Will validate PSLibraryVersion contains the connected appliance version object" {

            $PSLibraryVersion.$Appliance1.ApplianceVersion | Should -BeOfType HPOneView.Appliance.Version

        }

        It "Will disconnect from Appliance" {

            { $Script:AfterConnectionTerminated = Disconnect-HPOVMgmt -Hostname $Connection -ErrorAction Stop } | Should -Not -Throw
            $AfterConnectionTerminated | Should -BeNullOrEmpty

        }

    }
    
    Context "Will test connection to $Appliance1 using Connect-HPOVMgmt (PSCredential)"  {

        BeforeAll {

            { $Script:PSCredentialConnection = Connect-HPOVMgmt -Hostname $Appliance1 -PSCredential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        It "Will validate [HPOneView.Appliance.Connection] object type" {
            
            $PSCredentialConnection | Should -BeOfType HPOneView.Appliance.Connection

        }

        It "Will validate connection object contains a SessionID" {

            $PSCredentialConnection.SessionID | Should -Not -BeNullOrEmpty

        }   

        It "Will validate connection exists in the Global `$ConnectedSession tracker variable" {
            
            $PSCredentialConnection | Where-Object Name -eq $PSCredentialConnection.Name | Should -BeOfType HPOneView.Appliance.Connection
            
        }   

        It "Will disconnect from Appliance" {

            { $Script:AfterConnectionTerminated = Disconnect-HPOVMgmt -Hostname $PSCredentialConnection -ErrorAction Stop } | Should -Not -Throw
            $AfterConnectionTerminated | Should -BeNullOrEmpty

        } 

    }

    Context "Test multiple appliance connections and `$ConnectedSessions global variable" {

        $_Count = 0

        It "Will initiate connection to first appliance, $Appliance1" {

            $ConnectedSessions | Should -BeNullOrEmpty

            $Global:Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge

            $_Count++

            $Connection1 | Should -BeOfType HPOneView.Appliance.Connection
            $Connection1.Name | Should -Be $Appliance1
            $Connection1.SessionID | Should -Not -BeNullOrEmpty
            $Connection1.ConnectionID | Should -BeExactly 1

        }

        It "Will initiate connection to second appliance, $Appliance2" {

            $ConnectedSessions | Should -Not -BeNullOrEmpty

            $Global:Connection2 = Connect-HPOVMgmt -Hostname $Appliance2 -Credential $AppliancePSCredential -LoginAcknowledge
            $Connection2 | Should -BeOfType HPOneView.Appliance.Connection
            $Connection2.SessionID | Should -Not -BeNullOrEmpty
            $Connection2.ConnectionID | Should -BeExactly 2

        }

        It "Will get appliance version from Connection1" {

            $Appliance1Version = Send-HPOVRequest /rest/version -Hostname $Global:Connection1
            $Appliance1Version | Should -Not -BeNullOrEmpty
            $Appliance1Version.minimumVersion | Should -BeExactly 120

        }

        It "Will get appliance version from Connection2" {

            $Appliance2Version = Send-HPOVRequest /rest/version -Hostname $Global:Connection2
            $Appliance2Version | Should -Not -BeNullOrEmpty
            $Appliance2Version.minimumVersion | Should -BeExactly 120

        }

        It "Will get appliance version from both connections" {

            $AllApplianceVersion = Send-HPOVRequest /rest/version -Hostname $Global:Connection1,$Global:Connection2
            $AllApplianceVersion | Should -Not -BeNullOrEmpty

            $_c = 0

            ForEach ($_Result in $AllApplianceVersion) {

                $_Result.ApplianceConnection.Name | Should -BeExactly $ConnectedSessions[$_c].Name
                $_Result.minimumVersion | Should -BeExactly 120

                $_c++

            }            

        }

        It 'Will tear down all established connections' {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

            $ConnectedSessions.Count | Should -Be 0 

        } 

    }

    Context "Test removing connection using Disconnect-HPOVMgmt" {

        BeforeEach {

            if (-not($ConnectedSessions)) {

                Write-Output 'No appliance connections. Initiating one.'

                $Connection = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge

            }        

        }

        It "Will disconnect an appliance connection" {

            $Connection | Should -BeOfType HPOneView.Appliance.Connection
            { $script:DisconnectState = Disconnect-HPOVMGmt $Connection -ErrorAction Stop } | Should -Not -Throw
            $DisconnectState | Should -BeNullOrEmpty
            $ConnectedSessions | Should -BeNullOrEmpty

        }

    }

    Context "Test IPv6 Appliance Connection to $IPv6Appliance1" {

        It "Will connect to '$IPv6Appliance1' using its IPv6 Address" {

            { $Script:IPv6Connection = Connect-HPOVMgmt -Hostname $IPv6Appliance1 -Credential $AppliancePSCredential } | Should -Not -Throw

        }

        It "Will validate ApplianceConnection is of type [HPOneView.Appliance.Connection]" {

            $IPv6Connection | Should -BeOfType HPOneView.Appliance.Connection

        }

        It "Will validate ApplianceConnection contains a Session ID" {

            $IPv6Connection.SessionID | Should -Not -BeNullOrEmpty

        }

        It "Will validate ApplianceConnection contains the correct Hostname" {

            $IPv6Connection.Name | Should -Be $IPv6Appliance1

        }

        It "Will validate API call succeeds (GET /rest/version)" {

            { Send-HPOVRequest /rest/version } | Should -Not -Throw

        }

        It "Will disconnect from Appliance" {

            { Disconnect-HPOVMgmt $IPv6Connection -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Use Send-HPOVRequest to interact with the API" {

        BeforeAll {

            If ($ConnectedSessions) {

                Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop | Out-Null

            }

        }

        AfterAll {

            If ($ConnectedSessions) {

                Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop | Out-Null

            }

        }

        It "Will fail API call (/rest/version) with no appliance connection" {

            { Send-HPOVRequest -uri /rest/version } | Should -Throw 'No appliance Hostname Parameter provided and no valid appliance session(s) found.'

        }

        It "Will connect to appliance, and get version (/rest/version)" {

            { Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw
            { $Script:Resp = Send-HPOVRequest -uri /rest/version } | Should -Not -Throw
            $Resp | Should -Not -BeNullOrEmpty
            $resp.currentVersion | Should -BeExactly 600

        }

        It "Will validate returned objects contain ApplianceConnection property and is of type HPOneView.Library.ApplianceConnection" {

            { $Script:HPOVVersion = Send-HPOVRequest -uri /rest/version } | Should -Not -Throw
            $HPOVVersion.ApplianceConnection | Should -BeOfType HPOneView.Library.ApplianceConnection
            $HPOVVersion.ApplianceConnection.Name | Should -Not -BeNullOrEmpty
            $HPOVVersion.ApplianceConnection.ConnectionID | Should -Not -BeNullOrEmpty

        }

    }

    Context "Test unauthenticated Cmdlets" {

        AfterAll {

            { Disconnect-HPOVMgmt -ErrorAction Stop } | Should -Not -Throw

        }

        it "Will get appliance EULA Status with Valid IP Address, no existing connection" {

            { $Script:ApplianceEulaStatus = Get-HPOVEulaStatus -Appliance $Appliance1IPv4 } | Should -Not -Throw
            $ApplianceEulaStatus | Should -Not -BeNullOrEmpty

        }

        It "Will get appliance EULA Status with valid FQDN, no existing connection" {
            
            $Script:ApplianceEulaStatus = $null
            { $Script:ApplianceEulaStatus = Get-HPOVEulaStatus -Appliance $Appliance1 } | Should -Not -Throw
            $ApplianceEulaStatus | Should -Not -BeNullOrEmpty

        }

        It "Will generate Exception by getting appliance EULA Status with Invalid FQDN (invalid.domain.local)" {

            $ExpectedExceptionMessage = 'The remote name could not be resolved'
            
            { Get-HPOVEulaStatus -Appliance invalid.domain.local } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will successfully get appliance EULA Status and validate object type with Valid Appliance Connection object" {

            $Connection = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge

            { Get-HPOVEulaStatus -Appliance $Connection } | Should -Not -BeNullOrEmpty
            (Get-HPOVEulaStatus -Appliance $Connection) -is [HPOneView.Appliance.EulaStatus] | Should -Be $true #`OfType [HPOneView.Appliance.EulaStatus]

        }

    } 

    Context "Test Unauthorized Calls"  {

        BeforeAll {

            If ($ConnectedSessions) {

                { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

            }

        }

        AfterAll {

            If ($ConnectedSessions) {

                { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

            }

        }

        it "Will attempt connection with invalid user account" {

            $ExpectedExceptionMessage = 'Invalid username or password or directory. Enter correct credentials and try again. To obtain a username or password, contact your administrator.'
            
            { Connect-HPOVMgmt -Hostname $Appliance1 -Username Foo -Password Bar -LoginAcknowledge } | Should -Throw $ExpectedExceptionMessage

        }

        it "Will connect with under privledged user account (Sally) and throw exception user attempted unauthorized API call" {

            { Connect-HPOVMgmt -Hostname $Appliance1 -Username Sally -Password $CommonPassword -LoginAcknowledge } | Should -Not -Throw

            $ExpectedExceptionMessage = 'User not authorized for this operation'
            
            { Send-HPOVRequest /rest/users } | Should -Throw $ExpectedExceptionMessage

            Remove-Variable -Name ExpectedExceptionMessage

        }

    }

    Context "Download Appliance Support Files" {

        BeforeAll {

            #Establish appliance connection
            If (-not($ConnectedSessions)) {

                { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

            }

            $RemoteBackupPublicKey | Set-Content TestDrive:\BackupHost_PublicKey.pub -Confirm:$false

        }

        It 'Will create and download Appliance Backup' {

            { $Script:BackupFileResults = New-HPOVBackup -Location $TestDrive -Force } | Should -Not -Throw

        }

        It 'Will validate the downloaded appliance backup file' {
            
            $BackupFileResults | Should -Exist
            $BackupFileResults.Length | Should -BeGreaterThan 0

        }

        It "Will save the generated backup file" {

            if (Test-Path $BackupFileResults) {

                Remove-Item -Path $BackupFileResults.FullName -Confirm:$false
                
            }

            { $Script:SavedBackupFileResults = Save-HPOVBackup -Location $TestDrive } | Should -Not -Throw

        }

        It "Will validate saved backup file exists" {

            $SavedBackupFileResults | Should -Exist
            $SavedBackupFileResults.Length | Should -BeGreaterThan 0

        }

        It "Will configure appliance automated backup configuration" {
        
            { $Script:AutomatedBackupConfigResults = Set-HPOVAutomaticBackupConfig -Hostname $RemoteBackupHostname -Username $RemoteBackupUsername -Password $RemoteBackupPassword -HostSSHKey (Get-Content TestDrive:\BackupHost_PublicKey.pub -ErrorAction Stop) -Protocol SCP -Interval Daily -Time 20:00 } | Should -Not -Throw
            $AutomatedBackupConfigResults | Should -Not -BeNullOrEmpty
            $AutomatedBackupConfigResults.category | Should -Be tasks
            $AutomatedBackupConfigResults.taskState | Should -Be Completed
        
        }

        It "Will disable appliance automated backup configuration" {
        
            { $Script:AutomatedBackupConfigResults = Set-HPOVAutomaticBackupConfig -Disabled -Confirm:$false } | Should -Not -Throw
            $AutomatedBackupConfigResults | Should -Not -BeNullOrEmpty
            $AutomatedBackupConfigResults.category | Should -Be tasks
            $AutomatedBackupConfigResults.taskState | Should -Be Completed
        
        }

        It 'Will create and download Appliance Support Dump' {

            { $Script:SupportDumpFileResults = New-HPOVSupportDump -Type Appliance -Location $TestDrive } | Should -Not -Throw

        }

        It 'Will validate the downloaded Appliance Support Dump file' {

            $SupportDumpFileResults.File | Should -Exist

        }

    }

    Context "Appliance DateTime" {

        It "Will get the appliance datetime" {

            { $script:ApplianceDateTime = Get-HPOVApplianceDateTime } | Should -Not -Throw

        }

        It "Will validate appliance date time object type" {

            $ApplianceDateTime | Should -BeOfType HPOneView.Appliance.ApplianceLocaleDateTime
            
        }

        It "Will validate appliance date time object properties are not empty" {
            
            $ApplianceDateTime.Locale | Should -BeOfType System.String
            $ApplianceDateTime.Locale | Should -Not -BeNullOrEmpty

            $ApplianceDateTime.TimeZone | Should -BeOfType System.String
            $ApplianceDateTime.TimeZone | Should -Not -BeNullOrEmpty

            $ApplianceDateTime.DateTime | Should -BeOfType System.DateTime
            $ApplianceDateTime.DateTime | Should -Not -BeNullOrEmpty

            if ($ApplianceDateTime.NtpServers.Count -gt 1) {

                $ApplianceDateTime.NtpServers | Should -BeOfType System.String

            }

            else {

                $ApplianceDateTime.NtpServers | Should -BeOfType System.Collections.IList

            }            

            $ApplianceDateTime.SyncWithHost | Should -BeOfType System.Boolean
            $ApplianceDateTime.SyncWithHost | Should -Not -BeNullOrEmpty

            $ApplianceDateTime.LocaleDisplayName | Should -BeOfType System.String
            $ApplianceDateTime.LocaleDisplayName | Should -Not -BeNullOrEmpty

        }

    }

    Context "Validate dashboard launcher" {

        $PSDefaultParameterValues = @{ 'It:Skip' = $LabPC }

        It "Will validate the PC default browser $($PCDefaultWebBrowser.Name) will be launched with the default appliance connection" {

            #Tear down existing default browser process
            Get-Process -Name $PCDefaultWebBrowser.ProcessName -ErrorAction SilentlyContinue | Stop-Process

            { Invoke-HPOVWebBrowser } | Should -Not -Throw

            #Validate the process has started
            { Get-Process -Name $PCDefaultWebBrowser.ProcessName -ErrorAction Stop } | Should -Not -Throw

            #Tear it down again
            Get-Process -Name $PCDefaultWebBrowser.ProcessName -ErrorAction SilentlyContinue | Stop-Process

        }

    }

    Context "Validate support Cmdlets" {

        It "Will execute Get-HPOVCommandTrace and capture output" {

            { $Script:LogFile = Get-HPOVCommandTrace { Get-HPOVNetwork } -Location $TestDrive\ 4> $TestDrive\cmdlet_verbose.trace } | Should -Not -Throw

        }

        It "Will validate log file is created by the Cmdlet" {

            $LogFile | Should -BeOfType [System.IO.FileInfo]
            $LogFile | Should -Exist

        }
        
    }

}

# APPLIANCE BASE, Certificate Management
Describe "Appliance base tests: Licensing, Certificate and SCMB" -Tag All, ApplianceBase, ApplianceCertificateManagement {

    BeforeAll {
        
        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow 

        if (-not (Get-HPOVApplianceTrustedCertificate -Name $DC1CACononicalName -ErrorAction SilentlyContinue))
        {

            Microsoft.PowerShell.Utility\write-host ('Appliance does not contain the Enterprise Issuing CA cert in appliance trusted store.  Adding.' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow 

            Add-HPOVApplianceTrustedCertificate -Path $DC1CACertificate

        }

        if (Get-ChildItem Cert:\CurrentUser\My | Where-Object FriendlyName -eq $TrustedCertificateFriendlyName)
        {

            Get-ChildItem Cert:\CurrentUser\My | Where-Object FriendlyName -eq $TrustedCertificateFriendlyName | Remove-Item -Confirm:$false
            
        }

        $Certificate = New-SelfSignedCertificate -DnsName $TrustedCertificateDnsName, $TrustedCertificateDnsName2 -KeyFriendlyName $TrustedCertificateFriendlyName -FriendlyName $TrustedCertificateFriendlyName -Type SSLServerAuthentication -CertStoreLocation cert:\CurrentUser\My

        Export-Certificate -Cert $Certificate -FilePath $TestDrive\TestCert.cer

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "License Management tasks" {

        It "Will get installed licenses on the appliance" {

            { $Script:ApplianceLicenses = Get-HPOVLicense } | Should -Not -Throw
            $ApplianceLicenses | Should -Not -BeNullOrEmpty

        }

        It "Will validate the base class object [HPOneView.Appliance.License]" {

            $ApplianceLicenses | Should -BeOfType HPOneView.Appliance.License

        }

        It "Will validate the licensed nodes child property object [HPOneView.Appliance.LicensedNode]" {

            $ApplianceLicenses.Nodes[0] | Should -BeOfType HPOneView.Appliance.LicensedNode

        }

    }

    Context "Create and Manage RabbitMQ (SCMB/MSMB) certificates" {
        
        BeforeAll {

            #Establish appliance connection
            If (-not($ConnectedSessions)) {

                { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

            }  

        }

        AfterAll {

            Start-Sleep -Seconds 20
            
        }

        It "Will create RabbitMQ certificates" -skip {
        
            { Get-HPOVScmbCertificates -Location $TestDrive } | Should -Not -Throw
        
        }

        It "Will validate Appliance Root Certificate file exists" -skip  {
        
            $RootCaFile = "$TestDrive\{0}_ca.cer" -f $Appliance1

            Test-Path -Path $RootCaFile -PathType Leaf | Should -Be $true
        
        }

        It "Will validate SCMB rabbit_readonly Certificate file exists" -skip  {
        
            $RabbitMQUserCertFile = "$TestDrive\{0}_cert.cer" -f $Appliance1

            Test-Path -Path $RabbitMQUserCertFile -PathType Leaf | Should -Be $true
        
        }

        It "Will validate SCMB rabbit_readonly Private Key file exists" -skip  {
        
            $RabbitMQUserPrivateKeyFile = "$TestDrive\{0}_privateKey.key" -f $Appliance1

            Test-Path -Path $RabbitMQUserPrivateKeyFile -PathType Leaf | Should -Be $true
        
        }

        It "Will create RabbitMQ certificates with PFX/Pkcs12 certificate file" -skip  {
        
            { Get-HPOVScmbCertificates -Location $TestDrive -ConvertToPFx -Password (ConvertTo-SecureString -String $CommonPassword -AsPlainText -Force)} | Should -Not -Throw
        
        }

        It "Will validate SCMB rabbit_readonly PFX file exists" -skip  {
        
            $RabbitMQUserPrivateKeyFile = "$TestDrive\{0}_privateKey.pfx" -f $Appliance1

            Test-Path -Path $RabbitMQUserPrivateKeyFile -PathType Leaf | Should -Be $true
        
        }

        It "Will remove created SCMB certificate key pair" -skip {
        
            { $Script:RemoveResult = Remove-HPOVScmbCertificate -Confirm:$false } | Should -Not -Throw
            $RemoveResult | Should -Not -BeNullOrEmpty
            $RemoveResult.Message | Should -Be 'Resource deleted successfully.'
        
        }

    }

    Context "Manage trusted SSL certificates" {

        It "Will validate Certificate doesn't -Exist on the appliance" {

            $CertExpectedExceptionMessage = "The specified '{0}' trusted SSL certificate resource not" -f $TrustedCertificateFriendlyName 
            { Get-HPOVApplianceTrustedCertificate -Name $TrustedCertificateFriendlyName -ErrorAction Stop } | Should -Throw $CertExpectedExceptionMessage

        }

        It "Will add the untrusted SSL cert to the appliance trusted store" {

            { $Script:Results = Add-HPOVApplianceTrustedCertificate -Path "$TestDrive\TestCert.cer" -AliasName $TrustedCertificateFriendlyName -force } | Should -Not -Throw

            $Results.category | Should -Be 'tasks'

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will validate the certificate exists on the appliance" {

            { Get-HPOVApplianceTrustedCertificate -Name $TrustedCertificateFriendlyName -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will remove the certificate from the appliance" {

            { $Script:Results = Get-HPOVApplianceTrustedCertificate -Name $TrustedCertificateFriendlyName -ErrorAction Stop | Remove-HPOVApplianceTrustedCertificate -Confirm:$false } | Should -Not -Throw

            # $Results.Message | Should -Be "Resource deleted successfully."
            $Results.category | Should -Be 'tasks'
            
            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will add HTTPS certificate using the ComputerName and Port parameters" {

            { $script:Resp = Add-HPOVApplianceTrustedCertificate -ComputerName $RemoteBackupHostname -Port 443 -AliasName fileserver_test } | Should -Not -Throw

            $Results = [String]::Join(',',$resp.progressUpdates.statusUpdate)

            $Results | Should Match 'CA that has issued the certificate is already trusted'

        }

        # It "Will remove the certificate from the appliance" {

        #     { $Script:Results = Get-HPOVApplianceTrustedCertificate -Name fileserver_test -ErrorAction Stop | Remove-HPOVApplianceTrustedCertificate -Confirm:$false } | Should -Not -Throw

        #     $Results.Message | Should -Be "Resource deleted successfully."

        # }


    }

    Context "Manage appliance advanced certificate settings" {

        BeforeAll {

            if (-not (Get-HPOVLdapDirectory -Name *-2FA -ErrorAction SilentlyContinue)){

                $DC1Object = New-HPOVLdapServer -Name $DC1
                $DC2Object = New-HPOVLdapServer -Name $DC2
                $LdapDirResults = New-HPOVLdapDirectory -Name "Doctors-Lab.local-2FA" -AD -BaseDN "dc=doctors-lab,dc=local" -Servers $DC1Object, $DC2Object -Credential $LdapPSPSCredential -ServiceAccount
    
                $LdapGroups = Get-HPOVLdapDirectory -Name "Doctors-Lab.local-2FA" -ErrorAction Stop | Show-HPOVLdapGroups -Credential $LdapPSPSCredential

                # Add 'Server Admins' Directory Group
                $ServerAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Server'
                
                New-HPOVLdapGroup -Directory $LdapDirResults -Group $ServerAdminGroup -Roles 'Server Administrator' -Credential $LdapPSPSCredential

            }

        }

        It "Will disable certificate validation using -WhatIf" {

            { Disable-HPOVCertificateValidation -WhatIf -ErrorAction Stop } | Should -Not -Throw

        }

        # A directory without a service account hasn't been configued by default.  Should I create one for testing?
        It "Will enable Two Factor authentication, and attempt to disable certificate validation" -Skip {

            $_Uri = '/rest/logindomains/global-settings'
            $CurrentConfig = Send-HPOVRequest -Uri $_Uri
            $CurrentConfig.twoFactorAuthenticationEnabled = $true
            Send-HPOVRequest -Uri $_Uri -Method PUT -Body $CurrentConfig | Out-Null

            $ExpectedExceptionMessage = 'Certificate validation or revocation cannot be disabled as two-factor authentication is enabled.  Turn off two-factor authentication to disable certificate validation or revocation.'

            { Disable-HPOVCertificateValidation -WhatIf -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage

            $CurrentConfig = Send-HPOVRequest -Uri $_Uri
            $CurrentConfig.twoFactorAuthenticationEnabled = $false
            Send-HPOVRequest -Uri $_Uri -Method PUT -Body $CurrentConfig | Out-Null

        }

        It "Will enable certificate validation using -WhatIf" {

            { Enable-HPOVCertificateValidation -WhatIf } | Should -Not -Throw

        }

        It "Will enable certificate validation and enable CheckForSelfSignedExpiry using -WhatIf" {

            { Enable-HPOVCertificateValidation -CheckForSelfSignedExpiry $true -WhatIf } | Should -Not -Throw

        }

        It "Will enable certificate validation and disable CheckForSelfSignedExpiry using -WhatIf" {

            { Enable-HPOVCertificateValidation -CheckForSelfSignedExpiry $false -WhatIf } | Should -Not -Throw

        }

    }

}

# APPLIANCE BASE, Directory auth
Describe "Active Directory (LDAP) configuration and auth" -Tag All, ApplianceBase, DirectoryAuthentication {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow 

        if (-not (Get-HPOVApplianceTrustedCertificate -Name $DC1CACononicalName -ErrorAction SilentlyContinue))
        {

            Microsoft.PowerShell.Utility\write-host ('Appliance does not contain the Enterprise Issuing CA cert in appliance trusted store.  Adding.' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow 

            Add-HPOVApplianceTrustedCertificate -Path $DC1CACertificate

        }

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Configure Active Directory Provider (IPv4) on appliance" {

        It "Will attempt invalid Directory Server object (Foo.Bar)" {

            { New-HPOVLdapServer -Name Foo.Bar -TrustLeafCertificate } | Should -Throw "The remote name could not be resolved: 'foo.bar' Please check the spelling of the hostname or FQDN."

        }

        It "Will attempt invalid directory server object with incorrect SSLPort value (6366)" {

            { New-HPOVLdapServer -Name $DC1 -SslPort 6366 -TrustLeafCertificate } | Should -Throw "Unable to connect to the remote server. Valid Ssl Port or firewall blocking port?"

        }

        It "Will create Directory Server object for Active Directory SRV Records" {

            { $Script:DC1Object = New-HPOVLdapServer -Name $DirectoryDomainName } | Should -Not -Throw
            $DC1Object.directoryServerIpAddress | Should -Be $DirectoryDomainName
            $DC1Object.directoryServerCertificateBase64Data | Should -BeNullOrEmpty

        }

        It "Will create '$LdapIPv4DirectoryName' Authentication Directory" {

            { $Script:LdapDirResults = New-HPOVLdapDirectory -Name $LdapIPv4DirectoryName -AD -BaseDN "dc=doctors-lab,dc=local" -Servers $DC1Object -Username $LdapUser -Password $LdapSecurePassword } | Should -Not -Throw

            $LdapDirResults.authProtocol | Should -Be 'AD'
            $LdapDirResults.name | Should -Be $LdapIPv4DirectoryName
            $LdapDirResults.directoryServers.Count | Should -Be 1

        }

        It "Will retrieve LDAP Groups" {

            { $Script:LdapGroups = Get-HPOVLdapDirectory -Name $LdapIPv4DirectoryName -ErrorAction Stop | Show-HPOVLdapGroups -Username $LdapUser -Password $LdapSecurePassword } | Should -Not -Throw

            $LdapGroups.Count | Should -BeGreaterThan 0

        }

        It "Will add 'Infrastructure Admins' Directory Group" {

            $InfrastructureAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Full'

            $InfrastructureAdminGroup | Should -Not -BeNullOrEmpty

            $InfrastructureAdminGroup | Should -BeOfType HPOneView.Appliance.LdapDirectoryGroup

            { $Script:InfraAdminDirGroupResults = New-HPOVLdapGroup -Directory $LdapDirResults -Group $InfrastructureAdminGroup -Roles 'Infrastructure Administrator' -Credential $LdapPSPSCredential } | Should -Not -Throw

            $InfraAdminDirGroupResults | Should -Not -BeNullOrEmpty

            $InfraAdminDirGroupResults.type | Should -Be 'LoginDomainGroupPermission'

            $InfraAdminDirGroupResults.permissions.count | Should -Be 1

            $InfraAdminDirGroupResults.loginDomain | Should -Be $LdapIPv4DirectoryName

        }

        It "Will add 'Server Admins' Directory Group via it's DN value [#146]" {

            $ServerAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Server'

            $ServerAdminGroup | Should -Not -BeNullOrEmpty

            $ServerAdminGroup | Should -BeOfType HPOneView.Appliance.LdapDirectoryGroup

            $ServerAdminGroup.DN -match $CommonNamePattern | Should -Be $true

            { New-HPOVLdapGroup -Directory $LdapDirResults -Group $ServerAdminGroup.DN -Roles 'Server Administrator' -Credential $LdapPSPSCredential } | Should -Not -Throw

        }

        It "Will add 'Storage Admins' Directory Group" {

            $StorageAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Storage'

            $StorageAdminGroup | Should -Not -BeNullOrEmpty

            $StorageAdminGroup | Should -BeOfType HPOneView.Appliance.LdapDirectoryGroup

            { New-HPOVLdapGroup -Directory $LdapDirResults -Group $StorageAdminGroup -Roles 'Storage Administrator' -Credential $LdapPSPSCredential } | Should -Not -Throw

        }

        It "Will add 'Network Admins' Directory Group" {

            $NetworkAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Network'

            $NetworkAdminGroup | Should -Not -BeNullOrEmpty

            $NetworkAdminGroup | Should -BeOfType HPOneView.Appliance.LdapDirectoryGroup

            { New-HPOVLdapGroup -Directory $LdapDirResults -Group $NetworkAdminGroup -Roles 'Network Administrator' -Credential $LdapPSPSCredential } | Should -Not -Throw

        }

        It "Will attempt to disable Local Login" {
        
            $ExpectedExceptionMessage = 'To disable local login you must log in using another authentication service.'
            
            { Disable-HPOVLdapLocalLogin } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will disconnect from Appliance" {

            { Disconnect-HPOVMgmt -Hostname $Appliance1 -ErrorAction Stop } | Should -Not -Throw

            $ConnectedSessions.Count | Should -Be 0

        }

        It "Will attempt to connect with invalid Directory User account" {

            { Connect-HPOVMgmt -Hostname $Appliance1 -Username $InvalidLdapUserUpn -Password $LdapSecurePassword -AuthLoginDomain $LdapIPv4DirectoryName } | Should -Throw 'Invalid username or password. Enter correct credentials and try again. To obtain a username or password, contact your administrator.'

        }

        It "Will attempt to connect with valid AD User Account without Role Mapping" {

            $ExpectedException = "No member groups found for the user in the external directory server(s). Provide a valid user credentials."
            { Connect-HPOVMgmt -Hostname $Appliance1 -Username Doctors-Lab\ldapuser -Password $LdapSecurePassword -AuthLoginDomain $LdapIPv4DirectoryName } | Should -Throw $ExpectedException

        }

        It "Will connect with valid User Account using UPN" {

            { Connect-HPOVMgmt -Hostname $Appliance1 -Username $InfraAdminUserUpn -Password $LdapSecurePassword -AuthLoginDomain $LdapIPv4DirectoryName } | Should -Not -Throw
            { Get-HPOVNetwork -ErrorAction Stop } | Should -Not -BeNullOrEmpty
            { Disconnect-HPOVMgmt -Hostname $Appliance1 -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will connect with valid User Account using NtSamAccountName" {

            { Connect-HPOVMgmt -Hostname $Appliance1 -Username $InfraAdminUserNt -Password $LdapSecurePassword -AuthLoginDomain $LdapIPv4DirectoryName } | Should -Not -Throw
            
        }

        It "Will attempt to disable local logins without first changing the default login directory" {
        
            $ExpectedExceptionMessage = 'The Default Login Domain must not be set to "LOCAL" before disabling Local Logins.'
            
            { Disable-HPOVLdapLocalLogin } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will set the default login domain to '$LdapIPv4DirectoryName'" {
        
            { Get-HPOVLdapDirectory -Name $LdapIPv4DirectoryName -ErrorAction Stop | Set-HPOVLdapDefaultDirectory -Confirm:$false } | Should -Not -Throw
        
        }

        It "Will disable local logins" {
        
            { $Script:DisableLocalLoginResults = Disable-HPOVLdapLocalLogin -Confirm:$false } | Should -Not -Throw
            $DisableLocalLoginResults | Should -Not -BeNullOrEmpty
            $DisableLocalLoginResults.allowLocalLogin | Should -Be $false
        
        }

        It "Will log off and attempt to log in with Local User account" {
        
            { Disconnect-HPOVMgmt -ErrorAction Stop } | Should -Not -Throw

            $ExpectedExceptionMessage = 'Invalid username or password.'
            
            { Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will log on with Directory User and reset Default Directory settings" {
        
            { Connect-HPOVMgmt -Hostname $Appliance1 -Username $InfraAdminUserNt -Password $LdapSecurePassword -AuthLoginDomain $LdapIPv4DirectoryName -LoginAcknowledge } | Should -Not -Throw
            { $Script:DisableLocalLoginResults = Enable-HPOVLdapLocalLogin -Confirm:$false } | Should -Not -Throw
            $DisableLocalLoginResults | Should -Not -BeNullOrEmpty
            $DisableLocalLoginResults.allowLocalLogin | Should -Be $true

            { $Script:SetLocalDefaultDirectoryResults = Set-HPOVLdapDefaultDirectory -InputObject LOCAL -Confirm:$false } | Should -Not -Throw
            $SetLocalDefaultDirectoryResults | Should -Not -BeNullOrEmpty
            $SetLocalDefaultDirectoryResults.allowLocalLogin | Should -Be $true
            $SetLocalDefaultDirectoryResults.defaultLoginDomain.loginDomain | Should -Be 0
            $SetLocalDefaultDirectoryResults.defaultLoginDomain.name | Should -Be LOCAL
        
        }

        It "Will remove LDAP Directory Groups" {

            { Disconnect-HPOVMgmt -ErrorAction Stop } | Should -Not -Throw

            { Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

            { $Script:LdapGroupResults = Get-HPOVLdapGroup | Where-Object loginDomain -eq $LdapIPv4DirectoryName | Remove-HPOVLdapGroup -Confirm:$false } | Should -Not -Throw
            $LdapGroupResults.count | Should -Be 4

            $LdapGroupResults[0].Message -eq "Resource deleted successfully." | Should -Be $true
            $LdapGroupResults[1].Message -eq "Resource deleted successfully." | Should -Be $true
            $LdapGroupResults[2].Message -eq "Resource deleted successfully." | Should -Be $true
            $LdapGroupResults[3].Message -eq "Resource deleted successfully." | Should -Be $true 

        }

        It "Will remove Ldap Directory " {

            { Disconnect-HPOVMgmt -ErrorAction Stop } | Should -Not -Throw
            { Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw
            { $Script:RemoveLdapDirResults = Get-HPOVLdapDirectory -Name $LdapIPv4DirectoryName -ErrorAction Stop | Remove-HPOVLdapDirectory -Confirm:$false } | Should -Not -Throw
            $RemoveLdapDirResults.Message -eq "Resource deleted successfully." | Should -Be $true 

        }

    }

    Context "Configure Active Directory Provider (IPv6) on appliance using Service Account and PSCredential" {

        It "Create Directory Server Object for DC1 (IPv6)" {

            { $Script:DC1Object = New-HPOVLdapServer -Name $DC1IPv6 -TrustLeafCertificate } | Should -Not -Throw
            $DC1Object.directoryServerIpAddress | Should -Be $DC1IPv6
            $DC1Object.directoryServerCertificateBase64Data | Should -Not -BeNullOrEmpty

        }

        It "Create Directory Server Object for DC2 (IPv6)" {

            { $Script:DC2Object = New-HPOVLdapServer -Name $DC2IPv6 -TrustLeafCertificate } | Should -Not -Throw
            $DC2Object.directoryServerIpAddress | Should -Be $DC2IPv6
            $DC2Object.directoryServerCertificateBase64Data | Should -Not -BeNullOrEmpty

        }

        It "Create '$LdapIPv6DirectoryName' Authentication Directory using PSCredential and setting ServiceAccount mode" {

            { $Script:LdapDirResults = New-HPOVLdapDirectory -Name $LdapIPv6DirectoryName -AD -BaseDN "dc=doctors-lab,dc=local" -Servers $DC1Object,$DC2Object -Credential $LdapPSPSCredential -ServiceAccount } | Should -Not -Throw

            $LdapDirResults.authProtocol | Should -Be 'AD'
            $LdapDirResults.name | Should -Be $LdapIPv6DirectoryName
            $LdapDirResults.directoryServers.Count | Should -Be 2
            $LdapDirResults.directoryBindingType | Should -Be 'SERVICE_ACCOUNT'

        }

        It "Will remove '$DC2IPv6' from '$LdapIPv6DirectoryName' directory configuration with PSCredential" {
        
            { $Script:RemoveResults = Get-HPOVLdapDirectory -Name $LdapIPv6DirectoryName -ErrorAction Stop | Remove-HPOVLdapServer -Name $DC2IPv6 -Credential $LdapPSPSCredential -Confirm:$False } | Should -Not -Throw
            $RemoveResults.directoryServers.Count | Should -Be 1
        
        }

        It "Will add '$DC2IPv6' back into '$LdapIPv6DirectoryName' directory configuration with PSCredential" {
        
            { $Script:AddResults = Get-HPOVLdapDirectory -Name $LdapIPv6DirectoryName -ErrorAction Stop | Add-HPOVLdapServer -Name $DC2IPv6 -TrustLeafCertificate -Credential $LdapPSPSCredential } | Should -Not -Throw
            $AddResults.directoryServers.Count | Should -Be 2
        
        }

        It "Retrieve LDAP Groups without explicit authentication" {

            { $Script:LdapGroups = Get-HPOVLdapDirectory -Name $LdapIPv6DirectoryName -ErrorAction Stop | Show-HPOVLdapGroups } | Should -Not -Throw

            $LdapGroups.Count | Should -BeGreaterThan 0

        }

        It "Add 'Infrastructure Admins' Directory Group without explicit authentication" {

            $InfrastructureAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Full'

            $InfrastructureAdminGroup | Should -Not -BeNullOrEmpty

            $InfrastructureAdminGroup | Should -BeOfType HPOneView.Appliance.LdapDirectoryGroup

            { $Script:InfraAdminDirGroupResults = New-HPOVLdapGroup -Directory $LdapDirResults -Group $InfrastructureAdminGroup -Roles 'Infrastructure Administrator' } | Should -Not -Throw

            $InfraAdminDirGroupResults | Should -Not -BeNullOrEmpty

            $InfraAdminDirGroupResults.type | Should -Be 'LoginDomainGroupPermission'

            $InfraAdminDirGroupResults.permissions.count | Should -Be 1

            $InfraAdminDirGroupResults.loginDomain | Should -Be $LdapIPv6DirectoryName

        }

        It "Add 'Server Admins' Directory Group without explicit authentication" {

            $ServerAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Server'

            $ServerAdminGroup | Should -Not -BeNullOrEmpty

            $ServerAdminGroup | Should -BeOfType HPOneView.Appliance.LdapDirectoryGroup

            { New-HPOVLdapGroup -Directory $LdapDirResults -Group $ServerAdminGroup -Roles 'Server Administrator' } | Should -Not -Throw

        }

        It "Add 'Storage Admins' Directory Group without explicit authentication" {

            $StorageAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Storage'

            $StorageAdminGroup | Should -Not -BeNullOrEmpty

            $StorageAdminGroup | Should -BeOfType HPOneView.Appliance.LdapDirectoryGroup

            { New-HPOVLdapGroup -Directory $LdapDirResults -Group $StorageAdminGroup -Roles 'Storage Administrator' } | Should -Not -Throw

        }

        It "Add 'Network Admins' Directory Group without explicit authentication" {

            $NetworkAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Network'

            $NetworkAdminGroup | Should -Not -BeNullOrEmpty

            $NetworkAdminGroup | Should -BeOfType HPOneView.Appliance.LdapDirectoryGroup

            { New-HPOVLdapGroup -Directory $LdapDirResults -Group $NetworkAdminGroup -Roles 'Network Administrator' } | Should -Not -Throw

        }

        It "Disconnect from Appliance" {

            { Disconnect-HPOVMgmt -Hostname $Appliance1 -ErrorAction Stop } | Should -Not -Throw

            $ConnectedSessions.Count | Should -Be 0

        }

        It "Connect with valid User Account using UPN" {

            { Connect-HPOVMgmt -Hostname $IPv6Appliance1 -Username $InfraAdminUserUpn -Password $LdapSecurePassword -AuthLoginDomain $LdapIPv6DirectoryName } | Should -Not -Throw
            { Get-HPOVNetwork -ErrorAction Stop } | Should -Not -BeNullOrEmpty
            { Disconnect-HPOVMgmt -Hostname $IPv6Appliance1 -ErrorAction Stop } | Should -Not -Throw

        }

        It "Connect with valid User Account using NtSamAccountName" {

            { Connect-HPOVMgmt -Hostname $IPv6Appliance1 -Username $InfraAdminUserNt -Password $LdapSecurePassword -AuthLoginDomain $LdapIPv6DirectoryName } | Should -Not -Throw
            
        }

        It "Remove LDAP Directory Groups" {

            { $Script:LdapGroupResults = Get-HPOVLdapGroup | Where-Object loginDomain -eq $LdapIPv6DirectoryName | Remove-HPOVLdapGroup -Confirm:$false } | Should -Not -Throw
            $LdapGroupResults.count | Should -Be 4

            $LdapGroupResults[0].Message -eq "Resource deleted successfully." | Should -Be $true
            $LdapGroupResults[1].Message -eq "Resource deleted successfully." | Should -Be $true
            $LdapGroupResults[2].Message -eq "Resource deleted successfully." | Should -Be $true
            $LdapGroupResults[3].Message -eq "Resource deleted successfully." | Should -Be $true 

        }

        It "Remove Ldap Directory " {

            { Disconnect-HPOVMgmt -ErrorAction Stop } | Should -Not -Throw
            { Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw
            { $Script:RemoveLdapDirResults = Get-HPOVLdapDirectory -Name $LdapIPv6DirectoryName -ErrorAction Stop | Remove-HPOVLdapDirectory -Confirm:$false } | Should -Not -Throw
            $RemoveLdapDirResults.Message -eq "Resource deleted successfully." | Should -Be $true 

        }

    }

}

Describe "Local user account management" -Tag All, ApplianceBase, LocalAuthentication {    

    Context "Create and manage user local user account and roles/permissions" {

        BeforeAll {
        
            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1)) {
    
                $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge
    
            }
    
            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {
    
                ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection
    
            }

            if (-not(Get-HPOVScope -Name $ExistingScopeName -ErrorAction SilentlyContinue))
            {

                New-HPOVScope -Name $ExistingScopeName | Out-Null

                $Servers = Get-HPOVServer | Select-Object -first 4

                Get-HPOVScope -Name $ExistingScopeName | Add-HPOVResourceToScope -InputObject $Servers | Out-Null

                $Networks = Get-HPOVNetwork -Type Ethernet -Name Dev*

                Get-HPOVScope -Name $ExistingScopeName | Add-HPOVResourceToScope -InputObject $Networks | Out-Null

            }
        
        }

        It "Will create a new user account with 'Infrastructure administrator' role" {

            { New-HPOVUser -Username $NewLocalAccountUsername -Fullname $NewLocalAccountFullname -Password $CommonPassword -Roles 'Infrastructure administrator' } | Should -Not -Throw
    
        }
    
        It "Will validate the user account exists" {
    
            { Get-HPOVUser -Username $NewLocalAccountUsername -ErrorAction Stop } | Should -Not -Throw
    
        }
    
        It "Will modify the account role and scope permissions" {
    
            { $Script:Scope = Get-HPOVScope -Name $ExistingScopeName -ErrorAction Stop } | Should -Not -Throw
            { Get-HPOVUser -Username $NewLocalAccountUsername -ErrorAction Stop | Set-HPOVUser -Roles 'Server administrator' -ScopePermissions @{Role = 'Network administrator'; Scope = $Scope } } | Should -Not -Throw
    
        }

        It "Will validate the user has the correct role and scope permissions" {

            { $Script:CreatedUserAccount = Get-HPOVUser -Username $NewLocalAccountUsername -ErrorAction Stop } | Should -Not -Throw

            ($CreatedUserAccount.permissions | Where-Object roleName -eq 'Server administrator') | Should -Not -BeNullOrEmpty
            ($CreatedUserAccount.permissions | Where-Object roleName -eq 'Server administrator').scopeUri | Should -BeNullOrEmpty
            ($CreatedUserAccount.permissions | Where-Object roleName -eq 'Network administrator') | Should -Not -BeNullOrEmpty
            ($CreatedUserAccount.permissions | Where-Object roleName -eq 'Network administrator').scopeUri | Should -Be $Scope.uri

        }

    }

    Context "Perform appliance authentication operations with user account" {

        BeforeAll {

            If ($ConnectedSessions) {

                { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw
    
            }

        }

        AfterAll {

            If ($ConnectedSessions) {
    
                { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw
    
            }
    
        }

        It "Will log in with the user account" {

            { $Script:NewApplianceConnection = Connect-HPOVMgmt -Hostname $Appliance1 -Username $NewLocalAccountUsername -Password $CommonPassword -LoginAcknowledge } | Should -Not -Throw

            $Script:OriginalSessionID = $NewApplianceConnection.SessionID.Clone()

        }

        It "Will change the active permissions of the user" {

            $Script:PermissionsToUpdate = $NewApplianceConnection.ActivePermissions | Where-Object RoleName -eq 'Network administrator'

            { Push-HPOVAppliancePermission -SetActivePermissions $PermissionsToUpdate } | Should -Not -Throw

        }

        It "Will validate HPOneView.Appliance.Connection SessionID property is updated" {

            $ConnectedSessions[0].SessionID | Should Not Be $OriginalSessionID

        }

        It "Will validate HPOneView.Appliance.Connection ActivePermissions property for inactive permission" {

            ($ConnectedSessions[0].ActivePermissions | Where-Object RoleName -eq 'Server administrator').Active | Should -Be $false

        }

        It "Will validate HPOneView.Appliance.Connection ActivePermissions property for active permission" {

            ($ConnectedSessions[0].ActivePermissions | Where-Object RoleName -eq 'Network administrator').Active | Should -Be $true

        }

        It "Will get a valid resource from the active scope" {

            { $Script:Servers = Get-HPOVServer } | Should -Not -Throw
            ($Servers | Measure-Object).Count | Should -BeGreaterThan 0

        }

        It "Will switch the active permissions of the user" {

            $Script:NewPermissionsToUpdate = $NewApplianceConnection.ActivePermissions | Where-Object RoleName -eq 'Server administrator'

            { Push-HPOVAppliancePermission -SetActivePermissions $NewPermissionsToUpdate } | Should -Not -Throw

        }
        
        It "Will validate HPOneView.Appliance.Connection ActivePermissions property for active permission" {

            ($ConnectedSessions[0].ActivePermissions | Where-Object RoleName -eq 'Server administrator').Active | Should -Be $true

        }

        It "Will validate HPOneView.Appliance.Connection ActivePermissions property for inactive permission" {

            ($ConnectedSessions[0].ActivePermissions | Where-Object RoleName -eq 'Network administrator').Active | Should -Be $false

        }

        It "Will reset the users active permissions" {

            { Pop-HPOVAppliancePermission } | Should -Not -Throw

        }

        It "Will validate HPOneView.Appliance.Connection ActivePermissions property for active permissions" {

            ($ConnectedSessions[0].ActivePermissions | Where-Object RoleName -eq 'Server administrator').Active | Should -Be $true
            ($ConnectedSessions[0].ActivePermissions | Where-Object RoleName -eq 'Network administrator').Active | Should -Be $true

        }

    }

    Context "Remove created user resources" {

        BeforeAll {
        
            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1)) {
    
                $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge
    
            }
    
            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {
    
                ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection
    
            }
        
        }

        It "Will remove the local user account" {

            { Get-HPOVUser -Username $NewLocalAccountUsername -ErrorAction Stop | Remove-HPOVUser -Confirm:$false } | Should -Not -Throw
    
        }   

    }    

}

# APPLIANCE BASE, Advanced security and 2FA
Describe "Appliance advanced security" -Tag All, ApplianceAdvancedSecurity, ApplianceBase {

    BeforeAll {
        
        if (-not $ConnectedSessions) {

            $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge
            $Connection2 = Connect-HPOVMgmt -Hostname $Appliance2 -Credential $AppliancePSCredential -LoginAcknowledge

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        if (-not (Get-HPOVLdapDirectory -Name *-2FA -ErrorAction SilentlyContinue)){

            $DC1Object = New-HPOVLdapServer -Name $DC1
            $DC2Object = New-HPOVLdapServer -Name $DC2
            $LdapDirResults = New-HPOVLdapDirectory -Name "Doctors-Lab.local-2FA" -AD -BaseDN "dc=doctors-lab,dc=local" -Servers $DC1Object, $DC2Object -Credential $LdapPSPSCredential -ServiceAccount

        }

        # Need to have a check here if the directory group exists for 2FA
        if (-not (Get-HPOVLdapGroup -name 'CI Manager Full Admins' -ErrorAction SilentlyContinue | Where-Object loginDomain -eq 'Doctors-Lab.local-2FA')) {

            $LdapDirResults = Get-HPOVLdapDirectory -Name "Doctors-Lab.local-2FA" -ErrorAction Stop
            $LdapGroups = Get-HPOVLdapDirectory -Name "Doctors-Lab.local-2FA" -ErrorAction Stop | Show-HPOVLdapGroups -Credential $LdapPSPSCredential

            # Add 'Server Admins' Directory Group
            $ServerAdminGroup = $LdapGroups | Where-Object Name -match 'CI Manager Full'
            
            New-HPOVLdapGroup -Directory $LdapDirResults -Group $ServerAdminGroup -Roles "Infrastructure administrator" -Credential $LdapPSPSCredential

        }

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context 'Set appliance advanced security options' {

        It "Will disable Service Console Access" {

            { $Script:DisableServiceConsoleAccessResults = Disable-HPOVApplianceServiceConsoleAccess -Confirm:$false } | Should -Not -Throw

            $DisableServiceConsoleAccessResults.status | Should -Be Disabled

        }

        It "Will enable Service Console Access" {

            { $Script:EnableServiceConsoleAccessResults = Enable-HPOVApplianceServiceConsoleAccess } | Should -Not -Throw
            
            $EnableServiceConsoleAccessResults.status | Should -Be Enabled

        }

        It "Will enable enforce complex passwords" {

            { $Script:EnableApplianceComplexPasswordsResults = Enable-HPOVApplianceComplexPasswords } | Should -Not -Throw
            
            $EnableApplianceComplexPasswordsResults.enforceComplexPasswordEnabled | Should -Be $True

        }

        It "Will disable enforce complex passwords" {

            { $Script:DisableApplianceComplexPasswordsResults = Disable-HPOVApplianceComplexPasswords } | Should -Not -Throw
            
            $DisableApplianceComplexPasswordsResults.enforceComplexPasswordEnabled | Should -Be $False

        }

        It "Will disable SSH Access" {

            { $Script:DisableApplianceSshAccessResults = Disable-HPOVApplianceSshAccess -Confirm:$false } | Should -Not -Throw

            $DisableApplianceSshAccessResults.category | Should -Be 'tasks'
            
            if ($DisableApplianceSshAccessResults.taskState -ne "Completed") {

                DisplayTaskError $DisableApplianceSshAccessResults

            }

            $DisableApplianceSshAccessResults.taskState | Should -Be Completed

        }

        It "Will enable SSH Access" {

            { $Script:EnableApplianceSshAccessResults = Enable-HPOVApplianceSshAccess -Async | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $EnableApplianceSshAccessResults.category | Should -Be 'tasks'
            
            if ($EnableApplianceSshAccessResults.taskState -ne "Completed") {

                DisplayTaskError $EnableApplianceSshAccessResults

            }

            $EnableApplianceSshAccessResults.taskState | Should -Be Completed

        }

        It 'Will disable Hardware Setup Access user' {

            { $Script:DisableServiceConsoleAccessResults = Disable-HPOVApplianceServiceConsoleAccess -Confirm:$false } | Should -Not -Throw
            
            $DisableServiceConsoleAccessResults.status | Should -Be Disabled

        }

        It "Will enable Hardware Setup Access user" {

            { $Script:EnableServiceConsoleAccessResults = Enable-HPOVApplianceServiceConsoleAccess } | Should -Not -Throw

            $EnableServiceConsoleAccessResults.status | Should -Be Enabled

        }

    }

    Context 'Managed 2-Factor Authentication' {

        BeforeAll {

            $SkipSmartCardTests = $false

            $MySmartCard = Get-ChildItem Cert:\CurrentUser\my | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match 'Smart Card Logon' -and $_.Subject -match 'DC=Doctors-Lab' }

            if (-not $MySmartCard) {

                'SmartCard resource not found.  Skipping tests.' | Microsoft.PowerShell.Utility\write-host -ForegroundColor Yellow

                $SkipSmartCardTests = $true

            }

            else {

                "Using {0} SmartCard resource." -f $MySmartCard.Subject | Microsoft.PowerShell.Utility\write-host -ForegroundColor Yellow

            }

        }

        It "Will get 2FA global settings" -Skip:$SkipSmartCardTests {

            { $Script:2FAGlobalSettings = Get-HPOVApplianceTwoFactorAuthentication } | Should -Not -Throw

        }

        It "Will validate return object is of type [HPOneView.Appliance.Security.TwoFactorAuthConfiguration]" -Skip:$SkipSmartCardTests {

            $2FAGlobalSettings | Should -BeOfType HPOneView.Appliance.Security.TwoFactorAuthConfiguration

        }
        
        It "Will validate properties of class object are Read-Only " -Skip:$SkipSmartCardTests {

            $ExpectedExcpetionMessage = "'AllowEmergencyLogin' is a ReadOnly property."

            { $2FAGlobalSettings.AllowEmergencyLogin = $false} | Should -Throw $ExpectedExcpetionMessage

            $ExpectedExcpetionMessage = "'AllowLocalLogin' is a ReadOnly property."
            { $2FAGlobalSettings.AllowLocalLogin     = $false} | Should -Throw $ExpectedExcpetionMessage

            $ExpectedExcpetionMessage = "'ApplianceConnection' is a ReadOnly property."
            { $2FAGlobalSettings.ApplianceConnection = $false} | Should -Throw $ExpectedExcpetionMessage

            $ExpectedExcpetionMessage = "'EmergencyLoginType' is a ReadOnly property."
            { $2FAGlobalSettings.EmergencyLoginType  = $false} | Should -Throw $ExpectedExcpetionMessage

            $ExpectedExcpetionMessage = "'Enabled' is a ReadOnly property."
            { $2FAGlobalSettings.Enabled             = $false} | Should -Throw $ExpectedExcpetionMessage

            $ExpectedExcpetionMessage = "'StrictEnforcement' is a ReadOnly property."
            { $2FAGlobalSettings.StrictEnforcement   = $false} | Should -Throw $ExpectedExcpetionMessage

        }

        It "Will attempt to authenticate to appliance using certificate, and generate exception" -Skip:$SkipSmartCardTests {

            $ExpectedExceptionMessage = "The appliance is not configured for 2-Factor authentication.  Please provide a valid username and password in order to authenticate to the appliance."

            { $null = Connect-HPOVMgmt -Hostname $Appliance1IPv4 -Certificate $MySmartCard -LoginAcknowledge } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will enable Two-factor Authentication" -Skip:$SkipSmartCardTests {

            { $Script:Enable2FAResults = Set-HPOVApplianceTwoFactorAuthentication -ValidationOids @(@{"1.3.6.1.4.1.311.20.2.2" = "Smart Card Logon"; "1.3.6.1.5.5.7.3.2" = "Client Authentication"}) } | Should -Not -Throw
    
        }

        It "Will validate two-factor authentication is enabled" -Skip:$SkipSmartCardTests {

            $Enable2FAResults.twoFactorAuthenticationEnabled -eq $true | Should -Be $true

        }

        It "Will authenticate to appliance using SmartCard" -Skip:$SkipSmartCardTests {

            { $Script:TempConnection = Connect-HPOVMgmt -Hostname $Appliance1IPv4 -Certificate $MySmartCard -LoginAcknowledge } | Should -Not -Throw

        }

        It "Will validate the connection object type is HPOneView.Appliance.Connection" -Skip:$SkipSmartCardTests {

            $TempConnection | Should -BeOfType HPOneView.Appliance.Connection

        }

        It "Will validate the appliance connection is in the global tracker" -Skip:$SkipSmartCardTests {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1IPv4).Name | Should -Be $Appliance1IPv4

        }

        It "Will disable Two-factor Authentication" -Skip:$SkipSmartCardTests {

            { $Script:Disable2FAResults = Disable-HPOVApplianceTwoFactorAuthentication -Confirm:$false } | Should -Not -Throw

        }

        It "Will validate two-factor authentication is disabled" -Skip:$SkipSmartCardTests {

            $Disable2FAResults.twoFactorAuthenticationEnabled | Should -Be $false

        }

    }

}

# APPLIANCE BASE, Alerting, Scopes, SBAC and Labels
Describe "Appliance Alerting (Email, SNMP, Remote Syslog), Scopes, SBAC and Label configuration" -Tag All, ApplianceBase, ApplianceAlerting {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Manage appliance Proxy settings" {

        It "Will set the appliance proxy to HTTP/$ApplianceProxyAddress" {

            { $script:ApplianceProxyResults = Set-HPOVApplianceProxy -Hostname $ApplianceProxyAddress -Port $ApplianceProxyHttpTCPPort } | Should -Not -Throw

            $ApplianceProxyResults | Should -Not -BeNullOrEmpty
            $ApplianceProxyResults.category | Should -Be 'tasks'

            if ($ApplianceProxyResults.taskState -ne "Completed") {

                DisplayTaskError $ApplianceProxyResults

            }

            $ApplianceProxyResults.taskState | Should -Be Completed

        }

        It "Will validate can retrieve Proxy settings" {

            { $script:ApplianceProxySettings = Get-HPOVApplianceProxy } | Should -Not -Throw

            $ApplianceProxySettings | Should -Not -BeNullOrEmpty

        }

        It "Will validate appliance proxy object type" {

            $ApplianceProxySettings | Should -BeOfType HPOneView.Appliance.ProxyServer

        }

        It "Will validate server is set correctly" {

            $ApplianceProxySettings.Server | Should -Be $ApplianceProxyAddress

        }

        It "Will validate port is set correctly" {

            $ApplianceProxySettings.Port | Should -Be $ApplianceProxyHttpTCPPort

        }

        It "Will reset proxy back to unconfigured" {

            { $script:ResetApplianceProxyResults = Remove-HPOVApplianceProxy -Confirm:$false } | Should -Not -Throw

            $ResetApplianceProxyResults | Should -Not -BeNullOrEmpty
            $ResetApplianceProxyResults.category | Should -Be 'tasks'

            if ($ResetApplianceProxyResults.taskState -ne "Completed") {

                DisplayTaskError $ResetApplianceProxyResults

            }

            $ResetApplianceProxyResults.taskState | Should -Be Completed

        }

    }

    Context "Resource Alert Management" {

        BeforeAll {

            $Script:BaseUrl = 'http://{0}:9990' -f ($ConnectedSessions | Where-Object Default ).Name
            $uri = '{0}/dcs/rest/schematic/details' -f $BaseUrl
            { $Script:Schematic = Invoke-RestMethod -Uri $uri -Headers $DcsHeaders -ErrorAction Stop } | Should -Not -Throw

            $DcsEnclosureInstanceUri = '{0}/dcs/rest/schematic/instances/{1}' -f $BaseUrl, (($Schematic.Schematic.Enclosures.Enclosure | Where-Object { $_.OABay.OA.IP -match '172.18.1.11' }).Name)
            { $Script:DcsEnclosureInstance = Invoke-RestMethod -Uri $DcsEnclosureInstanceUri -Headers $DcsHeaders -ErrorAction Stop } | Should -Not -Throw

            $c = 0

            $Script:IloTrapEventUris = New-Object System.Collections.ArrayList

            ($DcsEnclosureInstance.InstanceInfo.targets.EntityInstance | Where-Object type -match 'bl|sy') | ForEach-Object {

                if ($c -eq 3) { break }

                { $Script:Server = Invoke-RestMethod -Uri ("{0}{1}" -f $BaseUrl, $_.uri) -Headers $DcsHeaders -ErrorAction Stop } | Should -Not -Throw
                
                $EventUrl = '{0}{1}?action=sendIloTrapEvent&eventType=cpqHe3TemperatureDegraded' -f $BaseUrl, ($Server.InstanceInfo.targets.EntityInstance | Where-Object type -match 'ilo').uri
                
                { Invoke-RestMethod -Uri $EventUrl -Method POST -Headers $DcsHeaders -ErrorAction Stop } | Should -Not -Throw
                
                [void]$IloTrapEventUris.Add(($Server.InstanceInfo.targets.EntityInstance | Where-Object type -match 'ilo').uri)
                
                $c++

            }

            if ($IloTrapEventUris.count -eq 0) {

                Throw "iLO Traps were NOT generated for alerts."

            }

        }

        AfterAll {

            $IloTrapEventUris | ForEach-Object {

                { Invoke-RestMethod -Uri ('{0}{1}?action=sendIloTrapEvent&eventType=cpqHe3TemperatureOk' -f $BaseUrl, $_) -Headers $DcsHeaders -ErrorAction Stop } | Should -Not -Throw

            }

        }

        It "Will get all active alerts" {
        
            { $Script:Alerts = Get-HPOVAlert -State Active } | Should -Not -Throw
            $Alerts.count -ge 1 | Should -Be $true 
        
        }

        It "Will retrieve alerts for 'Encl1, Bay 1' server via resource pipeline" {
        
            { $Script:Alert = Get-HPOVServer -Name 'Encl1, Bay 1' | Get-HPOVAlert -AlertState Active } | Should -Not -Throw
            $Alert | Should -Not -BeNullOrEmpty 
            $Alert | ForEach-Object { $_.category | Should -Be alerts }

        }

        It "Will add a note to the alert" {
        
            { $Script:AlertNoteResults = Get-HPOVServer -Name 'Encl1, Bay 1' | Get-HPOVAlert -AlertState Active | Set-HPOVAlert -Notes "Ticket 123456789A" } | Should -Not -Throw
            $AlertNoteResults | Should -Not -BeNullOrEmpty 
            $AlertNoteResults | ForEach-Object { $_.category | Should -Be alerts }
            $AlertNoteResults.changeLog[0].notes -eq 'Ticket 123456789A' | Should -Be True
        
        }

        It "Will get 5 alert objects" {
        
            { $Script:Alerts = Get-HPOVAlert -Count 5 } | Should -Not -Throw
            $Alerts.Count | Should -Be 5
        
        }

        It "Will get alerts from a 2 day TimeSpan" {
        
            $TimeSpan = New-TimeSpan -Days 2
            { $Script:AlertsFromRange = Get-HPOVAlert -TimeSpan $TimeSpan } | Should -Not -Throw
            $AlertsFromRange | Should -Not -BeNullOrEmpty
            $AlertsFromRange[0].category | Should -Be alerts
        
        }

        It "Will get alerts from specific dates" {
        
            $Start = [System.DateTime]::Now.AddDays(-4)
            $End = [System.DateTime]::Now.AddDays(-2)
            { $Script:AlertsFromRange = Get-HPOVAlert -Start $Start -End $End -count 20} | Should -Not -Throw
            $AlertsFromRange.Count -le 20 | Should -Be $true
            if ($AlertsFromRange.Count -gt 1) { $AlertsFromRange[0].category | Should -Be alerts }
        
        }

        It "Will clear all active alerts" {
        
            { Get-HPOVAlert -AlertState Active | Set-HPOVAlert -Cleared } | Should -Not -Throw
        
        }

        It "Will validate no active alerts -Exist" {
        
            Get-HPOVAlert -AlertState Active | Should -BeNullOrEmpty

        }

        It "Will remove the first alert from the appliance" {

            $Script:Alert = Get-HPOVAlert | Select-Object -Last 1

            { $Script:Results = $Alert | Remove-HPOVAlert -Confirm:$false } | Should -Not -Throw
            
            $Results.Message | Should -Be "Resource deleted successfully."

        }
        
        It "Will validate removed alert does not -Exist" {

            $ExpectedExceptionMessage = "The requested resource '{0}' could not be found. Provide a valid alert URI." -f $Alert.uri

            { Send-HPOVRequest -Uri $Alert.uri } | Should -Throw $ExpectedExceptionMessage
        
        }

    }

    Context "Configure Email Alerting appliance settings" {
    
        It "Will configure Email Alerting with basic settings" {
        
            { $Script:ConfigureEmailAlertingResults = Set-HPOVSmtpConfig -SenderEmailAddress $Appliance1EmailAddress -ConnectionSecurity None -Async | Wait-HPOVTaskComplete } | Should -Not -Throw
            $ConfigureEmailAlertingResults | Should -Not -BeNullOrEmpty
            $ConfigureEmailAlertingResults.category | Should -Be 'tasks'

            if ($ConfigureEmailAlertingResults.taskState -ne "Completed") {

                DisplayTaskError $ConfigureEmailAlertingResults

            }

            $ConfigureEmailAlertingResults.taskState | Should -Be Completed
        
        }

        It "Will attempt to configure Email Alerting with specific SMTP settings omitting SMTP Server" {
        
            $ExpectedExceptionMessage = 'When specifying an SMTP Server Port value, the -Server parameter or an existing SMTP Server value must be present on the appliance.'
            
            { Set-HPOVSmtpConfig -Port 25 } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will configure Email Altering with specific Server and SMTP Port" {
        
            { $Script:ConfigureEmailAlertingResults = Set-HPOVSmtpConfig -SenderEmailAddress $Appliance1EmailAddress -ConnectionSecurity None -Server $SmtpRelayServerAddress -Port $SmtpRelayServerTcpPort -Async | Wait-HPOVTaskComplete } | Should -Not -Throw
            $ConfigureEmailAlertingResults | Should -Not -BeNullOrEmpty
            $ConfigureEmailAlertingResults.category | Should -Be 'tasks'

            if ($ConfigureEmailAlertingResults.taskState -ne "Completed") {

                DisplayTaskError $ConfigureEmailAlertingResults

            }

            $ConfigureEmailAlertingResults.taskState | Should -Be Completed
        
        }

        It "Will generate test email message" {
        
            { $Script:TestEmailMessageResults = Test-HPOVEmailAlert -Recipients $Recipient1EmailAddress } | Should -Not -Throw
            $TestEmailMessageResults | Should -Not -BeNullOrEmpty
            $TestEmailMessageResults.category | Should -Be 'appliance'
            $TestEmailMessageResults.toAddress.Contains($Recipient1EmailAddress) | Should -Be $true
        
        }

        It "Will generate second test email message with multiple recipients, custom subject and body" {
        
            { $Script:TestEmailMessageResults = Test-HPOVEmailAlert -Recipients $Recipient1EmailAddress,$Recipient2EmailAddress -Subject $TestEmailAlertSubject -Body $TestEmailAlertHtmlBody } | Should -Not -Throw
            $TestEmailMessageResults | Should -Not -BeNullOrEmpty
            $TestEmailMessageResults.category | Should -Be 'appliance'
            $TestEmailMessageResults.toAddress.Contains($Recipient1EmailAddress) | Should -Be $true
            $TestEmailMessageResults.toAddress.Contains($Recipient2EmailAddress) | Should -Be $true
            [System.String]::IsNullOrWhiteSpace($TestEmailMessageResults.textMessageBody) | Should -Be $true
            [System.String]::IsNullOrWhiteSpace($TestEmailMessageResults.htmlMessageBody) | Should -Be $false
        
        }
    
    }

    Context "Configure Email Altering Filters" {

        It "Will attempt to configure an invalid alert filter using an invalid Email address" {
        
            $ExpectedExceptionMessage = "Cannot validate argument on parameter 'Emails'. The Parameter value 'invalidemail' is not an email address. Please correct the value and try again."
        
            { Add-HPOVSmtpAlertEmailFilter -Name 'Invalid Alert Filter' -Filter 'status:critical' -Emails 'invalidemail' } | Should -Throw $ExpectedExceptionMessage
        
        }
    
        It "Will configure 'status:Critical' email alert filter" {
    
            { $Script:NewAlertFilterResults = Add-HPOVSmtpAlertEmailFilter -Name 'My Test Filter 1' -Filter 'status:critical' -Emails "user2@doctors-lab.local" } | Should -Not -Throw
            $NewAlertFilterResults | Should -Not -BeNullOrEmpty
            $NewAlertFilterResults.category | Should -Be 'tasks'

            if ($NewAlertFilterResults.taskState -ne "Completed") {

                DisplayTaskError $NewAlertFilterResults

            }

            $NewAlertFilterResults.taskState | Should -Be Completed
    
        }

    }

    Context "Create and manage Scopes (Non-SBAC)" {

        It "Will create 'My New Scope' Scope" {
        
            { $Script:CreateNewScopeResults = New-HPOVScope -Name 'My New Scope' -Description 'My test scope' } | Should -Not -Throw
            $CreateNewScopeResults | Should -Not -BeNullOrEmpty
            $CreateNewScopeResults | Should -BeOfType HPOneView.Appliance.ScopeCollection
        
        }

        It "Will add New resources (ethernet-networks) to 'My New Scope'" {
        
            { $Script:EthernetNetworks = Get-HPOVNetwork -Type Ethernet -Name VLAN* -ErrorAction Stop } | Should -Not -Throw
            $EthernetNetworks | Should -Not -BeNullOrEmpty
            { $Script:MyNewScope = Get-HPOVScope -Name 'My New Scope' -ErrorAction Stop } | Should -Not -Throw
            $MyNewScope | Should -BeOfType HPOneView.Appliance.ScopeCollection
            { $Script:AddResourcesToScopeResults = Add-HPOVResourceToScope -Scope $MyNewScope -InputObject $EthernetNetworks } | Should -Not -Throw
            $AddResourcesToScopeResults | Should -Not -BeNullOrEmpty
            $AddResourcesToScopeResults.category | Should -Be 'tasks'
            if ($AddResourcesToScopeResults.taskState -ne "Completed") {

                DisplayTaskError $AddResourcesToScopeResults

            }

            $AddResourcesToScopeResults.taskState | Should -Be Completed

        }

        It "Will test Scope filtering at the Get resource Cmdlet (Get-HPOVNetwork)" {
        
            { $Script:ScopedEthernetNetworks = Get-HPOVNetwork -Name VLAN* -Scope $MyNewScope -ErrorAction Stop } | Should -Not -Throw
            $ScopedEthernetNetworks.count -eq $EthernetNetworks.count | Should -Be $true
        
        }

        It "Will validate invalid Name resource with Scope will generate error" {
        
            $ExpectedExceptionMessage = "The specified '{0}' Network resource was not found on '{1}' appliance connection.  Please check the name and try again." -f $InvalidName, $Appliance1

            { Get-HPOVNetwork -Name $InvalidName -Scope $MyNewScope -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will create 'My New Scope2' Scope" {
        
            { $Script:CreateNewScopeResults = New-HPOVScope -Name 'My New Scope2' -Description 'My test scope2' } | Should -Not -Throw
            $CreateNewScopeResults | Should -Not -BeNullOrEmpty
            $CreateNewScopeResults | Should -BeOfType HPOneView.Appliance.ScopeCollection
        
        }

        It "Will add New resources to 'My New Scope2'" {
        
            { $Script:ServerHardware = Get-HPOVServer } | Should -Not -Throw
            $ServerHardware | Should -Not -BeNullOrEmpty
            { $Script:MyNewScope2 = Get-HPOVScope -Name 'My New Scope2' -ErrorAction Stop } | Should -Not -Throw
            $MyNewScope2 | Should -BeOfType HPOneView.Appliance.ScopeCollection
            { $Script:AddResourcesToScopeResults = Add-HPOVResourceToScope -Scope $MyNewScope2 -InputObject $ServerHardware } | Should -Not -Throw
            $AddResourcesToScopeResults | Should -Not -BeNullOrEmpty
            $AddResourcesToScopeResults.category | Should -Be 'tasks'
            if ($AddResourcesToScopeResults.taskState -ne "Completed") {

                DisplayTaskError $AddResourcesToScopeResults

            }

            $AddResourcesToScopeResults.taskState | Should -Be Completed

        }

        It "Will remove a resource from 'My New Scope'" {
            
            { $Script:ServerHardware = Get-HPOVServer | Select-Object -Last 1 } | Should -Not -Throw
            { $Script:MyNewScope2 = Get-HPOVScope -Name 'My New Scope2' -ErrorAction Stop } | Should -Not -Throw
            
            { $Script:RemoveResourceFromScopeResults = Remove-HPOVResourceFromScope -Scope $MyNewScope2 -InputObject $ServerHardware } | Should -Not -Throw

            $RemoveResourceFromScopeResults | Should -Not -BeNullOrEmpty
            $RemoveResourceFromScopeResults.category | Should -Be 'tasks'
            if ($RemoveResourceFromScopeResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResourceFromScopeResults

            }

            $RemoveResourceFromScopeResults.taskState | Should -Be Completed

            $MyNewScope2 = Get-HPOVScope -Name 'My New Scope2' -ErrorAction Stop
            $MyNewScope2.Members.Uri -notcontains $ServerHardware.uri | Should -Be $true
        
        }
    
    }

    Context "Create and manage Scopes with Permissions (SBAC)" {

        $LdapDirectory = Get-HPOVLdapDirectory -Name $DefaultLdapDirectoryName -ErrorAction Stop
        $LdapGroups =  $LdapDirectory | Show-HPOVLdapGroups -Credential $LdapPSPSCredential

        # Add 'Server Admins' Directory Group
        $ServerAdminGroup = $LdapGroups | Where-Object Name -match $CIManagerServerAdmins
        $ServerAdminGroup | Should -Not -BeNullOrEmpty

        if (-not (Get-HPOVLdapGroup -name $CIManagerServerAdmins -ErrorAction SilentlyContinue | Where-Object loginDomain -eq $DefaultLdapDirectoryName)) {
           
            { New-HPOVLdapGroup -Directory $LdapDirectory -Group $ServerAdminGroup -Roles 'Server Administrator' -Credential $LdapPSPSCredential } | Should -Not -Throw       

        }        

        # Add 'Storage Admins' Directory Group
        $StorageAdminGroup = $LdapGroups | Where-Object Name -match $CIManagerStorageAdmins
        $StorageAdminGroup | Should -Not -BeNullOrEmpty

        if (-not (Get-HPOVLdapGroup -name $CIManagerStorageAdmins -ErrorAction SilentlyContinue | Where-Object loginDomain -eq $DefaultLdapDirectoryName)) {
           
            { New-HPOVLdapGroup -Directory $LdapDirectory -Group $StorageAdminGroup -Roles 'Storage Administrator' -Credential $LdapPSPSCredential } | Should -Not -Throw

        }       

        # Add 'Network Admins' Directory Group
        $NetworkAdminGroup = $LdapGroups | Where-Object Name -match $CIManagerNetworkAdmins
        $NetworkAdminGroup | Should -Not -BeNullOrEmpty
        
        if (-not (Get-HPOVLdapGroup -name $CIManagerNetworkAdmins -ErrorAction SilentlyContinue | Where-Object loginDomain -eq $DefaultLdapDirectoryName)) {
           
            { New-HPOVLdapGroup -Directory $LdapDirectory -Group $NetworkAdminGroup -Roles 'Network Administrator' -Credential $LdapPSPSCredential } | Should -Not -Throw

        }        

        # Create new scope with 1 specific role and permissions
        It "Will create '$MySbacScope1Name' Scope" {
            
            { $Script:CreateNewScopeResults = New-HPOVScope -Name $MySbacScope1Name -Description $MySbacScope1Name } | Should -Not -Throw
            $CreateNewScopeResults | Should -Not -BeNullOrEmpty
            $CreateNewScopeResults | Should -BeOfType HPOneView.Appliance.ScopeCollection
            
        }

        It "Will create a new Ethernet Network assigning to new scope." {

            $Scope = Get-HPOVScope -Name $MySbacScope1Name -ErrorAction Stop

            { $Script:NetworkWithScopeResults = New-HPOVNetwork -Name $SbacEthernetNetwork -VLANType Untagged -Scope $Scope } | Should -Not -Throw


            $NetworkWithScopeResults | Should -Not -BeNullOrEmpty
            $NetworkWithScopeResults.Name | Should -Be $SbacEthernetNetwork
            
            if ($NetworkWithScopeResults.Status -ne "Completed") {

                DisplayTaskError $NetworkWithScopeResults

            }         

            $NetworkWithScopeResults.Status | Should -Be Completed

        }

        It "Will validate ethernet network is within scope" {

            { $Script:NewSBACScope = Get-HPOVScope -Name $MySbacScope1Name -ErrorAction Stop } | Should -Not -Throw
            $NewSBACScope.Members.Name | Should -Be $SbacEthernetNetwork

        }

        It "Will retreive network resource using scope filter" {

            [Array]$Network = Get-HPOVNetwork -Scope $NewSBACScope -ErrorAction Stop
            $Network.Count | Should -Be 1
            $Network[0].name | Should -Be $SbacEthernetNetwork

        }

        It "Will assign Network Group to $MySbacScope1Name with Network Administrators permission" {

            { $Script:LdapPermissionsResults = Get-HPOVLdapGroup -Group $CIManagerNetworkAdmins -ErrorAction Stop | Where-Object loginDomain -eq $DefaultLdapDirectoryName | Set-HPOVLdapGroupRole -ScopePermissions @{Role = 'Network administrator'; Scope = $NewSBACScope } -Credential $LdapPSPSCredential} | Should -Not -Throw

        }

        It "Will verify group was added to SBAC Scope" {

            { $Script:SbacGroup = Get-HPOVLdapGroup -Group $CIManagerNetworkAdmins -ErrorAction Stop | Where-Object loginDomain -eq $DefaultLdapDirectoryName } | Should -Not -Throw
            # $SbacGroup.Count | Should -Be 1
            $SbacGroup[0].permissions.roleName | Should -Be 'Network administrator'
            
        }

        It "Will verify group SBAC Scope has correct permissions" {

            { $Script:SbacGroup = Get-HPOVLdapGroup -Group $CIManagerNetworkAdmins -ErrorAction Stop | Where-Object loginDomain -eq $DefaultLdapDirectoryName } | Should -Not -Throw
            # $SbacGroup.Count | Should -Be 1
            $SbacGroup[0].permissions.scopeUri | Should -Be $NewSBACScope.uri

        }

    }

    Context "Associate Scopes with Email Filters" {

        It "Will configure 'status:Critical' email alert filter for specific Scope" {
        
            { $Script:NewAlertFilterResults = Add-HPOVSmtpAlertEmailFilter -Name 'My Test Filter 2' -Filter 'status:critical' -Emails "user2@doctors-lab.local" -Scope 'My New Scope' } | Should -Not -Throw
            $NewAlertFilterResults | Should -Not -BeNullOrEmpty
            $NewAlertFilterResults.category | Should -Be 'tasks'
            if ($NewAlertFilterResults.taskState -ne 'Completed') { Microsoft.PowerShell.Utility\write-host ('Task did not Complete successfully.  Task URI: {0}' -f $NewAlertFilterResults.uri) -ForegroundColor Yellow }
            $NewAlertFilterResults.taskState | Should -Be Completed
        
        }

        It "Will configure 'status:Critical' email alert filter for multiple scopes and multiple Emails" {
        
            { $Script:NewAlertFilterResults = Add-HPOVSmtpAlertEmailFilter -Name 'My Test Filter 3' -Filter 'status:critical' -Emails 'user1@doctors-lab.local','user2@doctors-lab.local' -Scope 'My New Scope','My New Scope2' -Async | Wait-HPOVTaskComplete } | Should -Not -Throw
            $NewAlertFilterResults | Should -Not -BeNullOrEmpty
            $NewAlertFilterResults.category | Should -Be 'tasks'
            
            if ($NewAlertFilterResults.taskState -ne "Completed") {

                DisplayTaskError $NewAlertFilterResults

            }
            
            $NewAlertFilterResults.taskState | Should -Be Completed    
        
        }

    }

    Context "Configure and manage labels" {

        BeforeAll { 

            { $Script:DevNetworks = Get-HPOVNetwork -Name Dev* -Type Ethernet -ErrorAction Stop } | Should -Not -Throw
            { $Script:ProdNetworks = Get-HPOVNetwork -Name VLAN* -Type Ethernet -ErrorAction Stop } | Should -Not -Throw
            { $Script:Fabrics = Get-HPOVNetwork -Name Fabric* -Type FibreChannel -ErrorAction Stop } | Should -Not -Throw
            { $Script:StoragePools = Get-HPOVStoragePool -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will create and assign a new label $NewLabel1Name to resources" {

            { $Script:Results = Add-HPOVResourceToLabel -Name $NewLabel1Name -InputObject $DevNetworks } | Should -Not -Throw

        }

        It "Will validate $NewLabel1Name exists" {

            { $Script:Results = Get-HPOVLabel -Name $NewLabel1Name -ErrorAction Stop } | Should -Not -Throw

            $Results | Should -Not -BeNullOrEmpty
            $Results | ForEach-Object { $_ | Should -BeOfType HPOneView.Appliance.Label }

        }

        It "Will validate $NewLabel2Name does not -Exist" {

            $ExpectedExceptionMessage = '{0} was not found on {1} appliance.  Check the Name Parameter value.' -f $NewLabel2Name, $Appliance1

            { Get-HPOVLabel -Name $NewLabel2Name -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will create and assign a new label $NewLabel2Name to resources" {

            { $Script:ProdNetsResults = Add-HPOVResourceToLabel -Name $NewLabel2Name -InputObject $ProdNetworks } | Should -Not -Throw
            $ProdNetsResults | ForEach-Object { $_.type | Should -Be 'ResourceLabels' }
            $ProdNetsResults | ForEach-Object { $_.labels.name | Should -Be $NewLabel2Name }

        }

        It "Will assign resources to an existing Label" {

            { $Script:FabricResults = Add-HPOVResourceToLabel -Name $NewLabel2Name -InputObject $Fabrics } | Should -Not -Throw
            $FabricResults | ForEach-Object { $_.type | Should -Be 'ResourceLabels' }
            $FabricResults | ForEach-Object { $_.labels.name | Should -Be $NewLabel2Name }
            { $Script:StoragePoolResults = Add-HPOVResourceToLabel -Name $NewLabel2Name -InputObject $StoragePools } | Should -Not -Throw
            $StoragePoolResults | ForEach-Object { $_.type | Should -Be 'ResourceLabels' }
            $StoragePoolResults | ForEach-Object { $_.labels.name | Should -Be $NewLabel2Name }

        }

        It "Will get networks associated with label1" {

            { $Script:NetworkResults = Get-HPOVNetwork -Type FibreChannel -Label $NewLabel2Name -ErrorAction Stop } | Should -Not -Throw
            
            #There should not be any networks other than FC Networks
            $NetworkResults.category | Where-Object { $_ -ne 'fc-networks' } | Should -BeNullOrEmpty

        }

        It "Will get Storage Pools associated with label2" {

            { $Script:StoragePoolResults = Get-HPOVStoragePool -Label $NewLabel2Name -ErrorAction Stop } | Should -Not -Throw

            $StoragePoolResults | Should -Not -BeNullOrEmpty
            $StoragePoolResults.Count | Should -Be $StoragePools.Count

        }
        
        It "Will attempt to remove a label" {
        
            $ExpectedExceptionMessage = "An invalid InputObject argument value type was provided, {0}.  Labels cannot be removed via the appliance API.  Labels are automatically removed when the last association to a resource is removed.  Please provide a resource object to remove the label association." -f $NewLabel1Name

            { Get-HPOVLabel -Name $NewLabel1Name -ErrorAction Stop | Remove-HPOVResourceFromLabel -Confirm:$false } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will remove resource from 1 label" {
        
            $ResourceToRemoveFromLabel = $DevNetworks | Sort-Object { Get-Random } | Select-Object -First 1

            { Remove-HPOVResourceFromLabel -InputObject $ResourceToRemoveFromLabel -Name $NewLabel1Name } | Should -Not -Throw
        
        }

        It "Will remove resources from all labels" {
        
            { $DevNetworks | Remove-HPOVResourceFromLabel -RemoveAllLabelsFromResource -Confirm:$false } | Should -Not -Throw
            { $ProdNetworks | Remove-HPOVResourceFromLabel -RemoveAllLabelsFromResource -Confirm:$false } | Should -Not -Throw
            { $Fabrics | Remove-HPOVResourceFromLabel -RemoveAllLabelsFromResource -Confirm:$false } | Should -Not -Throw
            { $StoragePools | Remove-HPOVResourceFromLabel -RemoveAllLabelsFromResource -Confirm:$false } | Should -Not -Throw
        
        }

        It "Will validate created labels are removed" {

            { $Script:Label1Results = Get-HPOVLabel -Name $NewLabel1Name -ErrorAction SilentlyContinue } | Should -Not -Throw

            $Label1Results | Should -BeNullOrEmpty

            { $Script:Label2Results = Get-HPOVLabel -Name $NewLabel2Name -ErrorAction SilentlyContinue } | Should -Not -Throw

            $Label2Results | Should -BeNullOrEmpty
            
        }
        
    }

    Context "Remove Email Alert Filters" {
    
        It "Will remove created email alert filters" {
    
            $_CurrentAlertConfiguration = Get-HPOVSMTPConfig
            [Array]$_CurrentAlertConfiguration.alertEmailFilters = @() 

            { $Script:EmailAlertConfigResetResults = Send-HPOVRequest -Uri $_CurrentAlertConfiguration.uri -Method POST -Body $_CurrentAlertConfiguration -Hostname $_CurrentAlertConfiguration.ApplianceConnection.Name | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $EmailAlertConfigResetResults | Should -Not -BeNullOrEmpty
            $EmailAlertConfigResetResults.category | Should -Be 'tasks'
            
            if ($EmailAlertConfigResetResults.taskState -ne "Completed")
            {

                DisplayTaskError $EmailAlertConfigResetResults

            }

            $EmailAlertConfigResetResults.taskState | Should -Be Completed
    
        }

        It "Will reset SMTP Server Settings" {
        
            $_CurrentAlertConfiguration = Get-HPOVSMTPConfig
            $_CurrentAlertConfiguration.smtpServer = $null
            $_CurrentAlertConfiguration.smtpPort   = $null

            { $Script:EmailAlertConfigResetResults = Send-HPOVRequest -Uri $_CurrentAlertConfiguration.uri -Method POST -Body $_CurrentAlertConfiguration -Hostname $_CurrentAlertConfiguration.ApplianceConnection.Name | Wait-HPOVTaskComplete } | Should -Not -Throw

            $EmailAlertConfigResetResults | Should -Not -BeNullOrEmpty
            $EmailAlertConfigResetResults.category | Should -Be 'tasks'

            if ($EmailAlertConfigResetResults.taskState -ne "Completed") {

                DisplayTaskError $EmailAlertConfigResetResults

            }

            $EmailAlertConfigResetResults.taskState | Should -Be Completed
        
        }
    
    }

    Context "Remove scopes" {
        
        It "Will reset LDAP directory group back to default permissions" {

            { $Script:RemoveScopePermissionsResults = Get-HPOVLdapGroup -Group $CIManagerNetworkAdmins | Where-Object loginDomain -eq $DefaultLdapDirectoryName | Set-HPOVLdapGroupRole -Role 'Network administrator' -Credential $LdapPSPSCredential } | Should -Not -Throw
            $RemoveScopePermissionsResults.permissions.scopeUri | Should -BeNullOrEmpty
            $RemoveScopePermissionsResults.permissions.roleName | Should -Be 'Network administrator'
            
        }
    
        It "Will remove created scopes" {
    
            { $Script:RemoveResults = 'My New Scope', 'My New Scope2', $MySbacScope1Name | ForEach-Object { Get-HPOVScope -Name $_ -ErrorAction SilentlyContinue | Remove-HPOVScope -Confirm:$false | Wait-HPOVTaskComplete } } | Should -Not -Throw

            $RemoveResults | ForEach-Object {

                $_ | Should -Not -BeNullOrEmpty
                $_.category | Should -Be 'tasks'
                
                if ($_.taskState -ne "Completed") {

                    DisplayTaskError $_

                }
                
                $_.taskState | Should -Be Completed 

            }
    
        }

        It "Will remove created SBAC network" {

            { Get-HPOVNetwork -Name $SbacEthernetNetwork -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$False }

        }
    
    }

    Context "Configure Appliance SNMP settings" {

        BeforeAll {

            $SnmpV1TrapDestinations = Send-HPOVRequest -uri '/rest/appliance/trap-destinations'
            $SnmpV3TrapDestinations = Send-HPOVRequest -uri '/rest/appliance/snmpv3-trap-forwarding/destinations'
            $SnmpV3Users = Send-HPOVRequest -uri '/rest/appliance/snmpv3-trap-forwarding/users'

            if ($SnmpV1TrapDestinations.Count -gt 0) {

                Microsoft.PowerShell.Utility\write-host 'Cleaning up SNMPv1 Trap Destinations on appliance.' -ForegroundColor Yellow 

                ForEach ($_member in $SnmpV1TrapDestinations.members) {

                    Send-HPOVRequest -Uri $_member.uri -Method DELETE | Out-Null

                }

            }

            if ($SnmpV3TrapDestinations.Count -gt 0) {

                Microsoft.PowerShell.Utility\write-host 'Cleaning up SNMPv3 Trap Destinations on appliance.' -ForegroundColor Yellow 

                ForEach ($_member in $SnmpV3TrapDestinations.members) {

                    Send-HPOVRequest -Uri $_member.uri -Method DELETE | Out-Null

                }

            }

            if ($SnmpV3Users.Count -gt 0) {

                Microsoft.PowerShell.Utility\write-host 'Cleaning up SNMPv3 users on appliance.' -ForegroundColor Yellow                  

                ForEach ($_member in $SnmpV3Users.members) {

                    Send-HPOVRequest -Uri $_member.uri -Method DELETE | Out-Null

                }

            }            

        }
    
        It "Will get existing appliance SNMP Community" {
    
            { $Script:ApplianceSnmpReadCommunity = Get-HPOVSnmpReadCommunity } | Should -Not -Throw
    
        }

        It "Will validate SNMP Read Community data type" {

            $ApplianceSnmpReadCommunity | Should -BeOfType HPOneView.Appliance.SnmpReadCommunity

        }

        It "Will update SNMP Read Community string" {
        
            { $Script:UpdateApplianceSnmpReadCommunityResults = Set-HPOVSnmpReadCommunity -Name $PesterTestRandomName } | Should -Not -Throw

            $UpdateApplianceSnmpReadCommunityResults.communityString | Should -Be $PesterTestRandomName
        
        }

        It "Will add a new SNMPv1 trap destination '$SnmpV1TrapDestinationAddress' to appliance" {

            { $Script:NewSnmpV1TrapDestinationResults = New-HPOVApplianceTrapDestination -Destination $SnmpV1TrapDestinationAddress -Type SNMPv1 -Port $SnmpV1TrapDestinationPort -CommunityString $SnmpV1Community } | Should -Not -Throw

        }

        It "Will retrieve SNMPv1 trap destination '$SnmpV1TrapDestinationAddress'" {

            { $script:SnmpV1TrapDestinationResource = Get-HPOVApplianceTrapDestination -Destination $SnmpV1TrapDestinationAddress -Type SnmpV1 -ErrorAction Stop } | Should -Not -Throw

            $SnmpV1TrapDestinationResource | Should -Be HPOneView.Appliance.SnmpV1TrapDestination

        }

        It "Will get the appliance SNMPv3 Engine ID" {

            { $Script:ApplianceSnmpV3EngineId = Get-HPOVApplianceSnmpV3EngineId } | Should -Not -Throw
            $ApplianceSnmpV3EngineId | Should -BeOfType HPOneView.Appliance.SnmpV3EngineId
            $ApplianceSnmpV3EngineId.EngineId | Should -Not -BeNullOrEmpty

        }

        It "Will add a new SNMPv3 User '$SnmpV3UserName' to appliance" {

            { New-HPOVSnmpV3User -ApplianceSnmpUser -Username $SnmpV3UserName -SecurityLevel $SnmpV3UserSecurity -AuthProtocol $SnmpV3UserAuthProtocol -AuthPassword $SnmpV3AuthPassword -PrivProtocol $SnmpV3UserPrivProtocol -PrivPassword $SnmpV3PrivPassword } | Should -Not -Throw
            
        }

        It "Will retrieve SNMPv3 user '$SnmpV3UserName' from appliance" {

            { $Script:CreatedSnmpV3User = Get-HPOVSnmpV3User -Name $SnmpV3UserName -ErrorAction Stop } | Should -Not -Throw
            $CreatedSnmpV3User | Should -BeOfType HPOneView.Appliance.SnmpV3User

        }

        It "Will add a new SNMPv3 trap destination '$SnmpV3TrapDestinationAddress' to appliance" {

            { $Script:CreatedSnmpv3TrapDest = New-HPOVApplianceTrapDestination -Type SnmpV3 -SnmpV3User $CreatedSnmpV3User -Destination $SnmpV3TrapDestinationAddress } | Should -Not -Throw
            
            $CreatedSnmpv3TrapDest | Should -Be HPOneView.Appliance.SnmpV3TrapDestination
            
            $CreatedSnmpv3TrapDest.DestinationAddress | Should -Be $SnmpV3TrapDestinationAddress
            $CreatedSnmpv3TrapDest.SnmpV3User.Id | Should -Be $CreatedSnmpV3User.id

        }

        It "Will validate SNMPv3 trap destination '$SnmpV3TrapDestinationAddress' exists" {

            { $script:Snmpv3TrapDestinationResource = Get-HPOVApplianceTrapDestination -Destination $SnmpV3TrapDestinationAddress -ErrorAction Stop } | Should -Not -Throw

            $Snmpv3TrapDestinationResource | Should -Be HPOneView.Appliance.SnmpV3TrapDestination

            $Snmpv3TrapDestinationResource.DestinationAddress | Should -Be $SnmpV3TrapDestinationAddress
            $Snmpv3TrapDestinationResource.SnmpV3User.Id | Should -Be $CreatedSnmpV3User.id

        }
    
    }

    Context "Remove appliance SNMP trap settings" {

        It "Will remove SNMPv1 trap destination '$SnmpV1TrapDestinationAddress'" {

            { Get-HPOVApplianceTrapDestination -Destination $SnmpV1TrapDestinationAddress -ErrorAction Stop | Remove-HPOVApplianceTrapDestination -Confirm:$false } | Should -Not -Throw

        }

        It "Will attempt to remove SNMPv3 user '$SnmpV3UserName'" {

            $ExpectedExceptionMessage = "The SNMPv3 user you are trying to remove is associated with an existing SNMPv3 Trap Destination."

            { Get-HPOVSnmpV3User -Name $SnmpV3UserName -ErrorAction Stop | Remove-HPOVSnmpV3User -Confirm:$false } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will remove SNMPv3 trap destination '$SnmpV3TrapDestinationAddress'" {

            { Get-HPOVApplianceTrapDestination -Destination $SnmpV3TrapDestinationAddress -ErrorAction Stop | Remove-HPOVApplianceTrapDestination -Confirm:$false } | Should -Not -Throw
        }

        It "Will remove SNMPv3 user '$SnmpV3UserName'" {

            { Get-HPOVSnmpV3User -Name $SnmpV3UserName -ErrorAction Stop | Remove-HPOVSnmpV3User -Confirm:$false } | Should -Not -Throw 

        }

    }

    Context "Configure Remote Syslog" {

        AfterAll {

            { $Script:SyslogSettings = Get-HPOVRemoteSyslog } | Should -Not -Throw
            $SyslogSettings.remoteSyslogDestination = $null
            $SyslogSettings.remoteSyslogPort = $null
            { sr -Uri /rest/remote-syslog -method PUT -body $SyslogSettings | Wait-HPOVTaskComplete } | Should -Not -Throw

        }
    
        It "Will configure Remote Syslog settings" {
    
            { $Script:SetRemoteSyslogResults = Set-HPOVRemoteSyslog -Destination 192.168.19.2 } | Should -Not -Throw
            $SetRemoteSyslogResults | Should -Not -BeNullOrEmpty
            $SetRemoteSyslogResults.category | Should -Be 'tasks'
            
            if ($SetRemoteSyslogResults.taskState -ne "Completed") {

                DisplayTaskError $SetRemoteSyslogResults

            }

            $SetRemoteSyslogResults.taskState | Should -Be Completed
    
        }

        It "Will get Remote Syslog Settings" {
        
            { $Script:RemoteSyslogSettings = Get-HPOVRemoteSyslog } | Should -Not -Throw
            $RemoteSyslogSettings | Should -Not -BeNullOrEmpty
            $RemoteSyslogSettings.type | Should -Be 'RemoteSyslog'
            $RemoteSyslogSettings.remoteSyslogDestination | Should -Be '192.168.19.2'
        
        }

        It "Will disable Remote Syslog" {
        
            { $Script:DisableRemoteSyslogResults = Disable-HPOVRemoteSyslog } | Should -Not -Throw
            $DisableRemoteSyslogResults | Should -Not -BeNullOrEmpty
            $DisableRemoteSyslogResults.category | Should -Be 'tasks'

            if ($DisableRemoteSyslogResults.taskState -ne "Completed") {

                DisplayTaskError $DisableRemoteSyslogResults

            }

            $DisableRemoteSyslogResults.taskState | Should -Be Completed
        
        }

        It "Will validate Remote Syslog is disabled" {
        
            { $Script:RemoteSyslogSettings = Get-HPOVRemoteSyslog } | Should -Not -Throw
            $RemoteSyslogSettings | Should -Not -BeNullOrEmpty
            $RemoteSyslogSettings.enabled | Should -Be $false
        
        }

        It "Will enable Remote Syslog" {
        
            { $Script:DisableRemoteSyslogResults = Enable-HPOVRemoteSyslog } | Should -Not -Throw
            $DisableRemoteSyslogResults | Should -Not -BeNullOrEmpty
            $DisableRemoteSyslogResults.category | Should -Be 'tasks'

            if ($DisableRemoteSyslogResults.taskState -ne "Completed") {

                DisplayTaskError $DisableRemoteSyslogResults

            }

            $DisableRemoteSyslogResults.taskState | Should -Be Completed
        
        }

        It "Will validate Remote Syslog is enabled" {
        
            { $Script:RemoteSyslogSettings = Get-HPOVRemoteSyslog } | Should -Not -Throw
            $RemoteSyslogSettings | Should -Not -BeNullOrEmpty
            $RemoteSyslogSettings.enabled | Should -Be $true
        
        }
    
    }

}

# APPLIANCE BASE, Baseline management
Describe "Firmware Baseline Management" -Tag All, Baseline, ApplianceBase {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        if (Get-HPOVBaselineRepository -type External) {

            Get-HPOVBaselineRepository -type External | Remove-HPOVExternalRepository -Confirm:$false | Wait-HPOVTaskComplete

        }

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Validate Default Baseline resource" {
    
        It "Will validate Default Baseline exists" {
    
            { $Script:DefaultBaselineObject = Get-HPOVBaseline -File $ExistingBaselineName -ErrorAction Stop } | Should -Not -Throw
            $DefaultBaselineObject | Should -Not -BeNullOrEmpty
            $DefaultBaselineObject.category | Should -Be 'firmware-drivers'
    
        }
    
    }

    Context "Upload Support Pack for ProLiant" {

        It "Will attempt to upload SPP Baseline using invalid file" {

            $ExpectedExceptionMessage = "Cannot validate argument on parameter 'File'."
            
            { Add-HPOVBaseline -File Foo.iso } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will upload SPP Baseline" {

            { Add-HPOVBaseline -File $SppFile -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will validate SPP Baseline exists using -IsoFileName alias" {

            { $Script:BaselineObject = Get-HPOVBaseline -IsoFileName $SppFile.name -ErrorAction Stop } | Should -Not -Throw
            (Measure-Object -InputObject $BaselineObject).Count | Should -BeExactly 1
            $BaselineObject.isoFileName | Should -BeExactly $SppFile.Name

        }

        It "Will attempt to retrieve invalid Baseline Filename" {

            $ExpectedExceptionMessage = "The Baseline resource name 'foo.iso' was not found on '{0}' appliance." -f $Appliance1
            
            { Get-HPOVBaseline -File foo.iso -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will attempt upload same SPP File and throw error" {

            $ExpectedExceptionMessage = "The Baseline '{0}' is already present on the appliance" -f $SppFile.Name
            
            { Add-HPOVBaseline -File $SppFile -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage

        }

    }

    Context "Custom Baseline Management" {
    
        It "Will attempt to create a custom baseline with invalid baseline object name" {
    
            #$ExpectedExceptionMessage = "The Baseline name 'foo' was not found."
            
            { New-HPOVCustombaseline -BaselineName InvalidBaseline -SourceBaseline foo -Hotfixes bar.scexe } | Should -Throw
    
        }

        It "Will attempt to create a custom baseline with invalid hotfix object" {

            $SourceBaseline = Get-HPOVBaseline -File $ExistingBaselineName
        
            $ExpectedExceptionMessage = "The provided Hotfix 'bar.scexe' was not found."
            
            { New-HPOVCustomBaseline -BaselineName InvalidBaseline -SourceBaseline $SourceBaseline -hotfixes bar.scexe } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will upload hotfix '$($HotfixToUpload.Name)' to appliance" {
        
            { $Script:HotfixUploadResults = Add-HPOVBaseline -File $HotfixToUpload } | Should -Not -Throw
            $HotfixUploadResults | Should -Not -BeNullOrEmpty
            $HotfixUploadResults.category | Should -Be 'tasks'

            if ($HotfixUploadResults.taskState -ne "Completed") {

                DisplayTaskError $HotfixUploadResults

            }

            $HotfixUploadResults.taskState | Should -Be Completed
        
        }

        It "Will validate hotfix was uploaded using -HotfixesOnly parameter" {
        
            { $Script:Results = Get-HPOVBaseline -HotfixesOnly | Where-Object uuid -eq $HotfixToUpload.Name.Replace('.scexe', $null).Replace('.exe', $null).Replace('.rpm',$null).Replace('.','_') } | Should -Not -Throw

            $Results | Should -Not -BeNullOrEmpty
            $Results.bundleType | Should -Be Hotfix
            $Results.bundleSize | Should -BeGreaterThan 0
        
        }

        It "Will create custom baseline '$CustomBaselineName' using '$ExistingBaselineName' and '$($HotfixToUpload.Name)' [#148]" {
        
            { $Script:SourceBaseline = Get-HPOVBaseline -File $ExistingBaselineName -ErrorAction Stop } | Should -Not -Throw
            { $Script:Hotfix1 = Get-HPOVBaseline -File $HotfixtoUpload.Name -ErrorAction Stop } | Should -Not -Throw

            { $Script:CreateCustomBaselineResults = New-HPOVCustomBaseline -BaselineName $CustomBaselineName -SourceBaseline $SourceBaseline -Hotfixes $Hotfix1 } | Should -Not -Throw
            $CreateCustomBaselineResults | Should -Not -BeNullOrEmpty
            $CreateCustomBaselineResults.category | Should -Be 'tasks'

            if ($CreateCustomBaselineResults.taskState -ne "Completed") {

                DisplayTaskError $CreateCustomBaselineResults

            }

            $CreateCustomBaselineResults.taskState | Should -Be Completed
        
        }
    
    }

    Context "Manage External Repository" {

        It "Will validate Internal Repository exists" {

            { $Script:InternalRepository = Get-HPOVBaselineRepository -Type Internal -ErrorAction Stop } | Should -Not -Throw
            $InternalRepository | Should -Not -BeNullOrEmpty
            $InternalRepository.name | Should -Be Internal

        }

        It "Will add an external repository using HTTP protocol and anonymous auth" {

            $Params = @{

                Name      = $ExternalRepositoryName;
                Hostname  = $ExternalRepositoryHostname;
                Directory = $ExternalAnonymousRepoDirectory;
                Http      = $True;

            }

            { $Script:Results = New-HPOVExternalRepository @Params } | Should -Not -Throw

            $Results | Should -Not -BeNullOrEmpty
            $Results.category | Should -Be 'tasks'

            # Implement workaround for appliance "refresh race condition"
            if ($Results.taskState -ne "Completed" -and $Results.errorCode -ne 'REPOSITORY_RFRESH_EXCEPTION') {

                DisplayTaskError $Results

            }

            if ($Results.errorCode -eq 'REPOSITORY_RFRESH_EXCEPTION')
            {
            
                $true | Should -Be $true
            
            }

            else
            {
            
                $Results.taskState | Should -Be Completed
            
            }            

        }

        It "Will refresh the external repository" {
        
            { $Script:Results = Get-HPOVBaselineRepository -Type External | Update-HPOVExternalRepository -Confirm:$False } | Should -Not -Throw

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed
        
        }

        It "Will remove added external repository" {

            { $Script:RemoveResults = Get-HPOVBaselineRepository -Name $ExternalRepositoryName -ErrorAction Stop | Remove-HPOVExternalRepository -Confirm:$false } | Should -Not -Throw

            
            $RemoveResults | Should -Not -BeNullOrEmpty
            $RemoveResults.category | Should -Be 'tasks'

            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }

            $RemoveResults.taskState | Should -Be Completed

        }
        
        It "Will add an external repository using HTTPS protocol and standard auth (no PSCredential)" {

            $Script:ShouldSkipExtRepoRemove = $false

            $TrapableExceptionMessage = 'Unable to access files on external repository due to internal error.'

            $Params = @{

                Name        = $ExternalRepositoryName;
                Hostname    = $ExternalRepositoryHostname;
                Directory   = $ExternalRepositoryDirectory;
                Username    = $ExternalRepositoryUsername;
                Password    = $ExternalRepositoryPassword;
                Certificate = $ExternalRepositoryBase64Cert

            }

            # Implement as a workaround for appliance internal error
            Try
            {
            
                $Script:Results = New-HPOVExternalRepository @Params

                $Results | Should -Not -BeNullOrEmpty
                $Results.category | Should -Be 'tasks'

                if ($Results.taskState -ne "Completed") {

                    DisplayTaskError $Results

                }

                $Results.taskState | Should -Be Completed
            
            }
            
            Catch
            {

                $_CaughtError = $_.PSObject.Copy()
            
                if ($_.Exception -match $TrapableExceptionMessage)
                {

                    $ShouldSkipExtRepoRemove = $true

                }

                else
                {

                    { Throw $_CaughtError } | Should -Not -Throw

                }
            
            }

        }

        It "Will remove added external repository" -Skip:$ShouldSkipExtRepoRemove {

            { $Script:RemoveResults = Get-HPOVBaselineRepository -Name $ExternalRepositoryName -ErrorAction Stop | Remove-HPOVExternalRepository -Confirm:$false } | Should -Not -Throw

            
            $RemoveResults | Should -Not -BeNullOrEmpty
            $RemoveResults.category | Should -Be 'tasks'

            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }

            $RemoveResults.taskState | Should -Be Completed

        }

        It "Will add an external repository using HTTPS protocol and standard auth (PSCredential)" {

            $Params = @{

                Name        = $ExternalRepositoryName;
                Hostname    = $ExternalRepositoryHostname;
                Directory   = $ExternalRepositoryDirectory;
                Credential  = $ExternalRepositoryPSCredential;
                Certificate = $ExternalRepositoryBase64Cert

            }

            { $Script:Results = New-HPOVExternalRepository @Params } | Should -Not -Throw

            $Results | Should -Not -BeNullOrEmpty
            $Results.category | Should -Be 'tasks'

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will modify the existing external repository name with an updated value (PSCredential)" {

            $NewName = $ExternalRepositoryName + "_Updated"

            $Params = @{

                Name       = $NewName;
                Credential = $ExternalRepositoryPSCredential

            }

            { $Script:RemoveResults = Get-HPOVBaselineRepository -Name $ExternalRepositoryName -ErrorAction Stop | Set-HPOVExternalRepository @Params -Confirm:$false } | Should -Not -Throw

            
            $RemoveResults | Should -Not -BeNullOrEmpty
            $RemoveResults.category | Should -Be 'tasks'

            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }

            $RemoveResults.taskState | Should -Be Completed

        }

        It "Will validate repository resource name was updated to new value" {

            $NewName = $ExternalRepositoryName + "_Updated"

            { Get-HPOVBaselineRepository -Name $NewName -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will remove added external repository" {

            $NewName = $ExternalRepositoryName + "_Updated"

            { $Script:RemoveResults = Get-HPOVBaselineRepository -Name $NewName -ErrorAction Stop | Remove-HPOVExternalRepository -Confirm:$false } | Should -Not -Throw

            
            $RemoveResults | Should -Not -BeNullOrEmpty
            $RemoveResults.category | Should -Be 'tasks'

            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }

            $RemoveResults.taskState | Should -Be Completed

        }

    }

    Context "Remove Baselines" {
    
        It "Will remove Custom Baseline" {

            { Get-HPOVBaseline -File $CustomBaselineName -ErrorAction Stop | Remove-HPOVBaseline -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

        }

        It "Will remove Hotfix resource" {

            { Get-HPOVBaseline -File $HotfixToUpload.Name -ErrorAction Stop | Remove-HPOVBaseline -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

        }
        
        It "Will remove Baseline resource" {

            { Get-HPOVBaseline -File $SppFile.Name -ErrorAction Stop | Remove-HPOVBaseline -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

        }
    
    }

}

# APPLIANCE BASE, Remote Support
Describe "Manage Remote Support" -Tag ApplianceBase, RemoteSupport {
    
    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        if (-not(Get-HPOVRemoteSupportContact -Name 'Chris Lynch' -ErrorAction SilentlyContinue)) {

            { New-HPOVRemoteSupportContact -Firstname Chris -Lastname Lynch -Email clynch@company.com -PrimaryPhone 123-456-7890 -AlternatePhone 098-765-4321 -Language en -Default } | Should -Not -Throw
            
        }

        if (-not(Get-HPOVRemoteSupportContact -Name 'Phil Marshall' -ErrorAction SilentlyContinue)) {

            { New-HPOVRemoteSupportContact -Firstname Phil -Lastname Marshall -Email pmMarshall@company.com -PrimaryPhone 123-456-7890 -AlternatePhone 098-765-4321 -Language en } | Should -Not -Throw

        }

        if (-not (Get-HPOVRemoteSupport).enableRemoteSupport) {

            Microsoft.PowerShell.Utility\write-host "Enabling Remote Support"

            { Set-HPOVRemoteSupportDefaultSite -AddressLine1 "3000 Hanover St." -City "Palo Alto" -State CA -PostalCode 94304 -Country US -TimeZone "US/Pacific" } | Should -Not -Throw
            
            { Set-HPOVRemoteSupport -Company 'Hewlett-Packard Enterprise' } | Should -Not -Throw

        }    

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    #Need to have a default Contact that cannot be removed, but is not impacted by adding these contacts
    Context "Create Remote Support Contacts" {

        It "Will create DC Primary contact user, Bob Smith" {

            { $Script:RemoteSupportPrimaryContactResults = New-HPOVRemoteSupportContact -Firstname Bob -Lastname Smith -Email bob.smith@company.com -PrimaryPhone 123-456-7890 -AlternatePhone 098-765-4321 -Language en } | Should -Not -Throw
            $RemoteSupportPrimaryContactResults.firstName | Should -Be 'Bob'
            $RemoteSupportPrimaryContactResults.lastName | Should -Be 'Smith'

        }

        It "Will create DC Secondary contact user, Shiela Jones" {

            { $Script:RemoteSupportContactResults = New-HPOVRemoteSupportContact -Firstname Shiela -Lastname Jones -Email Shiela.Jones@company.com -PrimaryPhone 123-456-7891 -AlternatePhone 198-765-4321 -Language en } | Should -Not -Throw
            $RemoteSupportContactResults.firstName | Should -Be 'Shiela'
            $RemoteSupportContactResults.lastName | Should -Be 'Jones'

        }

        It "Will validate Remote Support contacts are defined" {

            { $Script:RemoteSuportContacts = Get-HPOVRemoteSupportContact -ErrorAction Stop } | Should -Not -Throw
            $RemoteSuportContacts | Should -Not -BeNullOrEmpty
            $RemoteSuportContacts.count | Should -BeGreaterThan 1

        }

    }

    Context "Define Default datacenter location" {

        It "Will set default Data Center location to Palo Alto" -Skip {
        
            { $Script:Results = Set-HPOVRemoteSupportDefaultSite -AddressLine1 "3000 Hanover St." -City "Palo Alto" -State CA -PostalCode 94304 -Country US -TimeZone "US/Pacific" } | Should -Not -Throw
            $Script:Results | Should -Not -BeNullOrEmpty
            $Script:Results.category | Should -Be 'support'
        
        }

    }

    Context "Manage Remote Support Partners" {
    
        It "Will add New Reseller, 'ZZ DUMMY UK Branch Release Testing' with PartnerID '40667051'" -Skip {
    
            { $Script:Results = New-HPOVRemoteSupportPartner -Name 'ZZ DUMMY UK Branch Release Testing' -Type Reseller -PartnerId 40667051 } | Should -Not -Throw
            $Script:Results | Should -Not -BeNullOrEmpty
            $Script:Results.category | Should -Be 'support'
            $Script:Results.type | Should -Be 'ChannelPartner'
    
        }
    
    }

    Context "Manage Remote Support collection schedules" {
    
        It "Will set Remote Support collection schedules to 14 days from today" -Skip {
    
            $Date = [DateTime]::Now.AddDays(14)
            { $Script:Results = Set-HPOVRemoteSupportDataCollectionSchedule -DateTime $Date } | Should -Not -Throw
            $Results | Should -Not -BeNullOrEmpty
            $Results.category | Should -Be 'tasks'

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed
    
        }
    
    }

    Context "Remove created Remote Support resources" {
    
        It "Will remove 'Bob Smith' contact" {
    
            { $Script:Result = Get-HPOVRemoteSupportContact -Name 'Bob Smith' -ErrorAction Stop | Remove-HPOVRemoteSupportContact -Confirm:$false } | Should -Not -Throw
            $Result | Should -Not -BeNullOrEmpty
            $Result.Message | Should -Be 'Resource deleted successfully.'
    
        }
    
        It "Will remove 'Shiela Jones' contact" {
    
            { $Script:Result = Get-HPOVRemoteSupportContact -Name 'Shiela Jones' -ErrorAction Stop | Remove-HPOVRemoteSupportContact -Confirm:$false } | Should -Not -Throw
            $Result | Should -Not -BeNullOrEmpty
            $Result.Message | Should -Be 'Resource deleted successfully.'
    
        }

        It "Will remove Reseller Partner" -Skip {
        
            { $Script:Result = Get-HPOVRemoteSupportPartner -Name 'ZZ DUMMY UK Branch*' -ErrorAction Stop | Remove-HPOVRemoteSupportPartner -Confirm:$false } | Should -Not -Throw
            $Result | Should -Not -BeNullOrEmpty
            $Result.Message | Should -Be 'Resource deleted successfully.'
        
        }
    
    }

    Context "Validate Remote Support class objects" {

        It "Will create HPOneView.RemoteSupport.ContractAndWarrantyStatus object using minimum .stor" {

            $RemoteSupportContractWarrantyStatusObject1 = New-Object HPOneView.RemoteSupport.ContractAndWarrantyStatus (
                                                                                                                        'My Host', 
                                                                                                                        ('/rest/server-hardware/{0}' -f [System.GUID]::NewGuid().ToString()), 
                                                                                                                        'SN12345ABAB', 
                                                                                                                        $null, 
                                                                                                                        $null, 
                                                                                                                        (New-Object HPOneView.Library.ApplianceConnection)
                                                                                                                       )
            
            $RemoteSupportContractWarrantyStatusObject1 | Should -Not -BeNullOrEmpty
            $RemoteSupportContractWarrantyStatusObject1.ResourceName | Should -Not -BeNullOrEmpty
            $RemoteSupportContractWarrantyStatusObject1.ResourceUri | Should -Not -BeNullOrEmpty
            $RemoteSupportContractWarrantyStatusObject1.ResourceSerialNumber | Should -Not -BeNullOrEmpty

        }

        It "WIll create HPOneView.RemoteSupport.ContractAndWarrantyStatus object with maximum .stor" {

            $RemoteSupportContractWarrantyStatusObject2 = New-Object HPOneView.RemoteSupport.ContractAndWarrantyStatus (
                                                                                                                        'MyName',
                                                                                                                        '/rest/support.server-hardware/GUID',
                                                                                                                        'AB123456789',
                                                                                                                        'entitlementPackage',
                                                                                                                        'entitlementStatus',
                                                                                                                        'offerStatus',
                                                                                                                        'coverageDays',
                                                                                                                        'coverageHoursDay1to5',
                                                                                                                        'coverageHoursDay6',
                                                                                                                        'coverageHoursDay7',
                                                                                                                        'responseTimeDay1to5',
                                                                                                                        'responseTimeDay6',
                                                                                                                        'responseTimeDay7',
                                                                                                                        [DateTime]::Now,
                                                                                                                        [DateTime]::Now,
                                                                                                                        [DateTime]::Now,
                                                                                                                        [DateTime]::Now,
                                                                                                                        'countryCode',
                                                                                                                        'obligationType',
                                                                                                                        'entitlementKey',
                                                                                                                        'obligationId',
                                                                                                                        $true,
                                                                                                                        $true,
                                                                                                                        'responseTimeHolidays',
                                                                                                                        'explanation',
                                                                                                                        (New-Object HPOneView.Library.ApplianceConnection)
                                                                                                                       )

            $RemoteSupportContractWarrantyStatusObject2 | Should -Not -BeNullOrEmpty
            $RemoteSupportContractWarrantyStatusObject2.ResourceName | Should -Not -BeNullOrEmpty
            $RemoteSupportContractWarrantyStatusObject2.ResourceUri | Should -Not -BeNullOrEmpty
            $RemoteSupportContractWarrantyStatusObject2.ResourceSerialNumber | Should -Not -BeNullOrEmpty

        }

    }

}

# APPLIANCE BASE, Facilities
Describe "Facilities and Remote Support DataCenter Configuration" -Tag All, ApplianceBase, Facilities {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        if (-not (Get-HPOVRemoteSupportContact -Name $DataCenter2Contact1Name -ErrorAction SilentlyContinue))
        {

            { $Script:RemoteSupportPrimaryContactResults = New-HPOVRemoteSupportContact -Firstname ($DataCenter2Contact1Name.Split(' '))[0] -Lastname ($DataCenter2Contact1Name.Split(' '))[1] -Email ('{0}@company.com' -f [String]::Join('',$DataCenter2Contact1Name.Split(' '))) -PrimaryPhone 123-456-7890 -AlternatePhone 098-765-4321 -Language en } | Should -Not -Throw
        
        }

        if (-not (Get-HPOVRemoteSupportContact -Name $DataCenter2Contact2Name -ErrorAction SilentlyContinue))
        {

            { $Script:RemoteSupportPrimaryContactResults = New-HPOVRemoteSupportContact -Firstname ($DataCenter2Contact2Name.Split(' '))[0] -Lastname ($DataCenter2Contact2Name.Split(' '))[1] -Email ('{0}@company.com' -f [String]::Join('',$DataCenter2Contact2Name.Split(' '))) -PrimaryPhone 123-456-7890 -AlternatePhone 098-765-4321 -Language en } | Should -Not -Throw

        }

        $Rack1UnmanagedDevices | ForEach-Object {

            New-HPOVUnmanagedDevice @_ | Out-Null

        }

    }

    AfterAll {

        $Rack1UnmanagedDevices | ForEach-Object {

            Get-HPOVUnmanagedDevice -Name $_.Name -ErrorAction Stop | Remove-HPOVUnmanagedDevice -Confirm:$false | Out-Null

        }
        
        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions } | Should -Not -Throw

        }

    }

    Context "Create DataCenter" {

        It "Will validate $DataCenter1Name does not -Exist" {
        
            $ExpectedExceptionMessage = 'The "{0}" datacenter was not found on {1}.  Please check the name and try again.' -f $DataCenter1Name, $Appliance1
            { Get-HPOVDataCenter -Name $DataCenter1Name -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }
    
        It "Will create new DataCenter, $DataCenter1Name" {
    
            { $Script:CreateResults = New-HPOVDataCenter -Name $DataCenter1Name -Width $DataCenter1Width -Depth $DataCenter1Depth -DefaultVoltage $DataCenter1Voltage -PowerCosts $DataCenter1PowerCosts -CoolingCapacity $DataCenter1CoolingCapacity } | Should -Not -Throw
            $CreateResults | Should -Not -BeNullOrEmpty
            $CreateResults.category | Should -Be datacenters
            $CreateResults.name | Should -Be $DataCenter1Name
            $ExpectedWidth = [Math]::Round($DataCenter1Width * .3048 * 1000, 2)
            $ExpectedDepth = [Math]::Round($DataCenter1Depth * .3048 * 1000, 2)
            $CreateResults.width | Should -Be $ExpectedWidth
            $CreateResults.depth | Should -Be $ExpectedDepth

        }

        It "Will validate DataCenter exists" {
        
            { $Script:DataCenterObj = Get-HPOVDataCenter -Name $DataCenter1Name -ErrorAction Stop } | Should -Not -Throw
            $DataCenterObj.category | Should -Be datacenters
            $DataCenterObj.name | Should -Be $DataCenter1Name
        
        }

        It "Will create new DataCenter $DataCenter2Name with Remote Support Location" {

            $NewDC2Params = @{

                Name             = $DataCenter2Name;
                Width            = $DataCenter2Width;
                Depth            = $DataCenter2Depth;
                Millimeters      = $True;
                DefaultVoltage   = $DataCenter2Voltage;
                PowerCosts       = $DataCenter2PowerCosts;
                CoolingCapacity  = $DataCenter2CoolingCapacity;
                Address1         = $DataCenter2Address1;
                Address2         = $DataCenter2Address2;
                City             = $DataCenter2City;
                State            = $DataCenter2State;
                Country          = $DataCenter2Country;
                PostCode         = $DataCenter2Zip;
                TimeZone         = $DataCenter2TimeZone;
                PrimaryContact   = (Get-HPOVRemoteSupportContact -Name $DataCenter2Contact1Name -EA Stop)
                SecondaryContact = (Get-HPOVRemoteSupportContact -Name $DataCenter2Contact2Name -EA Stop)

            }
    
            { $Script:CreateResults = New-HPOVDataCenter @NewDC2Params } | Should -Not -Throw
            $CreateResults.category | Should -Be datacenters

            { $Script:DataCenterObj = Get-HPOVDataCenter -Name $DataCenter2Name -ErrorAction Stop } | Should -Not -Throw
            $DataCenterObj.name | Should -Be $DataCenter2Name
            $DataCenterObj.width | Should -Be $DataCenter2Width
            $DataCenterObj.depth | Should -Be $DataCenter2Depth
            $DataCenterObj.RemoteSupportLocation.primaryContactUri | Should -Be (Get-HPOVRemoteSupportContact -Name $DataCenter2Contact1Name -EA Stop).uri
            $DataCenterObj.RemoteSupportLocation.secondaryContactUri | Should -Be (Get-HPOVRemoteSupportContact -Name $DataCenter2Contact2Name -EA Stop).uri
    
        }
    
    }

    Context "Create new Racks" {

        It "Will validate $Rack1Name does not -Exist" {
        
            $ExpectedExceptionMessage = 'The "{0}" rack was not found on {1}.  Please check the name and try again.' -f $Rack1Name, $Appliance1
            { Get-HPOVRack -Name $Rack1Name -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }
    
        It "Will create new Rack1" {
    
            $Params = @{

                Name         = $Rack1Name;
                Model        = $Rack1Model;
                ThermalLimit = $Rack1ThermalLimit;
                SerialNumber = $Rack1SerialNumber;
                PartNumber   = $Rack1PartNumber;
                Depth        = $Rack1Depth;
                Height       = $Rack1Height;
                UHeight      = $Rack1UHeight;
                Width        = $Rack1Width
                
            }

            { $Script:CreateResults = New-HPOVRack @Params } | Should -Not -Throw
    
        }

        It "Will validate $Rack1Name exists" {
        
            { $Script:Rack1Object = Get-HPOVRack -Name $Rack1Name -ErrorAction Stop } | Should -Not -Throw
        
        }

        It "Will validate '$Rack1Name' Settings: ThermalLimit" {

            $Rack1Object.thermalLimit | Should -BeExactly $Rack1ThermalLimit

        } 
        
        It "Will validate '$Rack1Name' Settings: SerialNumber" {

            $Rack1Object.serialNumber | Should -BeExactly $Rack1SerialNumber

        } 
        
        It "Will validate '$Rack1Name' Settings: PartNumber" {

            $Rack1Object.partNumber | Should -BeExactly $Rack1PartNumber

        } 
        
        It "Will validate '$Rack1Name' Settings: Model" {

            $Rack1Object.model | Should -BeExactly $Rack1Model

        } 
        
        It "Will validate '$Rack1Name' Settings: Depth" {

            $Rack1Object.depth | Should -BeExactly $Rack1Depth

        } 
        
        It "Will validate '$Rack1Name' Settings: Height" {

            $Rack1Object.height | Should -BeExactly $Rack1Height
            $Rack1Object.uHeight | Should -BeExactly $Rack1UHeight

        } 
        
        It "Will validate '$Rack1Name' Settings: Width" {

            $Rack1Object.width | Should -BeExactly $Rack1Width

        } 

        It "Will add $Rack1Name rack to $DataCenter1Name datacenter" {
        
            { $Script:Rack1Object = Get-HPOVRack -Name $Rack1Name -ErrorAction Stop } | Should -Not -Throw
            { $Script:DC = Get-HPOVDataCenter -Name $DataCenter1Name -ErrorAction Stop } | Should -Not -Throw

            { $Script:AddToDCResults = Add-HPOVRackToDataCenter -InputObject $Rack1Object -DataCenter $DC -X $Rack1XCordinate -Y $Rack1YCordinate } | Should -Not -Throw
            $AddToDCResults | Should -Not -BeNullOrEmpty
            $AddToDCResults.category | Should -Be datacenters
        
        }
    
    }

    Context "Manage Rack and Rack resources" {

        It "Will add resources to Rack1" {

            { $Script:Rack1Object = Get-HPOVRack -Name $Rack1Name -ErrorAction Stop } | Should -Not -Throw

            $_U = 1

            ForEach ($_Resource in $Rack1UnmanagedDevices) {

                { $Script:RackResource = Get-HPOVUnmanagedDevice -Name $_Resource.Name -ErrorAction Stop } | Should -Not -Throw

                { $Script:AddToRackResults = Add-HPOVResourceToRack -InputObject $RackResource -Rack $Rack1Object -ULocation $_U } | Should -Not -Throw

                $_U += $_Resource.Height

            }
    
        }

        It "Will move rack member resource $($Rack1UnmanagedDevices[$Rack1UnmanagedDevices.count - 1].Name) to new U Location" {

            { $Script:Rack1Member = Get-HPOVRack -Name $Rack1Name -ErrorAction Stop | Get-HPOVRackMember -Name $Rack1UnmanagedDevices[$Rack1UnmanagedDevices.count - 1].Name -ErrorAction Stop} | Should -Not -Throw

            $Rack1MemberOriginalLocation = $Rack1Member.ULocation

            { $Script:ModifyRackLocation = Set-HPOVRackMemberLocation -InputObject $Rack1Member -ULocation ($Rack1Member.ULocation + 5) } | Should -Not -Throw
            $ModifyRackLocation | Should -BeOfType HPOneView.Facilities.RackMember
            $ModifyRackLocation.ULocation | Should -Be ($Rack1MemberOriginalLocation + 5)
        
        }

        It "Will remove rack member resource $($Rack1UnmanagedDevices[$Rack1UnmanagedDevices.count - 1].Name) from rack" {
        
            { $Script:Rack1Member = Get-HPOVRack -Name $Rack1Name -ErrorAction Stop | Get-HPOVRackMember -Name $Rack1UnmanagedDevices[$Rack1UnmanagedDevices.count - 1].Name -ErrorAction Stop } | Should -Not -Throw

            { $Script:RemoveRackMemberResults = Remove-HPOVRackMember -InputObject $Rack1Member -Confirm:$false } | Should -Not -Throw
            $RemoveRackMemberResults.category | Should -Be racks
            ($RemoveRackMemberResults.rackMounts | Where-Object mountUri -eq $Rack1Member.uri) | Should -BeNullOrEmpty
        
        }
    
    }

    Context "Modify Datacenter settings" {
    
        It "Will attempt to set new datacenter setting for $DataCenter1Name without custom Electrical rating type" {

            $ExpectedExceptionMessage = 'The ElectricalDerating paraemter was used with a custom value, without providing the ElectricalDeratingType parameter.  ElectricalDerating will not be set to the value.'

            { $Script:DC = Get-HPOVDataCenter -Name $DataCenter1Name -ErrorAction Stop } | Should -Not -Throw

            $NewDCWidth = $DC.width + ([Math]::Round(10 * .3048 * 1000, 2))
            $NewDCElectricalDerating = 15
            $NewDCDefaultVoltage = 240

            { $Script:EditDCResults = $DC | Set-HPOVDataCenter -Width $NewDCWidth -Millimeters -ElectricalDerating $NewDCElectricalDerating -DefaultVoltage $NewDCDefaultVoltage } | Should -Throw $ExpectedExceptionMessage
    
        }

        It "Will set new datacenter setting for $DataCenter1Name" {

            { $Script:DC = Get-HPOVDataCenter -Name $DataCenter1Name -ErrorAction Stop } | Should -Not -Throw

            $NewDCWidth = $DC.width + ([Math]::Round(10 * .3048 * 1000, 2))
            $NewDCElectricalDerating = 22
            $NewDCElectricalDeratingType = 'Custom'
            $NewDCDefaultVoltage = 240

            { $Script:EditDCResults = $DC | Set-HPOVDataCenter -Width $NewDCWidth -Millimeters -ElectricalDeratingType $NewDCElectricalDeratingType -ElectricalDerating $NewDCElectricalDerating -DefaultVoltage $NewDCDefaultVoltage } | Should -Not -Throw
            
            $EditDCResults.width | Should -Be $NewDCWidth
            $EditDCResults.deratingType | Should -Be $NewDCElectricalDeratingType
            $EditDCResults.deratingPercentage | Should -Be $NewDCElectricalDerating
            $EditDCResults.defaultPowerLineVoltage | Should -Be $NewDCDefaultVoltage

        }

        It "Will update $DataCenter2Name datacenter Remote Support Settings" {

            $NewCity    = "Santa Ana"
            $NewZipCode = "92701"
        
           { $Script:UpdateResults = Get-HPOVDataCenter -Name $DataCenter2Name -ErrorAction Stop | Set-HPOVDataCenterRemoteSupport -PostCode $NewZipCode -City $NewCity } | Should -Not -Throw
            
            $UpdateResults.category | Should -Be tasks

            if ($UpdateResults.taskState -ne "Completed") {

                DisplayTaskError $UpdateResults

            }         

            $UpdateResults.taskState | Should -Be Completed
        
        }
    
    }

    Context "Remove facility resources" {
    
        It "Will remove $Rack1Name rack" {
    
            { $Script:RemoveResults = Get-HPOVRack -Name $Rack1Name -ErrorAction Stop | Remove-HPOVRack -Confirm:$false } | Should -Not -Throw
            $RemoveResults.StatusCode | Should -Be 204
            $RemoveResults.Message | Should -Be 'Resource deleted successfully.'
    
        }

        It "Will remove $DataCenter1Name datacenter" {
        
            { $Script:RemoveResults = Get-HPOVDataCenter -Name $DataCenter1Name -ErrorAction Stop | Remove-HPOVDataCenter -Confirm:$false } | Should -Not -Throw

            $RemoveResults.StatusCode | Should -Be 204
            $RemoveResults.Message | Should -Be 'Resource deleted successfully.'
        }

        It "Will remove $DataCenter2Name datacenter" {

            { $Script:RemoveResults = Get-HPOVDataCenter -Name $DataCenter2Name -ErrorAction Stop | Remove-HPOVDataCenter -Confirm:$false } | Should -Not -Throw

            $RemoveResults.StatusCode | Should -Be 204
            $RemoveResults.Message | Should -Be 'Resource deleted successfully.'
        
        }
    
    }

}

# POWERDEVICES
Describe "PowerDevice Configuration and Management" -Tag All, PowerDevice {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        if (Get-HPOVApplianceTrustedCertificate -Name $PowerDevice1Address -ErrorAction SilentlyContinue) {

            Get-HPOVApplianceTrustedCertificate -Name $PowerDevice1Address | Remove-HPOVApplianceTrustedCertificate -Confirm:$false

        }

    }

    Context "Add PowerDevice resource" {

        It "Will attempt to add a power device without appliance trusting certificate" -skip {

            $ExpectedExceptionMessage = 'The leaf certificate for {0} is untrusted by the appliance.  Either provide the -TrustLeafCertificate parameter or manually add the certificate using the Add-HPOVApplianceTrustedCertificate Cmdlet' -f $PowerDevice1Address

            # NEED TO FIND OUT WHY THIS IS NOT GENERATING AN EXCEPTION MESSAGE
            { Add-HPOVPowerDevice -Hostname $PowerDevice1Address -Username $PowerDeviceUsername -Password $PowerDevicePassword } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will add power device trusting the leaf certificate" -skip {

            { Add-HPOVPowerDevice -Hostname $PowerDevice1Address -Credential $PowerDevicePSCredential -TrustLeafCertificate } | Should -Not -Throw

        }

        It "Will validate the resouce was successfully added" -skip {

            { $Script:IPDUResource = Get-HPOVPowerDevice -Name $PowerDevice1Name -ErrorAction Stop } | Should -Not -Throw
            $IPDUResource | Should -Not -BeNullOrEmpty
            $IPDUResource.category | Should -Be power-devices
            $IPDUResource.name | Should -Be $PowerDevice1Name

        }

        It "Will get a power delivery device type, HpIpduCore" -skip {

            $Script:IPDUResource = $null

            { $Script:IPDUResource = Get-HPOVPowerDevice -Type HpIpduCore } | Should -Not -Throw
            $IPDUResource | Should -Not -BeNullOrEmpty
            $IPDUResource.category | Should -Be power-devices
            $IPDUResource.deviceType | Should -Be HpIpduCore

        }
        
    }

    Context "Remove PowerDevice resource" {

        It "Will remove the power delivery device" -skip {

            { $Script:RemoveTaskResults = Get-HPOVPowerDevice -Type HpIpduCore | Remove-HPOVPowerDevice -Confirm:$false } | Should -Not -Throw

            $RemoveTaskResults | Should -Not -BeNullOrEmpty
            $RemoveTaskResults.taskState | Should -Be Completed

        }

    }

}

# NETWORKING
Describe "Ethernet Network Testing" -Tag All,EthernetNetwork,Networking {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Create Ethernet network resources" {

        It "Will attempt to create Invalid Ethernet Network: '$EthernetNetworkName' ($InvalidEthernetVlan)" {

            $ThrowMessage = "Cannot validate argument on parameter 'VlanId'. The {0} argument is greater than the maximum allowed range of 4095. Supply an argument that is less than or equal to 4095 and then try the command again." -f $InvalidEthernetVlan
            { New-HPOVNetwork -Name $EthernetNetworkName -Type Ethernet -VlanID $InvalidEthernetVlan } | Should -Throw $ThrowMessage

        }

        It "Will create valid Ethernet network: '$EthernetNetworkName' with custom speeds." {

            { $Script:EthernetNetworkObject = New-HPOVNetwork -Name $EthernetNetworkName -Type Ethernet -VlanID $EthernetNetworkVlan -TypicalBandwidth 5000 -MaximumBandwidth 7500 } | Should -Not -Throw
            $EthernetNetworkObject | Should -Not -BeNullOrEmpty
            $EthernetNetworkObject.Name | Should -Be $EthernetNetworkName
            
            if ($EthernetNetworkObject.Status -ne "Completed") {

                DisplayTaskError $EthernetNetworkObject.Details

            }

            $EthernetNetworkObject.Status | Should -Be Completed

        }

        It "Will validate Ethernet Network TypicalBandwidth and MaximumBandwidth values [Public #179]" {
        
            { $Script:EthernetNetwork = Get-HPOVNetwork -Type Ethernet -Name $EthernetNetworkName -ErrorAction Stop } | Should -Not -Throw
            $EthernetNetwork.defaultMaximumBandwidth | Should -Be 7500
            $EthernetNetwork.defaultTypicalBandwidth | Should -Be 5000
        
        }

        It "Will create valid Ethernet iSCSI network: '$IscsiEthernetNetworkName' (US54189)" {

            { $Script:IscsiEthernetNetworkObject = New-HPOVNetwork -Name $IscsiEthernetNetworkName -Type Ethernet -VlanID $IscsiEthernetNetworkVlan -Purpose ISCSI } | Should -Not -Throw
            $IscsiEthernetNetworkObject | Should -Not -BeNullOrEmpty
            $IscsiEthernetNetworkObject.Name | Should -Be $IscsiEthernetNetworkName
            
            if ($IscsiEthernetNetworkObject.Status -ne "Completed") {

                DisplayTaskError $IscsiEthernetNetworkObject

            }         

            $IscsiEthernetNetworkObject.Status | Should -Be Completed

        }

        It "Will create valid bulk Ethernet networks: '$BulkEthernetNetworkNamePrefix' VLANs $BulkEthernetVlanIds" {

            { $Script:BulkEthernetNetworkObjects = New-HPOVNetwork -Name $BulkEthernetNetworkNamePrefix -VlanRange $BulkEthernetVlanIds -Purpose General } | Should -Not -Throw
            $BulkEthernetNetworkObjects | Should -Not -BeNullOrEmpty

            if ($BulkEthernetNetworkObjects.Status -ne "Completed") {

                DisplayTaskError $BulkEthernetNetworkObjects

            }            
            
            $BulkEthernetNetworkObjects.Status | Should -Be Completed

        }

        It "Will create networks from JSON file using -Import parameter" {

            $TestPath = "$TestDrive\import_networks.json"
            
            Set-Content $TestPath -value $NetworksToImport

            $NetworksToCreate = $NetworksToImport | ConvertFrom-Json
        
            { $Script:NetworkResults = New-HPOVNetwork -ImportFile $TestPath } | Should -Not -Throw

            ForEach ($Result in $NetworkResults) {

                if ($Result.Status -ne "Completed") {

                    DisplayTaskError $Result

                }         

                $Result.Status | Should -Be Completed

            }
        
        }

        It "Will validate imported Ethernet Network resources -Exist" {

            $NetworksToValidate = $NetworksToImport | ConvertFrom-Json

            ForEach ($Net in $NetworksToValidate) {

                { $Script:EthernetNetwork = Get-HPOVNetwork -Type Ethernet -Name $Net.name -ErrorAction Stop } | Should -Not -Throw
                $EthernetNetwork | Should -Not -BeNullOrEmpty

            }
        
        }

    }

    Context "Create Network Set with '$($EthernetNetworkObject.name)' assigned." {

        It "Will attempt to create NetworkSet '$NetworkSetName' with invalid Networks parameter" {

            $ExpectedExceptionMessage1 = "The specified 'Foo' Network resource was not found on '{0}' appliance connection.  Please check the name and try again." -f $Appliance1

            { New-HPOVNetworkSet -Name $NetworkSetName -Networks 'Foo' } | Should -Throw $ExpectedExceptionMessage1

        }

        It "Will attempt to create NetworkSet '$NetworkSetName' with invalid -TypicalBandwidth parameter" {

            $ExpectedExceptionMessage2 = "Missing an argument for parameter 'TypicalBandwidth'. Specify a parameter of type 'System.Int32' and try again."

            { New-HPOVNetworkSet -Name $NetworkSetName -Networks 'Foo' -TypicalBandwidth } | Should -Throw $ExpectedExceptionMessage2

        }

        It "Will create NetworkSet '$NetworkSetName'" {

            $EthernetNetworkObject = Get-HPOVNetwork -Name $EthernetNetworkName -Type Ethernet -ErrorAction Stop

            { $Script:CreateNetworkSetResults = New-HPOVNetworkSet -Name $NetworkSetName -Networks $EthernetNetworkObject | Wait-HPOVTaskComplete } | Should -Not -Throw
            $CreateNetworkSetResults.category | Should -Be tasks

            if ($CreateNetworkSetResults.taskState -ne "Completed") {

                DisplayTaskError $CreateNetworkSetResults

            }         

            $CreateNetworkSetResults.taskState | Should -Be Completed

        }

        It "Will validate Network Set '$NetworkSetName' exists" {

            { $Script:NetSet = Get-HPOVNetworkSet -Name $NetworkSetName -ErrorAction Stop } | Should -Not -Throw

            $NetSet.category | Should -Be "network-sets"

        }

    }

    Context "Update Network Set with New Ethernet Network object" {

        It "Will create New Ethernet Network: '$EthernetNetworkNameForNetSet'" {

            { $Script:NewEthernetNetwork = New-HPOVNetwork -Name $EthernetNetworkNameForNetSet -VlanID $EthernetNetworkVlanForNetSet } | Should -Not -Throw

            { $Script:EthernetNetworkForNetSetResults = Get-HPOVNetwork -Name $EthernetNetworkNameForNetSet -ErrorAction Stop } | Should -Not -Throw

        }        

        It "Will update Network Set with New Network '$EthernetNetworkNameForNetSet'" {

            $NetSet = Get-HPOVNetworkSet -Name $NetworkSetName -ErrorAction Stop
            $Network1 = Get-HPOVNetwork -Name $EthernetNetworkNameForNetSet -Type Ethernet -ErrorAction Stop
            $Network2 = Get-HPOVNetwork -Name $EthernetNetworkName -Type Ethernet -ErrorAction Stop

            { $Script:Results = Set-HPOVNetworkSet -NetworkSet $NetSet -Networks $Network1,$Network2 -UntaggedNetwork $Network1 | Wait-HPOVTaskComplete } | Should -Not -Throw
            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }    

            $Results.taskState | Should -Be Completed

        }

    }        

    Context "Remove Created Ethernet Networks" {

        It "Will attempt to find non-existant Ethernet Network: '$NonexistantEthernetNetworkName'" {

            $ExpectedExcpetionMessage = "The specified '{0}' Network resource was not found on '{1}' appliance connection.  Please check the name and try again." -f $NonexistantEthernetNetworkName, $Appliance1

            { Get-HPOVNetwork -Name $NonexistantEthernetNetworkName -ErrorAction Stop } | Should -Throw $ExpectedExcpetionMessage

        }

        It "Will find and remove existing Ethernet Network: '$EthernetNetworkName'" {

            { $Script:TaskResults = Get-HPOVNetwork -Name $EthernetNetworkName -Type Ethernet -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }    

            $TaskResults.taskState | Should -Be Completed

        }

        It "Will find and remove existing iSCSI Ethernet Network: '$IscsiEthernetNetworkName'" {

            { $Script:TaskResults = Get-HPOVNetwork -Name $IscsiEthernetNetworkName -Type Ethernet -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }    

            $TaskResults.taskState | Should -Be Completed

        }

        It "Will find and remove Ethernet Network for NetworkSet : '$EthernetNetworkNameForNetSet'" {

            { $Script:TaskResults = Get-HPOVNetwork -Name $EthernetNetworkNameForNetSet -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }    

            $TaskResults.taskState | Should -Be Completed

        }

        It "Will find and remove Bulk Ethernet Networks : '$BulkEthernetNetworkNamePrefix' VLANs $BulkEthernetVlanIds" {

            { $Script:TaskResults = Get-HPOVNetwork -Name $BulkEthernetNetworkNamePrefix* -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            0..($TaskResults.Count - 1) | ForEach-Object { 

                if ($TaskResults[$_].taskState -ne "Completed") {

                    DisplayTaskError $TaskResults[$_]

                }        
            
                $TaskResults[$_].taskState | Should -Be Completed 
            
        
            }

        }

        It "Will find and remove NetworkSet '$NetworkSetName'" {

            { $Script:Task = Get-HPOVNetworkSet -Name $NetworkSetName -ErrorAction Stop | Remove-HPOVNetworkSet -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }    

            $Task.taskState | Should -Be Completed

        }

        It "Will find and remove imported Ethernet Networks" {
        
            ($NetworksToImport | ConvertFrom-Json) | ForEach-Object {

                { $Script:RemoveResults = Get-HPOVNetwork -Name $_.name -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$False | Wait-HPOVTaskComplete } | Should -Not -Throw

                $RemoveResults | ForEach-Object {
                    
                    $_.category | Should -Be tasks

                    if ($_.taskState -ne "Completed") {

                        DisplayTaskError $_

                    }         

                    $_.taskState | Should -Be Completed

                }

            }
        
        }

    }

}

# NETWORKING
Describe "Fibre Channel Network Testing" -Tag All,FibreChannelNetwork,Networking {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        $NewFabricAttachNetworkName = "Fabric Attach {0}" -f (GetRandom)
        $NewFabricAttachNetworkFabricType = 'FabricAttach'
        $NewFabricAttachNetworkManagedSAN = 'SAN1_0'

        $NewDirectAttachNetworkName = "Direct Attach {0}" -f (GetRandom)
        $NewDirectAttachNetworkFabricType = 'DirectAttach'

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }
    
    Context "Retrieve FibreChannel Network" {

        [bool]($FibreChannelExists = Get-HPOVNetwork -Type FibreChannel -ErrorAction SilentlyContinue)

        $PSDefaultParameterValues = @{ 'It:Skip' = !$FibreChannelExists }

        It 'Will attempt to locate invalid FibreChannel Network, Foo' {

            $ExpectedExceptionMessage = "The specified 'Foo' Network resource was not found on '{0}' appliance connection.  Please check the name and try again." -f $Appliance1
            { Get-HPOVNetwork -Name Foo -type FibreChannel -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage

        }

        It 'Will locate real FibreChannel Network, "Fabric A"' {

            { $Script:FCNet = Get-HPOVNetwork -Name 'Fabric A' -Type FibreChannel -ErrorAction Stop } | Should -Not -Throw

            $FCNet | Should -Not -BeNullOrEmpty
            $FCNet.category | Should -Be 'fc-networks'

        }

    }

    Context 'Create FC Networks' {

        BeforeAll {

            If (-not(Get-HPOVSanManager -Name '172.18.15.1' -ErrorAction SilentlyContinue)) {

                $Task = Add-HPOVSanManager -Type BNA -Hostname 172.18.15.1 -Username dcs -Password dcs -UseSsl | Wait-HPOVTaskComplete

                if ($Task.taskState -ne "Completed") {

                    DisplayTaskError $Task

                }    

            }

        }

        It 'Will attempt to create "FCFoo" FC Network Resource with -VlanID Ethernet Param' {

            { New-HPOVNetwork -Name 'FCFoo' -Type FibreChannel -FabricType FabricAttach -VlanID 100 } | Should -Throw 'Parameter set cannot be resolved using the specified named parameters.'

        }

        It "Will attempt to create valid Fabric Attach FC Network Resource: $NewFabricAttachNetworkName" {

            { $Script:FabricAttachResults = New-HPOVNetwork -Name $NewFabricAttachNetworkName -Type FibreChannel -FabricType $NewFabricAttachNetworkFabricType } | Should -Not -Throw
            
            if ($FabricAttachResults.Status -ne "Completed") {

                DisplayTaskError $FabricAttachResults.Details

            }

            $FabricAttachResults.Status | Should -Be Completed

        }

        It "Will validate Fabric Attach FC '$NewFabricAttachNetworkName' network resource exists" {
        
            { $Script:Results = Get-HPOVNetwork -Type FibreChannel -Name $NewFabricAttachNetworkName -ErrorAction Stop } | Should -Not -Throw
            
            $Results.fabricType | Should -Be 'FabricAttach'
        
        }

        It "Will attempt to create valid Direct Attach FC Network Resource: $NewDirectAttachNetworkName" {

            { $Script:DirectAttachResults = New-HPOVNetwork -Name $NewDirectAttachNetworkName -Type FibreChannel -FabricType $NewDirectAttachNetworkFabricType } | Should -Not -Throw

            if ($DirectAttachResults.Status -ne "Completed") {

                DisplayTaskError $DirectAttachResults.Details

            }    

            $DirectAttachResults.Status | Should -Be Completed

            { $Script:Results = Get-HPOVNetwork -Type FibreChannel -Name $NewDirectAttachNetworkName -ErrorAction Stop } | Should -Not -Throw
            $Results.fabricType | Should -Be 'DirectAttach'

        }

        It 'Will update Fabric Attach FC Network with Managed SAN resource and AutoLoginRedistribution' {

            { $Script:ManagedSan = Get-HPOVManagedSan -Name $NewFabricAttachNetworkManagedSAN } | Should -Not -Throw

            { $Script:Results = Get-HPOVNetwork -Type FibreChannel -Name $NewFabricAttachNetworkName -ErrorAction Stop | Set-HPOVNetwork -AutoLoginRedistribution $true -LinkStabilityTime 30 -ManagedSan $ManagedSan -ErrorAction Stop | Wait-HPOVTaskComplete } | Should -Not -Throw

            { $Script:FabricAttachNetwork = Get-HPOVNetwork -Type FibreChannel -Name $NewFabricAttachNetworkName -ErrorAction Stop } | Should -Not -Throw
             $FabricAttachNetwork.managedSanUri | Should -Be $ManagedSan.uri

        }

        It 'Will attempt to Update Direct Attach FC Network with Managed SAN resource' {

            { $Script:ManagedSan = Get-HPOVManagedSan -Name $NewFabricAttachNetworkManagedSAN } | Should -Not -Throw

            $ThrowMessage = "The '{0}' FC Network resource is a Direct Attach fabric.  The Managed SAN resource cannot be modified." -f $NewDirectAttachNetworkName

            { $Result = Get-HPOVNetwork -Type FibreChannel -Name $NewDirectAttachNetworkName -ErrorAction Stop | Set-HPOVNetwork -ManagedSan $ManagedSan -ErrorAction Stop } | Should -Throw $ThrowMessage

        }

    }

    Context 'Remove FC Networks' {

        It "Will remove Fabric Attach Network: $NewFabricAttachNetworkName" {

            { $Script:Task = Get-HPOVNetwork -Name $NewFabricAttachNetworkName -Type FibreChannel -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 

            if ($Task.taskState -ne "Completed") {

                DisplayTaskError $Task

            }  

            $Task.taskState | Should -Be Completed

        }

        It "Will remove Direct Attach Network: $NewDirectAttachNetworkName" {

            { $Script:Task = Get-HPOVNetwork -Name $NewDirectAttachNetworkName -Type FibreChannel -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 

            if ($Task.taskState -ne "Completed") {

                DisplayTaskError $Task

            }  

            $Task.taskState | Should -Be Completed

        }

    }

}

# NETWORKING
Describe "Fibre Channel over Ethernet Network Testing" -Tag All,Networking,FCoENetwork {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions } | Should -Not -Throw

        }

    }

    Context "Create FCoE Network" {
    
        It "Will attempt to create an FCoE Network without -VlanID" {

            $ExpectedExceptionMessage = "The -Type Parameter was used to specify a 'FCoE' Network, however the -VLANID Parameter was not provided.  Please provide a VLANID to the Network resource you are creating."
    
            { New-HPOVNetwork -Name 'Invalid FCoE Network' -Type FCoE } | Should -Throw $ExpectedExceptionMessage

        }
            
        It "Will create a valid FCoE Network (VLAN ID: $FCoENetworkVlan)" {
    
            { $Script:NewFCoENetworkResults = New-HPOVNetwork -Name $NewFCoENetworkName -Type FCoE -VlanID $FCoENetworkVlan } | Should -Not -Throw 

            if ($NewFCoENetworkResults.Status -ne "Completed") {

                DisplayTaskError $NewFCoENetworkResults.Details

            }  

            $NewFCoENetworkResults.Status | Should -Be Completed
    
        }

        It "Will attempt to get an invalid FCoE Network" {
        
            $ExpectedExceptionMessage = "The specified '{0}' Network resource was not found on '{1}' appliance connection.  Please check the name and try again." -f 'foo', $Appliance1
            { Get-HPOVNetwork -Name 'foo' -Type FCoE -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }
    
    }

    Context "Remove FCoE Network" {
    
        It "Will remove created FCoE Network" {
    
            { $Script:RemoveResults = Get-HPOVNetwork -Type FCoE -Name $NewFCoENetworkName -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            $RemoveResults.category | Should -Be tasks

            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }  

            $RemoveResults.taskState | Should -Be Completed
    
        }
    
    }

}

# SAN Manager
Describe "SAN Manager function testing" -Tag All,Storage,Comet {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        $OriginalManagedSANObject = Get-HPOVManagedSAN -Name SAN1_0 -ErrorAction Stop

    }

    AfterAll {

        #Restore SAN1_0 settings
        $SAN1_0 = Get-HPOVManagedSAN -Name SAN1_0 -ErrorAction Stop
        $OriginalManagedSANObject.eTag = $SAN1_0.eTag
        { $Results = sr -Uri $OriginalManagedSANObject.uri -Method PUT -Body $OriginalManagedSANObject } | Should -Not -Throw

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Add BNA SAN Manager" {

        It "Will add bna1401.doctors-lab.local BNA to appliance" {

            { $Script:AddSanManagerResults = Add-HPOVSanManager -Hostname $BNASanManagerHostName -Username $BNASanManagerUsername -Password $BNASanManagerPassword -Type BNA -UseSSL | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($AddSanManagerResults.taskState -ne "Completed") {

                DisplayTaskError $AddSanManagerResults

            }  

            $AddSanManagerResults.taskState | Should -Be 'Completed' 

        }

        It "Will get bna1401.doctors-lab.local SAN Manager" {

            { $Script:SanManager = Get-HPOVSanManager -Name $BNASanManagerHostName -ErrorAction Stop } | Should -Not -Throw

            $SanManager.name | Should -Be $BNASanManagerHostName

        }

    }

    Context "Update SAN Manager with New properties" {

        It "Will attempt to update SAN Manager with an invalid username [#140]" {

            { $Script:UpdatedSanManagerResults = Get-HPOVSanManager -Name $BNASanManagerHostName -ErrorAction Stop | Set-HPOVSanManager -Username Foo -Password $UpdatedSanManagerPassword } | Should -Not -Throw
            
            $UpdatedSanManagerResults.taskState | Should -Be Error
            $UpdatedSanManagerResults.taskErrors.errorCode | Should -Be 'INVALID_CREDENTIALS'

        }

        It "Will update SAN Manager with New credentials [#140]" {

            { $Script:UpdatedSanManagerResults = Get-HPOVSanManager -Name $BNASanManagerHostName -ErrorAction Stop | Set-HPOVSanManager -Username $UpdatedSanManagerUsername -Password $UpdatedSanManagerPassword } | Should -Not -Throw
            
            if ($UpdatedSanManagerResults.taskState -ne "Completed") {

                DisplayTaskError $UpdatedSanManagerResults

            }  

            $UpdatedSanManagerResults.taskState | Should -Be Completed

        }

        #Modify managed san policies
        #Attempt to modify Auto Zoning for Internal SAN Manager (Should generate error)
        It "Will attempt to modify Auto Zoning policy for Internal SAN Manager" {
        
            $ExceptionMessage = "The provided Resource object '{0}' is an Internal SAN Manager and unsupported with this Cmdlet. Please check the value and try again." -f 'Encl1, interconnect 1_DirectAttach A'
            { Get-HPOVManagedSan -Name 'Encl1, interconnect 1_DirectAttach A' -ErrorAction Stop | Set-HPOVManagedSan -ZoningPolicy NoZoning -ErrorAction Stop } | Should -Throw $ExceptionMessage
        
        }

        #Disable Auto Zoning for SAN1_0
        It "Will disable automatic Zone management for 'SAN1_0' managed SAN" {
        
            { $Script:Results = Get-HPOVManagedSan -Name SAN1_0 -ErrorAction Stop | Set-HPOVManagedSan -ZoningPolicy NoZoning -ErrorAction Stop } | Should -Not -Throw
            $Results.sanPolicy.zoningPolicy | Should -Be NoZoning
            $Results.sanPolicy.enableAliasing | Should -Be $false
        
        }

        It "Will enable automatic Zone management for 'SAN1_0' managed SAN" {
        
            { $Script:Results = Get-HPOVManagedSan -Name SAN1_0 -ErrorAction Stop | Set-HPOVManagedSan -ZoningPolicy SingleInitiatorAllTargets -ErrorAction Stop  } | Should -Not -Throw
            $Results.sanPolicy.zoningPolicy | Should -Be SingleInitiatorAllTargets
        
        }

        It "Will change automated Zoning Policy to 'SingleInitiatorSingleTarget' for 'SAN1_0' managed SAN" {
        
            { $Script:Results = Get-HPOVManagedSan -Name SAN1_0 -ErrorAction Stop | Set-HPOVManagedSan -ZoningPolicy SingleInitiatorSingleTarget -ErrorAction Stop  } | Should -Not -Throw
            $Results.sanPolicy.zoningPolicy | Should -Be SingleInitiatorSingleTarget
        
        }

        It "Will change automated Zoning Policy to 'SingleInitiatorSingleStorageSystem' for 'SAN1_0' managed SAN" {
        
            { $Script:Results = Get-HPOVManagedSan -Name SAN1_0 -ErrorAction Stop | Set-HPOVManagedSan -ZoningPolicy SingleInitiatorSingleStorageSystem -EnableAliasing } | Should -Not -Throw
            $Results.sanPolicy.zoningPolicy | Should -Be SingleInitiatorSingleStorageSystem
            $Results.sanPolicy.enableAliasing | Should -Be $true
        
        }

        It "Will change automated Zoning Policy to 'SingleInitiatorAllTargets' (default), 'InitiatorNameFormat', and 'ZoneNameFormat' for 'SAN1_0' managed SAN" {
        
            { $Script:Results = Get-HPOVManagedSan -Name SAN1_0 -ErrorAction Stop | Set-HPOVManagedSan -InitiatorNameFormat 'Alias_{hostName}_{initiatorName}' -ZoneNameFormat 'zone_{hostName}_{initiatorName}_PG_{targetGroupName}' } | Should -Not -Throw
            $Results.sanPolicy.zoningPolicy | Should -Be SingleInitiatorAllTargets
            $Results.sanPolicy.initiatorNameFormat | Should -Be 'Alias_{hostName}_{initiatorName}'
            $Results.sanPolicy.zoneNameFormat | Should -Be 'zone_{hostName}_{initiatorName}_PG_{targetGroupName}'
        
        }

    }

    Context "Add Cisco SAN Manager" {
    
        It "Will add Cisco MDS SAN Manager" {

            $Params = @{

                Hostname         = $CiscoSanManagerHostname;
                Type             = 'Cisco';
                SnmpUsername     = $CiscoSanManagerSnmpUserName;
                SnmpAuthLevel    = $CiscoSanManagerSnmpAuthLevel;
                SnmpAuthProtocol = $CiscoSanManagerSnmpAuthProtocol;
                SnmpAuthPassword = $CiscoSanManagerSnmpAuthPassword;
                SnmpPrivProtocol = $CiscoSanManagerSnmpPrivProtocol; 
                SnmpPrivPassword = $CiscoSanManagerSnmpPrivPassword

            }
    
            { $Script:CiscoSanManagerResults = Add-HPOVSanManager @Params | Wait-HPOVTaskComplete } | Should -Not -Throw

            $CiscoSanManagerResults | Should -Not -BeNullOrEmpty
            $CiscoSanManagerResults.category | Should -Be tasks

            if ($CiscoSanManagerResults.taskState -ne "Completed") {

                DisplayTaskError $CiscoSanManagerResults

            }  

            $CiscoSanManagerResults.taskState | Should -Be Completed

        }

        It "Will validate Cisco MDS SAN Manager Exists" {
        
            { $script:CiscoSanManager = Get-HPOVSanManager -Name $CiscoSanManagerHostname -ErrorAction Stop } | Should -Not -Throw
        
        }

        It "Will validate Cisco SAN Manager SNMP SnmpUserName" {
        
            ($CiscoSanManager.connectionInfo | Where-Object name -eq 'SnmpUserName').value | Should -Be $CiscoSanManagerSnmpUserName
        
        }

        It "Will validate Cisco SAN Manager SNMP AuthLevel" {
        
            ($CiscoSanManager.connectionInfo | Where-Object name -eq 'SnmpAuthLevel').value | Should -Be AUTHPRIV
        
        }
        
        It "Will validate Cisco SAN Manager SNMP SnmpAuthProtocol" {
        
            ($CiscoSanManager.connectionInfo | Where-Object name -eq 'SnmpAuthProtocol').value | Should -Be SHA
        
        }
        
        It "Will validate Cisco SAN Manager SNMP AuthLevel" {
        
            ($CiscoSanManager.connectionInfo | Where-Object name -eq 'SnmpPrivProtocol').value | Should -Be AES128
        
        }
        
    }

    Context "Remove SAN Managers" {

        It "Will remove BNA SAN Manager from the appliance" {

            { $Script:RemoveSanManagerResults = Get-HPOVSanManager -Name $BNASanManagerHostName -ErrorAction Stop | Remove-HPOVSanManager -Confirm:$false } | Should -Not -Throw

            if ($RemoveSanManagerResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveSanManagerResults

            }  
            
            $RemoveSanManagerResults.taskState | Should -Be Completed

        }

        It "Will remove Cisco MDS SAN Manager from the appliance" {

            { $Script:RemoveSanManagerResults = Get-HPOVSanManager -Name $CiscoSanManagerHostname -ErrorAction Stop | Remove-HPOVSanManager -Confirm:$false } | Should -Not -Throw

            if ($RemoveSanManagerResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveSanManagerResults

            }  
            
            $RemoveSanManagerResults.taskState | Should -Be Completed

        }

    }

}

# StoreServe
Describe "StoreServe Storage System, Pool and Volume Management" -Tag All, Storage, StoreServ {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        if (Get-HPOVStorageSystem -Hostname $StorageSystemAddress -ErrorAction SilentlyContinue) {

            Microsoft.PowerShell.Utility\write-host ('{0} is present. Removing.' -f $StorageSystemAddress) -ForegroundColor Yellow

            Get-HPOVStorageSystem -Hostname $StorageSystemAddress -ErrorAction Stop | Remove-HPOVStorageSystem -Confirm:$false

        }

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Add StoreServ Storage System" {

        It "Will not add storage system due to invalid Domain parameter" {

            $ExpectedExceptionMessage = "Storage Domain '{0}' not found" -f $StorageSystemInvalidDomainName

            { Add-HPOVStorageSystem -Hostname $StorageSystemAddress -Username $StorageSystemUsername -Password $StorageSystemPassword -Domain $StorageSystemInvalidDomainName | Wait-HPOVTaskComplete } | Should -Throw $ExpectedExceptionMessage
            
        }

        It "Will not add storage system due to invalid Port parameter" {

            $ExpectedExceptionMessage = "The provided host port {0} name was not found to be present on the StoreServ system." -f 'InvalidPort'

            { Add-HPOVStorageSystem -Hostname $StorageSystemAddress -Username $StorageSystemUsername -Password $StorageSystemPassword -Domain $StorageSystemDomainName -Ports @{InvalidPort = "Fabric A"} | Wait-HPOVTaskComplete } | Should -Throw $ExpectedExceptionMessage
            
        }

        It "Will validate storage system was not added due to failed attempt" {

            $ExpecteExceptionMessage = "No Storage System with '{0}' system name found." -f $StorageSystem2Name

            { Get-HPOVStorageSystem -Name $StorageSystem2Name -ErrorAction Stop } | Should -Throw $ExpecteExceptionMessage

        }

        It "Will add a Storage System using 'Auto' port configuration" {

            { $Script:AddStorageSystemResults = Add-HPOVStorageSystem -Hostname $StorageSystemAddress -Username $StorageSystemUsername -Password $StorageSystemPassword -Domain $StorageSystemDomainName | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($AddStorageSystemResults.taskState -ne "Completed") {

                DisplayTaskError $AddStorageSystemResults

            }  

            $AddStorageSystemResults.taskState | Should -Be Completed

            $Script:StorageSystemName = (Send-HPOVRequest -Uri $AddStorageSystemResults.associatedResource.resourceUri).name

        }

        It "Will remove the Storage System" {

            { Get-HPOVStorageSystem -Name $StorageSystem2Name -ErrorAction Stop | Remove-HPOVStorageSystem -Confirm:$false } | Should -Not -Throw

        }

        It "Will add a Storage System specifying Ports parameters (using Auto) and PSCredential" {

            { $Script:AddStorageSystemResults = Add-HPOVStorageSystem -Hostname $StorageSystemAddress -Credential $StorageSystemPSCredential -Domain $StorageSystemDomainName -Ports @{"0:1:1" = "Auto";  "1:1:1" = "Auto"} | Wait-HPOVTaskComplete } | Should -Not -Throw

            $AddStorageSystemResults.taskState | Should -Be Completed

        }

        It "Will remove the Storage System" {

            { $Script:RemoveStorageSystemResults = Get-HPOVStorageSystem -Name $StorageSystem2Name -ErrorAction Stop | Remove-HPOVStorageSystem -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($RemoveStorageSystemResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveStorageSystemResults

            }  

        }

        It "Will add a Storage System specifying Ports and PortGroups parameters" {

            $FabricB = Get-HPOVNetwork -Name "Fabric B" -Type FC -ErrorAction Stop

            { $Script:AddStorageSystemResults = Add-HPOVStorageSystem -Hostname $StorageSystemAddress -Username dcs -Password dcs -Domain $StorageSystemDomainName -Ports @{"0:2:1" = "Fabric A";  "1:2:1" = "Fabric A"; "1:2:4" = $FabricB; "1:3:4" = $FabricB} -PortGroups @{"0:2:1"= 'PG1';  "1:2:1" = "PG1"; "1:2:4" = "PG2"; "1:3:4" = "PG2"} | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($AddStorageSystemResults.taskState -ne "Completed") {

                DisplayTaskError $AddStorageSystemResults

            }  

            $AddStorageSystemResults.taskState | Should -Be Completed

        }

        It "Will validate specified ports and PortGroups" {
        
            { $Script:StorageSystem = Get-HPOVStorageSystem -Hostname $StorageSystemAddress -ErrorAction Stop } | Should -Not -Throw
            $FabricA = Get-HPOVNetwork -Name 'Fabric A' -Type FC -ErrorAction Stop
            $FabricB = Get-HPOVNetwork -Name 'Fabric B' -Type FC -ErrorAction Stop

            # @{"0:1:1" = "Fabric A";  "0:2:1" = "Fabric A"; "1:2:4" = $FabricB; "1:3:4" = $FabricB}

            $ValidatePorts = @{
                "0:2:1" = [PSCustomObject]@{ Assignment = $FabricA; PortGroup = 'PG1'; ExpectedMode = 'Managed'};  
                "1:2:1" = [PSCustomObject]@{ Assignment = $FabricA; PortGroup = 'PG1'; ExpectedMode = 'Managed'}; 
                "1:2:4" = [PSCustomObject]@{ Assignment = $FabricB; PortGroup = 'PG2'; ExpectedMode = 'AutoManaged'};
                "1:3:4" = [PSCustomObject]@{ Assignment = $FabricB; PortGroup = 'PG2'; ExpectedMode = 'AutoManaged'}
            }

            ForEach ($_PortToValidate in $ValidatePorts.GetEnumerator()) {

                $_FoundPort = $StorageSystem.ports | Where-Object name -eq $_PortToValidate.Name
                $_FoundPort.mode | Should -Be $_PortToValidate.Value.ExpectedMode.Replace('Auto', $null)
                if ($_PortToValidate.Value.ExpectedMode -eq 'AutoManaged') { $_FoundPort.expectedNetworkUri | Should -Be $_PortToValidate.Value.Assignment.uri }
                else { $_FoundPort.expectedSanUri | Should -Be $_PortToValidate.Value.Assignment.managedSanUri }
                $_FoundPort.groupName | Should -Be $_PortToValidate.Value.PortGroup

            }
        
        }

        It "Will validate storage system exists by looking for Serial Number" {
        
            { $Script:StorageSystemObject = Get-HPOVStorageSystem -SerialNumber $StorageSystemSerialNumber -ErrorAction Stop } | Should -Not -Throw
            $StorageSystemObject | Should -Not -BeNullOrEmpty
            $StorageSystemObject.category | Should -Be 'storage-systems'
            $StorageSystemObject.deviceSpecificAttributes.serialNumber | Should -Be $StorageSystemSerialNumber
        
        }

    }

    Context "Add StoreServe Storage Pools" {

        It "Will add storage pool $StorageSystemPoolName1" {

            { $Script:AddStoragPool1Results = Get-HPOVStorageSystem -Name $StorageSystem2Name -ErrorAction Stop | Add-HPOVStoragePool -Pool $StorageSystemPoolName1 | Wait-HPOVTaskComplete } | Should -Not -Throw

            $AddStoragPool1Results.category | Should -Be tasks

            if ($AddStoragPool1Results.taskState -ne "Completed") {

                DisplayTaskError $AddStoragPool1Results

            }  

        }

        It "Will add storage pool $StorageSystemPoolName2" {

            { $Script:AddStoragPool2Results = Get-HPOVStorageSystem -Name $StorageSystem2Name -ErrorAction Stop | Add-HPOVStoragePool -PoolName $StorageSystemPoolName2 | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($AddStoragPool2Results.taskState -ne "Completed") {

                DisplayTaskError $AddStoragPool2Results

            }  

        }

        It "Will add storage pool $StorageSystemPoolName3" {

            { $Script:AddStoragPool3Results = Get-HPOVStorageSystem -Name $StorageSystem2Name -ErrorAction Stop | Add-HPOVStoragePool -PoolName $StorageSystemPoolName3 | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($AddStoragPool3Results.taskState -ne "Completed") {

                DisplayTaskError $AddStoragPool3Results

            }  

        }
        
        It "Will validate 3 Managed Storage Pools -Exist associated with $StorageSystem2Name " {

            $Pools = Get-HPOVStoragePool -StorageSystem $StorageSystem2Name -Managed -ErrorAction Stop
            $Pools.count | Should -Be 3

        }

        It "Will validate $StorageSystemPoolName1 exists and is Managed" {

            { $Script:Pool1 = Get-HPOVStoragePool -Name $StorageSystemPoolName1 -StorageSystem $StorageSystem2Name -ErrorAction Stop } | Should -Not -Throw
            $Pool1.isManaged | Should -Be $True
            $Pool1.state | Should -Be Managed

        }

        It "Will validate $StorageSystemPoolName2 exists and is Managed" {

            { $Script:Pool2 = Get-HPOVStoragePool -Name $StorageSystemPoolName2 -StorageSystem $StorageSystem2Name -ErrorAction Stop } | Should -Not -Throw
            $Pool2.isManaged | Should -Be $True
            $Pool2.state | Should -Be Managed

        }

        It "Will validate $StorageSystemPoolName3 exists and is Managed" {

            { $Script:Pool3 = Get-HPOVStoragePool -Name $StorageSystemPoolName3 -StorageSystem $StorageSystem2Name -ErrorAction Stop } | Should -Not -Throw
            $Pool3.isManaged | Should -Be $True
            $Pool3.state | Should -Be Managed

        }

    }

    Context "StoreServe Volume Provisioning" {

        It "Will provision a 10GB Storage Volume from $StorageSystemPoolName1" { 
        
            { $Script:CreateStorageVolResults = Get-HPOVStoragePool -Name $StorageSystemPoolName1 -StorageSystem $StorageSystem2Name -ErrorAction Stop | New-HPOVStorageVolume -Name $StorageVolumeName -Description 'Pester Volume Test' -Capacity 1 | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $CreateStorageVolResults.category | Should -Be tasks

            if ($CreateStorageVolResults.taskState -ne "Completed") {

                DisplayTaskError $CreateStorageVolResults

            }  

            $CreateStorageVolResults.taskState | Should -Be Completed

        }

        It "Will validate storage volume $StorageVolumeName exists" {

            { $Script:StorageVolumeObject = Get-HPOVStorageVolume -Name $StorageVolumeName -ErrorAction Stop } | Should -Not -Throw
            $StorageVolumeObject.name | Should -Be $StorageVolumeName
            $StorageVolumeObject.category | Should -Be 'storage-volumes'

        }

        It "Will validate storage volume is associated with the same StoragePool and SnapShotStoragePool" {

            $StorageVolumeObject.storagePoolUri | Should -Not -BeNullOrEmpty
            $StorageVolumeObject.deviceSpecificAttributes.snapshotPoolUri | Should -Not -BeNullOrEmpty
            $StorageVolumeObject.storagePoolUri -eq $StorageVolumeObject.deviceSpecificAttributes.snapshotPoolUri | Should -Be $true

        }

        It "Will update '$StorageVolumeName' Capacity by 1GB" {

            $StorageVolumeObject = Get-HPOVStorageVolume -Name $StorageVolumeName -ErrorAction Stop

            $NewCapacity = $StorageVolumeObject.provisionedCapacity / 1GB + 1

            { $Script:TaskResults = Set-HPOVStorageVolume -InputObject $StorageVolumeObject -Capacity $NewCapacity | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }  

            $TaskResults.taskState | Should -Be Completed

        }

        It "Will change '$StorageVolumeName' SnapShotStoragePool" {

            $StorageVolumeObject = Get-HPOVStorageVolume -Name $StorageVolumeName -ErrorAction Stop

            $Cpgs = Get-HPOVStoragePool -StorageSystem (Get-HPOVStorageSystem -Hostname $StorageSystemAddress -ErrorAction Stop) -Managed -ErrorAction Stop
            
            $CpgToUpdate = $Cpgs | Where-Object { $_.uri -ne $StorageVolumeObject.deviceSpecificAttributes.snapshotPoolUri } | Select-Object -First 1

            { $Script:TaskResults = $StorageVolumeObject | Set-HPOVStorageVolume -SnapShotStoragePool $CpgToUpdate | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }  

            $TaskResults.taskState | Should -Be Completed

        }

        It "Will remove '$StorageVolumeName' Storage Volume Export" {

            { $Script:TaskResults = Get-HPOVStorageVolume -Name $StorageVolumeName -ErrorAction Stop | Remove-HPOVStorageVolume -ExportOnly -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            $TaskResults.category | Should -Be "tasks"

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }

            $TaskResults.taskState | Should -Be Completed

        }

        It "Will attempt to Add non-existant Storage Volume [#132]" {

            { $Script:TaskResults = Get-HPOVStorageSystem -Name $StorageSystem2Name -ErrorAction Stop | Add-HPOVStorageVolume -Name Foo -StorageDeviceName Foo | Wait-HPOVTaskComplete } | Should -Not -Throw
            $TaskResults.taskState | Should -Be 'Error'
            $TaskResults.taskErrors.message | Should -Be "The volume 'foo' is not found on the specified storage system."


        }

        It "Will add existing Storage Volume back - $DeviceVolumeName; [#132]" {

            { $Script:TaskResults = Get-HPOVStorageSystem -Name $StorageSystem2Name | Add-HPOVStorageVolume -Name $DeviceVolumeName -StorageDeviceName $DeviceVolumeName | Wait-HPOVTaskComplete } | Should -Not -Throw
            $TaskResults.category | Should -Be 'tasks'

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }  

            $TaskResults.taskState | Should -Be 'Completed'

        }

    }

    Context "Manage StoreServe Thin Deduplication volumes" {

        It "Will verify $StoreServeSSDPoolName Storage Pool is Managed resource on $StorageSystem1Name" {

            { $Script:StoragPool = Get-HPOVStoragePool -Name $StoreServeSSDPoolName -ErrorAction Stop } | Should -Not -Throw

            $StoragPool.category | Should -Be 'storage-pools'
            $StoragPool.state | Should -Be Managed

        }

        It "Will create TPDD Storage Volume Template $StorageVolumeTPDDName-SVT with locked settings" {
            
            { $Script:CreateSVTResults = Get-HPOVStoragePool -Name $StoreServeSSDPoolName -StorageSystem $StorageSystem1Name -ErrorAction Stop | New-HPOVStorageVolumeTemplate -Name "$StorageVolumeTPDDName-SVT" -Description 'TPDD Pester SVT Test' -Capacity 1 -LockCapacity -ProvisionType TPDD -LockProvisionType } | Should -Not -Throw
            
            $CreateSVTResults.category | Should -Be storage-volume-templates

        }

        It "Will validate SVT is Thin Provision Dedup provision type" {

            $Volume = Get-HPOVStorageVolumeTemplate -Name "$StorageVolumeTPDDName-SVT" -ErrorAction Stop
            $Volume.properties.provisioningType.default | Should -Be 'Thin Deduplication'

        }

        It "Will validate SVT is Thin Provision Dedup provision type is locked" {

            $Volume = Get-HPOVStorageVolumeTemplate -Name "$StorageVolumeTPDDName-SVT" -ErrorAction Stop
            $Volume.properties.provisioningType.meta.locked | Should -Be $true

        }

        It "Will create TPDD Storage Volume $StorageVolumeTPDDName" {

            { $Script:CreateStorageVolResults = Get-HPOVStoragePool -Name $StoreServeSSDPoolName -StorageSystem $StorageSystem1Name -ErrorAction Stop | New-HPOVStorageVolume -Name $StorageVolumeTPDDVolumeName -Description 'TPDD Pester Volume Test' -Capacity 1 -ProvisionType TPDD | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $CreateStorageVolResults.category | Should -Be tasks

            if ($CreateStorageVolResults.taskState -ne "Completed") {

                DisplayTaskError $CreateStorageVolResults

            }  

            $CreateStorageVolResults.taskState | Should -Be Completed

        }

        It "Will validate volume is Thin Provision Dedup provision type" {

            $Volume = Get-HPOVStorageVolume -Name $StorageVolumeTPDDVolumeName -ErrorAction Stop
            $Volume.provisioningType | Should -Be 'Thin Deduplication'

        }

    }

    Context "Manage storage volume snapshots" {

        It "Will initiate snapshot of '$StorageVolumeName' Storage Volume" {

            { $Script:TaskResults = Get-HPOVStorageVolume -Name $StorageVolumeName -ErrorAction Stop | New-HPOVStorageVolumeSnapshot | Wait-HPOVTaskComplete } | Should -Not -Throw

            $TaskResults.category | Should -Be "tasks"

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }

            $TaskResults.taskState | Should -Be Completed

        }

        It "Will validate snapshot exists" {

            $VolumeSnapshot = Get-HPOVStorageVolume -Name $StorageVolumeName -ErrorAction Stop | Get-HPOVStorageVolumeSnapshot -ErrorAction Stop
            $VolumeSnapshot.category | Should -Be 'snapshots'

        }

        It "Will convert Snapshot to Volume" {

            { $Script:TaskResults = Get-HPOVStorageVolume -Name $StorageVolumeName -ErrorAction Stop | Get-HPOVStorageVolumeSnapshot | ConvertTo-HPOVStorageVolume -Name ($StorageVolumeName + '3') | Wait-HPOVTaskComplete } | Should -Not -Throw

            $TaskResults.category | Should -Be "tasks"

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }

            $TaskResults.taskState | Should -Be Completed

        }

        It "Will validate converted snapshot volume exists" {

            $ConvertedVolume = Get-HPOVStorageVolume -Name ($StorageVolumeName + '3') -ErrorAction Stop 
            $ConvertedVolume.name | Should -Be ($StorageVolumeName + '3')

        }

        It "Will remove converted snapshot volume" {

            { $Script:TaskResults = Get-HPOVStorageVolume -Name ($StorageVolumeName + '3') -ErrorAction Stop | Remove-HPOVStorageVolume -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $TaskResults.category | Should -Be "tasks"

            if ($TaskResults.taskState -ne "Completed") {

                DisplayTaskError $TaskResults

            }

            $TaskResults.taskState | Should -Be Completed

        }
        
    }

    Context "Create and manage StoreServ Storage Volume Templates" {

        It "Will create Shared Storage Volume Template $StorageVolumeTemplateName, 10GB, $StorageSystemPoolName1 and $StorageSystemPoolName2 with Unlocked Settings" {
            
            $StorageSystemPool1 = Get-HPOVStoragePool -Name $StorageSystemPoolName1 -ErrorAction Stop
            $StorageSystemPool2 = Get-HPOVStoragePool -Name $StorageSystemPoolName2 -ErrorAction Stop

            { $Script:CreatedStorageVolumeTemplateResults = New-HPOVStorageVolumeTemplate -Name $StorageVolumeTemplateName -Capacity 10 -StoragePool $StorageSystemPool1 -SnapShotStoragePool $StorageSystemPool2 -Shared } | Should -Not -Throw

        }

        It "Will validate created Storage Volume Template object name" {

            $CreatedStorageVolumeTemplateResults.name -eq $StorageVolumeTemplateName | Should -Be $true

        }

        It "Will validate created Storage Volume Template object capacity is 10GB" {

            $CreatedStorageVolumeTemplateResults.properties.size.default / 1GB | Should -Be 10

        }

        It "Will validate created Storage Volume Template object capacity is not locked" {

            $CreatedStorageVolumeTemplateResults.properties.size.meta.locked | Should -Be $false

        }

        It "Will validate created Storage Volume Template object provisioing type is Thin" {

            $CreatedStorageVolumeTemplateResults.properties.provisioningType.default | Should -Be Thin

        }

        It "Will validate created Storage Volume Template object provisioing type is not locked" {

            $CreatedStorageVolumeTemplateResults.properties.provisioningType.meta.locked | Should -Be $false

        }

        It "Will create Storage Volume $SharedStorageVolumeName from Template" {

            { $Script:CreatedStorageVolumeResults = New-HPOVStorageVolume -Name $SharedStorageVolumeName -VolumeTemplate $CreatedStorageVolumeTemplateResults | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($CreatedStorageVolumeResults.taskState -ne "Completed") {

                DisplayTaskError $CreatedStorageVolumeResults

            }

            $CreatedStorageVolumeResults.taskState | Should -Be Completed

        }

        It "Will update Storage Volume Template $StorageVolumeTemplateName with New description and increased capacity [#138]" {

            { $Script:StorageVoluemTemplateObject = Get-HPOVStorageVolumeTemplate -Name $StorageVolumeTemplateName -ErrorAction Stop } | Should -Not -Throw

            $Script:NewCapacity = ($CreatedStorageVolumeTemplateResults.provisioning.capacity / 1GB) + 1

            { $StorageVoluemTemplateObject | Set-HPOVStorageVolumeTemplate -Capacity $NewCapacity -Description "My New Updated Description" } | Should -Not -Throw

        }

        It "Will update Storage Volume Template $StorageVolumeTemplateName with New Name, Description, increased capacity, and change to Full provision type [#168]" {

            { $Script:StorageVoluemTemplateObject = Get-HPOVStorageVolumeTemplate -Name $StorageVolumeTemplateName -ErrorAction Stop } | Should -Not -Throw

            $Script:NewCapacity = ($CreatedStorageVolumeTemplateResults.provisioning.capacity / 1GB) + 1

            $Script:UpdatedName = '{0}-Updated' -f $StorageVoluemTemplateObject.name

            { Set-HPOVStorageVolumeTemplate -InputObject $StorageVoluemTemplateObject -Name $UpdatedName -Capacity $NewCapacity -Description "My New Updated Description 2" -Full } | Should -Not -Throw

        }

        It "Will remove Storage Volume Template $StorageVolumeTemplateName using wildcard search and pipeline" {

            Get-HPOVStorageVolumeTemplate -Name $StorageVolumeTemplateName* -ErrorAction Stop | Remove-HPOVStorageVolumeTemplate -Confirm:$false | ForEach-Object { $_.Message | Should -Be 'Resource deleted successfully.' }

        }

        It "Will remove Storage Volume $SharedStorageVolumeName" {

            (Get-HPOVStorageVolume -Name $SharedStorageVolumeName -ErrorAction Stop | Remove-HPOVStorageVolume -Confirm:$false | Wait-HPOVTaskComplete).taskState | Should -Be Completed

        }

    }    

    Context "Remove StoreServ Storage Volume, Pools and System" {

        It "Will remove $DeviceVolumeName Storage Volume" {

            { $Script:RemoveStorageVolResults = Get-HPOVStorageVolume -Name $DeviceVolumeName -ErrorAction Stop | Remove-HPOVStorageVolume -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            $RemoveStorageVolResults.category | Should -Be tasks

            if ($RemoveStorageVolResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveStorageVolResults

            }

            $RemoveStorageVolResults.taskState | Should -Be Completed

        }

        It "Will remove $StorageVolumeTPDDVolumeName Storage Volume" {

            { $Script:RemoveStorageVolResults = Get-HPOVStorageVolume -Name $StorageVolumeTPDDVolumeName -ErrorAction Stop | Remove-HPOVStorageVolume -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            $RemoveStorageVolResults.category | Should -Be tasks

            if ($RemoveStorageVolResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveStorageVolResults

            }

            $RemoveStorageVolResults.taskState | Should -Be Completed

        }

        It "Will remove TPDD Storage Volume Template $StorageVolumeTPDDName-SVT" {
            
            { $Script:RemoveSVTResults = Get-HPOVStorageVolumeTemplate -Name "$StorageVolumeTPDDName-SVT" -ErrorAction Stop | Remove-HPOVStorageVolumeTemplate -confirm:$false } | Should -Not -Throw
            
            $RemoveSVTResults.message | Should -Be 'Resource deleted successfully.'

        }

        It "Will remove $StorageSystemPoolName1 Storage Pool" {
        
            { $Script:RemoveStoragePool1Results = Get-HPOVStoragePool -Name $StorageSystemPoolName1 -StorageSystem $StorageSystem2Name -ErrorAction Stop | Remove-HPOVStoragePool -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $RemoveStoragePool1Results.category | Should -Be tasks

            if ($RemoveStoragePool1Results.taskState -ne "Completed") {

                DisplayTaskError $RemoveStoragePool1Results

            }
            
            $RemoveStoragePool1Results.taskState | Should -Be Completed

        }

        It "Will remove $StorageSystemPoolName2 Storage Pool" {
        
            { $Script:RemoveStoragePool2Results = Get-HPOVStoragePool -Name $StorageSystemPoolName2 -StorageSystem $StorageSystem2Name -ErrorAction Stop | Remove-HPOVStoragePool -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $RemoveStoragePool2Results.category | Should -Be tasks

            if ($RemoveStoragePool2Results.taskState -ne "Completed") {

                DisplayTaskError $RemoveStoragePool2Results

            }
            
            $RemoveStoragePool2Results.taskState | Should -Be Completed
            
        }

        It "Will remove $StorageSystemPoolName3 Storage Pool" {
        
            { $Script:RemoveStoragePool3Results = Get-HPOVStoragePool -Name $StorageSystemPoolName3 -StorageSystem $StorageSystem2Name -ErrorAction Stop | Remove-HPOVStoragePool -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $RemoveStoragePool3Results.category | Should -Be tasks

            if ($RemoveStoragePool3Results.taskState -ne "Completed") {

                DisplayTaskError $RemoveStoragePool3Results

            }
            
            $RemoveStoragePool3Results.taskState | Should -Be Completed
            
        }

        It "Will remove $StorageSystem2Name Storage System" {

            { $Script:RemoveStorageSystemResults = Get-HPOVStorageSystem -Name $StorageSystem2Name | Remove-HPOVStorageSystem -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $RemoveStorageSystemResults.category | Should -Be tasks

            if ($RemoveStorageSystemResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveStorageSystemResults

            }
            
            $RemoveStorageSystemResults.taskState | Should -Be Completed

        }

    }

}

# StoreVirtual
Describe "StoreVirtual Storage System, Pool and Volume Management" -Tag All, Storage, StoreVirtual {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Add StoreVirtual Storage System" {

        It "Will attempt to add StoreVirtual Storage System without VIPS parameter" {

            $ExpectedExceptionMessage = 'Adding a StoreVirtual resource requires you to provide the VIP or VIPS and associated Ethernet Network'
            
            { Add-HPOVStorageSystem -Hostname $StoreVirtual2Address -Credential $StorageSystemPSCredential -Family StoreVirtual } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will add StoreVirtual Storage System" {

            $IscsiNetwork = Get-HPOVNetwork -Name ISCSI* -ErrorAction Stop

            { $Script:AddStorageSystemResults = Add-HPOVStorageSystem -Hostname $StoreVirtual2Address -Credential $StorageSystemPSCredential -Family StoreVirtual -VIPS @{ "$StoreVirtual2Address" = $IscsiNetwork } | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($AddStorageSystemResults.taskState -ne "Completed") {

                DisplayTaskError $AddStorageSystemResults

            }  

            $AddStorageSystemResults.taskState | Should -Be Completed

            $Script:StorageSystemName = (Send-HPOVRequest -Uri $AddStorageSystemResults.associatedResource.resourceUri).name

        }

        It "Will validate storage system exists" {
        
            { $Script:StorageSystemObject = Get-HPOVStorageSystem -Name $StoreVirtual2Name -ErrorAction Stop } | Should -Not -Throw
            $StorageSystemObject | Should -Not -BeNullOrEmpty
            $StorageSystemObject.category | Should -Be 'storage-systems'
            $StorageSystemObject.Family | Should -Be StoreVirtual
        
        }

    }

    Context "StoreVirtual Volume Provisioning" {

        It "Will provision a 10GB Storage Volume from $StorageSystemPoolName1" { 
        
            { Get-HPOVStoragePool -Name $StoreVirtual2SystemPoolName -StorageSystem $StoreVirtual2Name -ErrorAction Stop | New-HPOVStorageVolume -Name ($StorageVolumeName + "2") -Description 'Pester Volume Test' -Capacity 1 -Async | Wait-HPOVTaskComplete } | Should -Not -Throw

        }

        It "Will validate storage volume $($StorageVolumeName)2 exists" {

            { $Script:StorageVolumeObject = Get-HPOVStorageVolume -Name ($StorageVolumeName + "2") -ErrorAction Stop } | Should -Not -Throw
            $StorageVolumeObject.category | Should -Be 'storage-volumes'

        }

    }

    Context "Create and manage StoreVirtual Storage Volume Templates" {

        It "Will attempt to create Shared Storage Volume Template with Snapshot Storage Pool settings" {

            $StorageVirtualSystemPool = Get-HPOVStoragePool -Name $StoreVirtual2SystemPoolName -ErrorAction Stop

            { $Script:CreatedStorageVolumeTemplateResults = New-HPOVStorageVolumeTemplate -Name $StoreVirtualTemplateName -Capacity 5 -LockCapacity -StoragePool $StorageVirtualSystemPool -Shared -EnableAdaptiveOptimization -DataProtectionLevel $DataProtectionLevel -LockProtectionLevel } | Should -Not -Throw

            $CreatedStorageVolumeTemplateResults.category | Should -Be storage-volume-templates

        }

        It "Will validate created Storage Volume Template object name" {

            $CreatedStorageVolumeTemplateResults.name -eq $StoreVirtualTemplateName | Should -Be $true

        }

        It "Will validate created Storage Volume Template object capacity is 5GB" {

            $CreatedStorageVolumeTemplateResults.properties.size.default / 1GB | Should -Be 5

        }

        It "Will validate created Storage Volume Template object capacity is not locked" {

            $CreatedStorageVolumeTemplateResults.properties.size.meta.locked | Should -Be $true

        }

        It "Will validate created Storage Volume Template object provisioing type is Thin" {

            $CreatedStorageVolumeTemplateResults.properties.provisioningType.default | Should -Be Thin

        }

        It "Will create Storage Volume $SharedStorageVolumeName from Template" {

            { $Script:CreatedStorageVolumeResults = New-HPOVStorageVolume -Name ($SharedStorageVolumeName + '2') -VolumeTemplate $CreatedStorageVolumeTemplateResults | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($CreatedStorageVolumeResults.taskState -ne "Completed") {

                DisplayTaskError $CreatedStorageVolumeResults

            }

            $CreatedStorageVolumeResults.taskState | Should -Be Completed

        }

    }    

    Context "Remove StoreVirtual Storage Volume, Pools and System" {

        It "Will remove remaining Storage Volumes" {

            { Get-HPOVStorageSystem -Name $StoreVirtual2Name -ErrorAction Stop | Get-HPOVStorageVolume -ErrorAction Stop | Remove-HPOVStorageVolume -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

        }

        it "Will validate all storage volumes associated with $StoreVirtual2Name are removed" {

            (Get-HPOVStorageSystem -Name $StoreVirtual2Name -ErrorAction Stop | Get-HPOVStorageVolume -ErrorAction Stop | Measure-Object).count | Should -Be 0

        }

        It "Will remove Storage Volume Template $StoreVirtualTemplateName using wildcard search and pipeline" {

            Get-HPOVStorageVolumeTemplate -Name $StoreVirtualTemplateName*  -ErrorAction Stop | Remove-HPOVStorageVolumeTemplate -Confirm:$false | ForEach-Object { $_.Message | Should -Be 'Resource deleted successfully.' }

        }

        It "Will remove $StoreVirtual2Name StoreVirtual Storage System" {

            { $Script:RemoveStorageSystemResults = Get-HPOVStorageSystem -Name $StoreVirtual2Name -ErrorAction Stop | Remove-HPOVStorageSystem -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveStorageSystemResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveStorageSystemResults

            }
            
            $RemoveStorageSystemResults.taskState | Should -Be Completed

        }

    }

}

# BladeSystem Policy testing
Describe "Address Pool Management" -Tag All, AddressPool {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Script:Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "MAC Address pool Management" {
    
        It "Will validate existing appliance MAC Address Pool exists" {
    
            { $Script:MacAddressPoolObject = Get-HPOVAddressPool -Type VMAC } | Should -Not -Throw
            $MacAddressPoolObject | Should -Not -BeNullOrEmpty
            $MacAddressPoolObject.category | Should -Be 'id-pool-VMAC'
    
        }

        It "Will attempt to create a MAC Address Pool with invalid parameters" {
        
            $ExpectedExceptionMessage = 'The provided End address 11:11:11:11:11:11:11:12 does not conform to a valid MAC Address value.'
            
            { New-HPOVAddressPoolRange -PoolType vmac -RangeType Custom -Start 11:11:11:11:11:11 -end 11:11:11:11:11:11:11:12 } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will create a New Generated MAC Address Pool" {
        
            { $Global:CreatedGeneratedMacAddressPoolResults = New-HPOVAddressPoolRange -PoolType vmac -RangeType Generated } | Should -Not -Throw
            $CreatedGeneratedMacAddressPoolResults | Should -Not -BeNullOrEmpty
            $CreatedGeneratedMacAddressPoolResults.category | Should -Be 'id-range-VMAC'
        
        }

        It "Will validate Generated MAC Address Pool exists" {
        
            { [Array]$Script:AddressPoolRange = Get-HPOVAddressPoolRAnge | Where-Object startAddress -eq $CreatedGeneratedMacAddressPoolResults.startAddress } | Should -Not -Throw
            $AddressPoolRange.Count | Should -Be 1
            $AddressPoolRange.startAddress | Should -Be $CreatedGeneratedMacAddressPoolResults.startAddress
        
        }

        It "Will create a New Custom MAC Address pool" {
        
            { $Script:CreatedCustomMacAddressPoolResults = New-HPOVAddressPoolRange -PoolType vmac -RangeType Custom -Start $CustomMacAddressPoolStart -End $CustomMacAddressPoolEnd } | Should -Not -Throw
            $CreatedCustomMacAddressPoolResults | Should -Not -BeNullOrEmpty
            $CreatedCustomMacAddressPoolResults.category | Should -Be 'id-range-VMAC'
            $CreatedCustomMacAddressPoolResults.totalCount | Should -Be $TotalCustomMacAddresses
        
        }

        It "Will validate Custom MAC Address Pool exists" {
        
            { $Script:AddressPoolRange = Get-HPOVAddressPoolRAnge | Where-Object startAddress -eq $CustomMacAddressPoolStart } | Should -Not -Throw
            $AddressPoolRange.Count | Should -Be 1
            $AddressPoolRange.startAddress | Should -Be $CustomMacAddressPoolStart
        
        }
    
    }

    Context "Remove created address pool resources" {
    
        It "Will remove Generated MAC Address Pool" {
    
            { $Script:RemoveResults = Get-HPOVAddressPoolRange | Where-Object startAddress -eq $CreatedGeneratedMacAddressPoolResults.startAddress | Remove-HPOVAddressPoolRange -Confirm:$false } | Should -Not -Throw
            $RemoveResults.Message | Should -Be "Resource deleted successfully."
    
        }

        It "Will remove Custom MAC Address Pool" {
    
            { $Script:RemoveResults = Get-HPOVAddressPoolRange | Where-Object startAddress -eq $CustomMacAddressPoolStart | Remove-HPOVAddressPoolRange -Confirm:$false } | Should -Not -Throw
            $RemoveResults.Message | Should -Be "Resource deleted successfully."
    
        }

    }

}

Describe "Create BladeSystem and Virtual Connect Group Policies" -Tag All, BladeSystemPolicies {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Create Layer 2 Network Resources" {

        It "Will create A-Side VLANs, '$EthernetNetworkPrefix-VLAN ' + 1,10,20,30,40,50 + '-A'" {

            { 1,10,20,30,40,50 | ForEach-Object { New-HPOVNetwork -Name "$EthernetNetworkPrefix-VLAN $_-A" -VlanId $_ -Type Ethernet } } | Should -Not -Throw

        }

        It "Will create B-Side VLANs, '$EthernetNetworkPrefix-VLAN ' + 1,10,20,30,40,50 + '-B'" {

            { 1,10,20,30,40,50 | ForEach-Object { New-HPOVNetwork -Name "$EthernetNetworkPrefix-VLAN $_-B" -VlanId $_ -Type Ethernet } } | Should -Not -Throw

        }

        It "Will create Ethernet Management Network, '$EthernetNetworkPrefix-MGMT-VLAN 100'" {

            { New-HPOVNetwork -Name "$EthernetNetworkPrefix-MGMT-VLAN 100" -VlanId 100 -Type Ethernet -Purpose Management } | Should -Not -Throw

        }

        It "Will create Ethernet Live Migration Network, '$EthernetNetworkPrefix-LiveMigration-VLAN 200'" {

            { New-HPOVNetwork -Name "$EthernetNetworkPrefix-LiveMigration-VLAN 200" -VlanId 100 -Type Ethernet -Purpose VMMigration } | Should -Not -Throw

        }

        It "Will create A-Side Network Sets, '$EthernetNetworkPrefix-NetworkSet A' (Using Network Objects)" {

            { $Script:ASideNetworks = Get-HPOVNetwork -Name "$EthernetNetworkPrefix-VLAN*-A" -ErrorAction Stop } | Should -Not -Throw

            { $Script:Results = New-HPOVNetworkSet -Name "$EthernetNetworkPrefix-NetworkSet A" -Networks $ASideNetworks -UntaggedNetwork $ASideNetworks[0] | Wait-HPOVTaskComplete } | Should -Not -Throw

            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will create B-Side Network Sets, '$EthernetNetworkPrefix-NetworkSet B' (Using Network Names)" {

            $BSideNetworkNamesArray = "$EthernetNetworkPrefix-VLAN 1-B","$EthernetNetworkPrefix-VLAN 10-B","$EthernetNetworkPrefix-VLAN 20-B","$EthernetNetworkPrefix-VLAN 30-B","$EthernetNetworkPrefix-VLAN 40-B","$EthernetNetworkPrefix-VLAN 50-B"

            { $Script:Results = New-HPOVNetworkSet -Name "$EthernetNetworkPrefix-NetworkSet B" -Networks $BSideNetworkNamesArray -UntaggedNetwork $BSideNetworkNamesArray[0] | Wait-HPOVTaskComplete } | Should -Not -Throw

            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will create Fabric Attach FibreChannel '$FCNetworkPrefix Fabric Attach A'" {

            { $script:Results = New-HPOVNetwork -Name "$FCNetworkPrefix Fabric Attach A" -Type FibreChannel -LinkStabilityTime 30 -AutoLoginRedistribution $true -FabricType FabricAttach } | Should -Not -Throw

            $Results.name | Should -Be "$FCNetworkPrefix Fabric Attach A"

            if ($Results.Status -ne "Completed") {

                DisplayTaskError $Results.Details

            }
            
            $Results.Status | Should -Be Completed

        }

        It "Will create Fabric Attach FibreChannel '$FCNetworkPrefix Fabric Attach B'" {

            { $script:Results = New-HPOVNetwork -Name "$FCNetworkPrefix Fabric Attach B" -Type FibreChannel -LinkStabilityTime 30 -AutoLoginRedistribution $true -FabricType FabricAttach } | Should -Not -Throw

            $Results.name | Should -Be "$FCNetworkPrefix Fabric Attach B"

            if ($Results.Status -ne "Completed") {

                DisplayTaskError $Results.Details

            }

            $Results.Status | Should -Be Completed

        }

        It "Will create DirectAttach FibreChannel '$FCNetworkPrefix Direct Attach A'" {

            { $script:Results = New-HPOVNetwork -Name "$FCNetworkPrefix Direct Attach A" -Type FibreChannel -FabricType DirectAttach } | Should -Not -Throw

            $Results.name | Should -Be "$FCNetworkPrefix Direct Attach A"

            if ($Results.Status -ne "Completed") {

                DisplayTaskError $Results.Details

            }

            $Results.Status | Should -Be Completed

        }

        It "Will create DirectAttach FibreChannel '$FCNetworkPrefix Direct Attach B'" {

            { $script:Results = New-HPOVNetwork -Name "$FCNetworkPrefix Direct Attach B" -Type FibreChannel -FabricType DirectAttach } | Should -Not -Throw

            $Results.name | Should -Be "$FCNetworkPrefix Direct Attach B"

            if ($Results.Status -ne "Completed") {

                DisplayTaskError $Results.Details

            }

            $Results.Status | Should -Be Completed

        }

    }

    Context "Create Logical Interconnect Group Policy" {

        It "Will create Logical Interconnect Group '$LogicalInterconnectGroupName' with Super Shaw modules" {

            $Bays = @{ 1 = 'Flex2040f8'; 2 = 'Flex2040f8'}

            $SnmpDest1 = New-HPOVSnmpTrapDestination -Destination mysnmpserver.company.com -Community MyR3adcommun1ty -SnmpFormat SNMPv1 -TrapSeverities critical,warning -VCMTrapCategories legacy
            $SnmpDest2 = New-HPOVSnmpTrapDestination -Destination 10.44.120.9 -Community MyR3adcommun1ty -SnmpFormat SNMPv1 -TrapSeverities critical,warning -VCMTrapCategories legacy -EnetTrapCategories Other,PortStatus,PortThresholds -FCTrapCategories Other,PortStatus
            $SnmpConfig = New-HPOVSnmpConfiguration -ReadCommunity MyR3adC0mmun1ty -AccessList '10.44.120.9/32','172.20.148.0/22' -TrapDestinations $SnmpDest1,$SnmpDest2
    
            { $Script:Results = New-HPOVLogicalInterconnectGroup -Name $LogicalInterconnectGroupName -bays $Bays -snmp $SnmpConfig | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will verify '$LogicalInterconnectGroupName' exists" {

            { $Script:LIGObject = Get-HPOVLogicalInterconnectGroup -Name $LogicalInterconnectGroupName -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will create '$LIGUplinkSet1Name' -> Bay 1 X1 and X2" {

           { $Script:ASideNetworks = Get-HPOVNetwork -Name "$EthernetNetworkPrefix-VLAN*-A" -ErrorAction Stop } | Should -Not -Throw

           { $Script:LIGObject = Get-HPOVLogicalInterconnectGroup -Name $LogicalInterconnectGroupName -ErrorAction Stop } | Should -Not -Throw

            $UplinkSetParamSplat = @{

                Resource         = $LIGObject;
                Name             = $LIGUplinkSet1Name;
                Type             = 'Ethernet';
                Networks         = $ASideNetworks;
                NativeEthNetwork = ($ASideNetworks | Where-Object vlanId -eq 1);
                UplinkPorts      = "Bay1:X1","Bay1:X2";
                LacpTimer        = 'Long'

            }

            { $Script:Results = New-HPOVUplinkSet @UplinkSetParamSplat } | Should -Not -Throw
            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will attempt to modify outdated LIG object with New Uplink Set '$LIGUplinkSet2Name' (Throw Exception)" {

            { $Script:BSideNetworks = Get-HPOVNetwork -Name "$EthernetNetworkPrefix-VLAN*-B" -ErrorAction Stop } | Should -Not -Throw

            $ExpectedExceptionMessage = "[Send-HPOVRequest]: The resource has changed since it was last retrieved. Please retry the operation."

            { $Script:Results = New-HPOVUplinkSet -Resource $LIGObject -Name $LIGUplinkSet2Name -Type Ethernet -Networks $BSideNetworks -UplinkPorts "Bay1:X1","Bay1:X2" -LacpTime 'Long' | Wait-HPOVTaskComplete } | Should -Throw $ExpectedExceptionMessage

        } 
        
        It "Will attempt to create '$LIGUplinkSet2Name' using Bay 1 X1 and X2 ports (Task Error; already allocated to Uplink Set 1)" {

            $ExpectedExceptionMessage = 'Invalid uplink set: one or more of the port locations are used twice in separate uplink sets.'

            { $Script:BSideNetworks = Get-HPOVNetwork -Name "$EthernetNetworkPrefix-VLAN*-B" -ErrorAction Stop } | Should -Not -Throw

            { $Script:LIGObject = Get-HPOVLogicalInterconnectGroup -Name $LogicalInterconnectGroupName -ErrorAction Stop } | Should -Not -Throw

            { $Script:Results = New-HPOVUplinkSet -Resource $LIGObject -Name $LIGUplinkSet2Name -Type Ethernet -Networks $BSideNetworks -UplinkPorts "Bay1:X1","Bay1:X2" -LacpTime 'Long' | Wait-HPOVTaskComplete } | Should -Not -Throw 
            $Results.category | Should -Be tasks
            $Results.taskState | Should -Be Error
            $Results.taskStatus | Should -Be $ExpectedExceptionMessage

        }

        It "Will create '$LIGUplinkSet2Name' -> Bay 2 X1 and X2" {

            { $Script:BSideNetworks = Get-HPOVNetwork -Name "$EthernetNetworkPrefix-VLAN*-B" -ErrorAction Stop } | Should -Not -Throw

            { $Script:LIGObject = Get-HPOVLogicalInterconnectGroup -Name $LogicalInterconnectGroupName -ErrorAction Stop } | Should -Not -Throw

            { $Script:Results = New-HPOVUplinkSet -Resource $LIGObject -Name $LIGUplinkSet2Name -Type Ethernet -Networks $BSideNetworks -UplinkPorts "Bay2:X1","Bay2:X2" -LacpTime 'Long' | Wait-HPOVTaskComplete } | Should -Not -Throw 
            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will create '$LIGUplinkSet3Name' -> Bay 1 Q1.1 and Bay 2 Q1.1" {

            { $Script:DevANetworks = Get-HPOVNetwork -Name "Dev VLAN*-A" -ErrorAction Stop } | Should -Not -Throw

            { $Script:LIGObject = Get-HPOVLogicalInterconnectGroup -Name $LogicalInterconnectGroupName -ErrorAction Stop } | Should -Not -Throw

            { $Script:Results = New-HPOVUplinkSet -Resource $LIGObject -Name $LIGUplinkSet3Name -Type Ethernet -Networks $DevANetworks -UplinkPorts "Bay1:Q1.1","Bay2:Q1.1" -LacpTime 'Long' | Wait-HPOVTaskComplete } | Should -Not -Throw 
            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

    }

    Context "Define New Enclosure Group policy" {

        It "Will attempt to locate invalid Logical Interconnect Group resource" {
        
            $ExpectedExceptionMessage = "Specified Logical Interconnect Group 'foo' was not found on '{0}' appliance" -f $Appliance1
            
            { Get-HPOVLogicalInterconnectGroup -Name foo -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will locate valid $DCSDefaultLIGName Logical Interconnect Group resource" {
        
            { $Script:DCSDefaultLigObject = Get-HPOVLogicalInterconnectGroup -Name $DCSDefaultLIGName -ErrorAction Stop } | Should -Not -Throw
            $DCSDefaultLigObject.category | Should -Be 'logical-interconnect-groups'    
        
        }

        It "Will attempt to create Enclosure Group with invalid LIG" {
        
            $ExpectedExceptionMessage = "Invalid LogicalInterconnectGroupMapping value provided 'Foo'"

            { New-HPOVEnclosureGroup -Name $EnclosureGroupName -LogicalInterconnectGroupMapping Foo } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will create an Enclosure Group with valid LIG" {
        
            { $Script:CreateEnclosureGroupResults = New-HPOVEnclosureGroup -Name $EnclosureGroupName -LogicalInterconnectGroupMapping $DCSDefaultLigObject -ConfigurationScript $EnclosureGroupConfigScript } | Should -Not -Throw
            $CreateEnclosureGroupResults | Should -Not -BeNullOrEmpty
            $CreateEnclosureGroupResults.category | Should -Be 'enclosure-groups'
        
        }

        It "Will validate created Enclosure Group exists" {
        
            { $Script:EnclosureGroupResults = Get-HPOVEnclosureGroup -Name $EnclosureGroupName -ErrorAction Stop } | Should -Not -Throw
            $EnclosureGroupResults | Should -Not -BeNullOrEmpty
            $EnclosureGroupResults.category | Should -Be 'enclosure-groups'
        
        }

    }

    Context "Manage existing Logical Interconnect resource" {

        It "Will validate '$ExistingLogicalInterconnectName' Logical Interconnect resource exists" {
    
            { Get-HPOVLogicalInterconnect -Name $ExistingLogicalInterconnectName -ErrorAction Stop } | Should -Not -Throw
    
        }

        It "Will add New Uplink Set to resource" {
        
            { $Script:Network = Get-HPOVNetwork -Name 'My Vlan 501' -ErrorAction Stop } | Should -Not -Throw

            $LIObject = Get-HPOVLogicalInterconnect -Name $ExistingLogicalInterconnectName -ErrorAction Stop

            $UplinkSetParamSplat = @{

                Resource         = $LIObject;
                Name             = $NewUplinkSetforLIName;
                Type             = 'Ethernet';
                Networks         = $Network
                UplinkPorts      = "Bay1:X6","Bay2:X6"

            }

            { $Script:Results = New-HPOVUplinkSet @UplinkSetParamSplat | Wait-HPOVTaskComplete } | Should -Not -Throw

            $Results.category | Should -Be tasks

            if ($Results.taskState -eq "Error") {
                
                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed
        
        }

        It "Will validate Logical Interconnect is no longer Consistent with LIG policy" {
        
            { $Script:ExistingLIResource = Get-HPOVLogicalInterconnect -Name $ExistingLogicalInterconnectName -ErrorAction Stop } | Should -Not -Throw
            $ExistingLIResource | Should -Not -BeNullOrEmpty
            $ExistingLIResource.category | Should -Be 'logical-interconnects'
            $ExistingLIResource.consistencyStatus | Should Not Be Consistent
        
        }

        It "Will update Logical Interconnect with LIG policy" {
        
            { $Script:UpdateLIFromParentResults = Get-HPOVLogicalInterconnect -Name $ExistingLogicalInterconnectName -ErrorAction Stop | Update-HPOVLogicalInterconnect -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            $UpdateLIFromParentResults | Should -Not -BeNullOrEmpty
            $UpdateLIFromParentResults.category | Should -Be 'tasks'

            if ($UpdateLIFromParentResults.taskState -eq "Error") {

                DisplayTaskError $UpdateLIFromParentResults

            }

            $UpdateLIFromParentResults.taskState | Should Not Be Error
        
        }

        It "Will validate Logical Interconnect is Consistent with LIG policy" {
        
            { $Script:ExistingLIResource = Get-HPOVLogicalInterconnect -Name $ExistingLogicalInterconnectName -ErrorAction Stop } | Should -Not -Throw

            $ExistingLIResource | Should -Not -BeNullOrEmpty
            $ExistingLIResource.category | Should -Be 'logical-interconnects'
            $ExistingLIResource.consistencyStatus | Should -Be Consistent
        
        }

        It "Will validate '$NewUplinkSetforLIName' does not -Exist" {
        
            $ExpectedExceptionMessage = "Specified Uplink Set '{0}' was not found on" -f $NewUplinkSetforLIName
            
            { Get-HPOVUplinkSet -Name $NewUplinkSetforLIName -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will validate Get-HPOVUplinkSet does not generate exception with no Uplink Sets defined" {

            { Get-HPOVUplinkSet -ErrorAction Stop } | Should -Not -Throw
        
        }
    
    }

    Context "Tear Down Created Resources" {

        It "Will remove created '$EnclosureGroupName' Enclosure Group" {

            { $Script:RemoveEnclosureGroupResults = Get-HPOVEnclosureGroup -Name $EnclosureGroupName -ErrorAction Stop | Remove-HPOVEnclosureGroup -Confirm:$false } | Should -Not -Throw
            $RemoveEnclosureGroupResults | Should -Not -BeNullOrEmpty
            $RemoveEnclosureGroupResults.Message | Should -Be 'Resource deleted successfully.'

        }       

        It "Will remove created '$LogicalInterconnectGroupName' LIG" {

            { $Script:RemoveLIGResults = Get-HPOVLogicalInterconnectGroup -Name $LogicalInterconnectGroupName -ErrorAction Stop | Remove-HPOVLogicalInterconnectGroup -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            $RemoveLIGResults | Should -Not -BeNullOrEmpty

            $RemoveLIGResults.category | Should -Be tasks
            
            if ($RemoveLIGResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveLIGResults

            }

            $RemoveLIGResults.taskState | Should -Be Completed

        }       

        It 'Will remove created Network Sets' {

            { $Script:RemoveNetworkSetsResults = Get-HPOVNetworkSet -Name "$EthernetNetworkPrefix*" -ErrorAction Stop | Remove-HPOVNetworkSet -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            $RemoveNetworkSetsResults | Should -Not -BeNullOrEmpty
            $RemoveLIGResults | ForEach-Object { 
                
                if ($_.taskState -ne "Completed") {

                    DisplayTaskError $_

                }
                
                $_.taskState | Should -Be Completed 
            
            }

        }

        It 'Will remove created networks' {

            { $Script:RemoveNetworksResults = Get-HPOVNetwork -Name "$EthernetNetworkPrefix*" -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            $RemoveNetworksResults | Should -Not -BeNullOrEmpty
            $RemoveNetworksResults | ForEach-Object { 
                
                $_.taskState | Should -Be Completed 
            
                if ($_.taskState -ne "Completed") {

                    DisplayTaskError $_

                }

            }

        }

    }

}

# Synergy Policy testing
Describe "Create Synergy Group Policies" -Tag All, SynergyPolicies {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Script:Connection2 = Connect-HPOVMgmt -Hostname $Appliance2 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
            { $Script:Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
            { $Script:Connection3 = Connect-HPOVMgmt -Hostname $Appliance3 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance2).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance2) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "IPv4 Address Pool Management" {

        It "Will attempt to create IPv4 Address Pool Subnet with invalid SubnetID" {

            $ExpectedExceptionMessage = 'The provided SubnetID 99 does not appear to be a valid Subnet Mask.'
            
            { $Script:CreatedIPv4Subnet = New-HPOVAddressPoolSubnet -NetworkId $IPv4SubnetID -SubnetMask 99 -Gateway $IPv4SubnetGateway -Domain $IPv4SubnetDomainName -DnsServers $IPv4SubnetDns1,$IPv4SubnetDns2 } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will attempt to create IPv4 Address Pool Subnet with invalid Subnet Mask ID" {

            $ExpectedExceptionMessage = '192.168.30.4 is an invalid Network ID for Subnet Mask 255.255.254.0. Provide a valid Network ID.'
            
            { $Script:CreatedIPv4Subnet = New-HPOVAddressPoolSubnet -NetworkId 192.168.30.4 -SubnetMask $IPv4SubnetMaskID -Gateway $IPv4SubnetGateway -Domain $IPv4SubnetDomainName -DnsServers $IPv4SubnetDns1,$IPv4SubnetDns2 } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will create IPv4 Address Pool Subnet" {
        
            { $Script:CreateIPv4SubnetResults = New-HPOVAddressPoolSubnet -NetworkId $IPv4SubnetID -SubnetMask $IPv4SubnetMaskID -Gateway $IPv4SubnetGateway -Domain $IPv4SubnetDomainName -DnsServers $IPv4SubnetDns1,$IPv4SubnetDns2 } | Should -Not -Throw
            $CreateIPv4SubnetResults | Should -Not -BeNullOrEmpty
            $CreateIPv4SubnetResults.category | Should -Be 'id-range-IPV4-subnet'
        
        }

        It "Will attempt to get an IPv4 Subnet from an unsupported appliance" {
        
            $ExpectedExceptionMessage = 'The ApplianceConnection {0} is not a Synergy Composer.  This Cmdlet is only supported with Synergy Composers.' -f $Appliance1
            
            { Get-HPOVAddressPoolSubnet -ApplianceConnection $Connection1 -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will validate IPv4 Subnet exists on '$($Connection2.Name)'" {
            
            { Get-HPOVAddressPoolSubnet -NetworkId $IPv4SubnetID -ErrorAction Stop } | Should -Not -Throw
        
        }

        It "Will attempt to create an IPv4 Address Pool Subnet Range with invalid Start Address" {
        
            $ExpectedExceptionMessage = 'The Start address value {0} is not within the Subnet Network ID {1}\{2}.' -f $IPv4SubnetInvalidStartAddress, $IPv4SubnetID, $IPv4SubnetMask
            
            { New-HPOVAddressPoolRange -IPv4Subnet $CreateIPv4SubnetResults -Name 'Invalid Subnet Range' -Start $IPv4SubnetInvalidStartAddress -End $IPv4SubnetEndAddress } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will attempt to create an IPv4 Address Pool Subnet Range with invalid End Address" {
        
            $ExpectedExceptionMessage = 'The End address value {0} is not within the Subnet Network ID {1}\{2}.' -f $IPv4SubnetInvalidEndAddress, $IPv4SubnetID, $IPv4SubnetMask
            
            { New-HPOVAddressPoolRange -IPv4Subnet $CreateIPv4SubnetResults -Name 'Invalid Subnet Range' -Start $IPv4SubnetStartAddress -End $IPv4SubnetInvalidEndAddress } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will create a New IPv4 Address Pool Range" {
        
            { $Script:CreatedIPv4AddressPoolRange = New-HPOVAddressPoolRange -IPv4Subnet $CreateIPv4SubnetResults -Name 'Test Subnet Range 1' -Start $IPv4SubnetStartAddress -End $IPv4SubnetEndAddress } | Should -Not -Throw
            $CreatedIPv4AddressPoolRange | Should -Not -BeNullOrEmpty
            $CreatedIPv4AddressPoolRange.category | Should -Be 'id-range-IPV4'
        
        }

        It "Will attempt to add an invalid Subnet to a New Ethernet Network" {
        
            $InvalidSubnet = Get-HPOVAddressPool | Select-Object -first 1
            $ExpectedExceptionMessage = "The Subnet Parameter value is not a valid 'id-range-IPv4-subnet' Object."
            
            { New-HPOVNetwork -Name 'Invalid Subnet Network' -type Ethernet -Subnet $InvalidSubnet -VLANId $I3SDeploymentNetworkVlanID -Purpose Management } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will create a New Ethernet Network, assigning IPv4 Address Pool" {
        
            { $Script:CreateEthernetNetwork = New-HPOVNetwork -Name $IPv4EthernetNetworkName -Type Ethernet -Subnet $CreateIPv4SubnetResults -VLANId $IPv4EthernetNetworkVlanID -Purpose Management } | Should -Not -Throw
            $CreateEthernetNetwork | Should -Not -BeNullOrEmpty
            
            if ($CreateEthernetNetwork.Status -ne "Completed") {

                DisplayTaskError $CreateEthernetNetwork.Details

            }

            $CreateEthernetNetwork.Status | Should -Be Completed

        }
    
    }

    Context "I3S Management" {

        BeforeAll {

            #Should it be removed?
            if (-not(Get-HPOVAddressPoolSubnet -NetworkID $IPv4SubnetID -ea SilentlyContinue))
            {

                $PSDefaultParameterValues = @{ 'It:Pending' = $true }
 
            }

        }

        It "Will create Deployment Subnet" {
        
            $NewIPv4SubnetParams = @{
                NetworkId  = $I3SIPv4SubnetId;
                SubnetMask = $I3SIPv4SubnetMaskID;
                Gateway    = $I3SIPv4SubnetGateway;
                Domain     = $IPv4SubnetDomainName;
                DnsServers = $IPv4SubnetDns1,$IPv4SubnetDns2
            }

            { $Script:CreateI3SDeploymentSubnet = New-HPOVAddressPoolSubnet @NewIPv4SubnetParams } | Should -Not -Throw

        }

        It "Will create a Deployment IPv4 Address Pool Range" {
        
            $NewIPv4SubnetRangeParams = @{
                IPv4Subnet = $CreateI3SDeploymentSubnet;
                Name       = $I3SIPv4PoolName;
                Start      = $I3SIPv4PoolStartAddress;
                End        = $I3SIPv4PoolEndAddress
            }
            
            { $Script:CreatedIPv4DeploymentAddressPoolRange = New-HPOVAddressPoolRange @NewIPv4SubnetRangeParams } | Should -Not -Throw
        
        }

        It "Will create New Ethernet Deployment Network" {
        
            $NewI3SDeploymentNetworkParams = @{
                Name    = $I3SDeploymentNetworkName;
                Type    = 'Ethernet';
                Subnet  = $CreateI3SDeploymentSubnet;
                VlanID  = $I3SDeploymentNetworkVlanID;
                Purpose = 'Management'
            }
            
            { $Script:CreateDeploymentEthernetNetwork = New-HPOVNetwork @NewI3SDeploymentNetworkParams } | Should -Not -Throw
        
        }

        It "Will validate i3S Deployment Network exists" {
        
            { $script:i3SDeploymentNetworkObject = Get-HPOVNetwork -Name $I3SDeploymentNetworkName -ErrorAction Stop } | Should -Not -Throw
            $i3SDeploymentNetworkObject.category | Should -Be 'ethernet-networks'
            $i3SDeploymentNetworkObject.purpose | Should -Be 'Management'
            $i3SDeploymentNetworkObject.subnetUri | Should -Be $CreateI3SDeploymentSubnet.uri
        
        }
    
        It "Will discover available I3S Management Appliances" -Skip {
    
            { $Script:AvailableI3SAppliances = Get-HPOVImageStreamerAppliance -ErrorAction Stop } | Should -Not -Throw
            $AvailableI3SAppliances | Should -Not -BeNullOrEmpty
            ($AvailableI3SAppliances | Select-Object -Frist 1).uri.StartsWith('/rest/deployment-servers/image-streamer-appliances') | Should -Be $true
    
        }

        It "Will add New OS Deployment Server" -Skip {

            { $Script:DeploymentNetwork = Get-HPOVNetwork -Type Ethernet -Name $I3SDeploymentNetworkName -ErrorAction Stop } | Should -Not -Throw
        
            { $Script:AddI3SAppliance = $AvailableI3SAppliances[0] | New-HPOVOSDeploymentServer -Name $I3SApplianceName -Description 'Pester Test' -ManagementNetwork $DeploymentNetwork } | Should -Not -Throw
            $AddI3SAppliance | Should -Not -BeNullOrEmpty
            $AddI3SAppliance.category | Should -Be tasks

            if ($AddI3SAppliance.taskState -ne "Completed") {

                DisplayTaskError $AddI3SAppliance

            }

            $AddI3SAppliance.taskState | Should -Be Completed
        
        }
    
    }

    Context "Create New Synergy Virtual Connect Logical Interconnect Group policy" {

        It "Will attempt to get a C-Class based Interconnect Type from a Synergy Composer" {
        
            $ExpectedExceptionMessage = "No Interconnect Types with 'HP VC 16Gb 24-Port FC Module' name were found on appliance"
        
            { Get-HPOVInterconnectType -Name 'HP VC 16Gb 24-Port FC Module' -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }        

        It "Will get Synergy Virtual Connect Specific Interconnect resource type" {

            { $Script:SynergyVC40F8InterconnectType = Get-HPOVInterconnectType -Name 'Virtual Connect SE 40Gb F8 Module for Synergy' }| Should -Not -Throw
            $SynergyVC40F8InterconnectType.partNumber | Should -Be '794502-B23'

        }

        It "Will attempt to create Synergy LIG with invalid Fabric Module device" {

            $ExpectedExceptionMessage = "Cannot validate argument on parameter 'FabricModuleType'"

            $Script:LigParams = @{

                Name               = 'InvalidLIG'
                InterconnectBaySet = 3;
                FabricModuleType   = 'Foo';
                FrameCount         = 1;
                Bays               = @{Frame1 = @{Bay3 = 'SEVC40f8'; Bay6 = 'SEVC40f8' }}

            }

            { New-HPOVLogicalInterconnectGroup @LIGParams } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will attempt to create Synergy LIG with wrong Interconnect Bay Set 2, instead of 3" {

            $ExpectedExceptionMessage = "Supported interconnect bay sets are 1(bays 1&4), 2(bays 2&5), or 3(bays 3&6)"

            $Script:LigParams = @{

                Name               = 'InvalidLIG'
                InterconnectBaySet = 2;
                FabricModuleType   = 'SEVC40f8';
                FrameCount         = 1;
                Bays               = @{Frame1 = @{Bay3 = 'SEVC40f8'; Bay6 = 'SEVC40f8' }}

            }

            { New-HPOVLogicalInterconnectGroup @LIGParams } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will attempt to create Synergy LIG with -FrameCount 1 but with 3 Frames within -Bays" {

            $ExpectedExceptionMessage = "The -FrameCount parameter value '1' does not match the expected Frame and Fabric Bay configuration in the -Bays parameters, '3'."

            $Script:LigParams = @{

                Name               = 'InvalidLig';
                InterconnectBaySet = 3;
                FabricModuleType   = 'SEVC40F8';
                FrameCount         = 1;
                Bays               = @{
                                        Frame1 = @{Bay3 = 'SEVC40f8'; Bay6 = 'SE20ILM' }; 
                                        Frame2 = @{Bay3 = 'SE20ILM'; Bay6 = 'SEVC40f8'};
                                        Frame3 = @{Bay3 = 'SE20ILM'; Bay6 = 'SE20ILM'}
                                     }

            }

            { New-HPOVLogicalInterconnectGroup @LIGParams } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will validate 'InvalidLig' does not -Exist" {
        
            $ExpectedExceptionMessage = "Specified Logical Interconnect Group 'InvalidLIG' was not found on '{0}' appliance connection.  Please check the name and try again." -f $Appliance2
            
            { Get-HPOVLogicalInterconnectGroup -Name InvalidLIG -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
        }    

        It "Will create Synergy Virtual Connect SE 40Gb LIG: $SynergyVCSE40F8LIGName" {

            { $Script:InternalNetworks = Get-HPOVNetwork -Name Internal* -ErrorAction Stop } | Should -Not -Throw

            $Script:LigParams = @{

                Name               = $SynergyVCSE40F8LIGName;
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

            { $Script:SynergyLIGCreateResults = New-HPOVLogicalInterconnectGroup @LigParams } | Should -Not -Throw

            $SynergyLIGCreateResults.category | Should -Be tasks

            if ($SynergyLIGCreateResults.taskState -ne "Completed") {

                DisplayTaskError $SynergyLIGCreateResults

            }

            $SynergyLIGCreateResults.taskState | Should -Be Completed

        }

        It "Will retrieve created Logical Interconnect Group resource from the Async task" {
        
            { $Script:CreatedLogicalInterconnectObject = $SynergyLIGCreateResults | Get-HPOVLogicalInterconnectGroup -ErrorAction Stop } | Should -Not -Throw
            $CreatedLogicalInterconnectObject | Should -Not -BeNullOrEmpty
            $CreatedLogicalInterconnectObject.category | Should -Be 'logical-interconnect-groups'
        
        }

        It "Will retrive all MLAG Ethernet Networks" {
        
            { $Script:AllMlagNetworks = Get-HPOVNetwork -Type Ethernet -Name MLAG* -ErrorAction Stop } | Should -Not -Throw
        
        }

        It "Will attempt to create an Uplink Set using invalid uplink ports" {
        
            $InvalidUplinkPorts = "Enclosure1:Bay3:X41","Enclosure1:Bay3:X42","Enclosure2:Bay6:Q1","Enclosure2:Bay6:Q2"

            $ExpectedExceptionMessage = "The provided uplink port 'BAY3:X41' is an invalid port ID.  Please check the value and try again."
            
            { New-HPOVUplinkSet -InputObject $CreatedLogicalInterconnectObject -Name 'Invalid Uplinkset' -UplinkPorts $InvalidUplinkPorts -Type Ethernet } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will create Uplink Set with MLAG Networks to $SynergyVCSE40F8LIGName LIG" {
        
            $Script:UplinkSetParams = @{

                InputObject = $CreatedLogicalInterconnectObject;
                Name        = $MLAGUplinkSetName;
                Type        = 'Ethernet';
                Networks    = $AllMlagNetworks;
                UplinkPorts = $MLAGUplinkSetUplinkPorts

            }
            
            { $Script:CreateUplinkSetResults = New-HPOVUplinkSet @UplinkSetParams } | Should -Not -Throw
        
        }

        It "Will validate $SynergyVCSE40F8LIGName has 1 Uplink Set defined" {
        
            { $Script:ModifiedLIGResource = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8LIGName -ErrorAction Stop } | Should -Not -Throw
            $ModifiedLIGResource | Should -Not -BeNullOrEmpty
            $ModifiedLIGResource.category | Should -Be 'logical-interconnect-groups'
            $ModifiedLIGResource.uplinkSets.Count | Should -Be 1
            $ModifiedLIGResource[0].uplinkSets[0].lacpTimer | Should -Be Short
            $ModifiedLIGResource[0].uplinkSets[0].ethernetNetworkType | Should -Be Tagged
            $ModifiedLIGResource[0].uplinkSets[0].networkUris.Count | Should -Be $AllMlagNetworks.Count
        
        }

    }

    Context "Create New Synergy Virtual Connect LIG with Image Streamer" {

        It "Will create Synergy Virtual Connect SE 40Gb LIG for ImageStreamer support: $SynergyVCSE40F8i3SLIGName" {

            { $Script:InternalNetworks = Get-HPOVNetwork -Name Internal* -ErrorAction Stop } | Should -Not -Throw

            $Script:LigParams = @{

                Name               = $SynergyVCSE40F8i3SLIGName;
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

            { $Script:SynergyLIGCreateResults = New-HPOVLogicalInterconnectGroup @LigParams } | Should -Not -Throw

            if ($SynergyLIGCreateResults.taskState -ne "Completed") {

                DisplayTaskError $SynergyLIGCreateResults

            }

            $SynergyLIGCreateResults.taskState | Should -Be 'Completed'

        }

        It "Will create Uplink Set with MLAG Networks for LIG: $SynergyVCSE40F8i3SLIGName" {

            { $Script:CreatedLogicalInterconnectObject = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8i3SLIGName -ErrorAction Stop } | Should -Not -Throw
        
            $Script:UplinkSetParams = @{

                InputObject = $CreatedLogicalInterconnectObject;
                Name        = $MLAGUplinkSetName;
                Type        = 'Ethernet';
                Networks    = $AllMlagNetworks;
                UplinkPorts = $MLAGUplinkSetUplinkPorts

            }
            
            { $Script:CreateUplinkSetResults = New-HPOVUplinkSet @UplinkSetParams } | Should -Not -Throw
            $CreateUplinkSetResults.category | Should -Be tasks
            
            if ($CreateUplinkSetResults.taskState -ne "Completed") {

                DisplayTaskError $CreateUplinkSetResults

            }

            $CreateUplinkSetResults.taskState | Should -Be Completed
        
        }

        It "Will create I3S Uplink Set for LIG: $SynergyVCSE40F8i3SLIGName" {
        
            { $script:i3SDeploymentNetworkObject = Get-HPOVNetwork -Name $I3SDeploymentNetworkName -ErrorAction Stop } | Should -Not -Throw
            { $Script:i3SUplinkSetResults = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8i3SLIGName -ErrorAction Stop | New-HPOVUplinkSet -Name $i3SUplinkSetName -Type ImageStreamer -Networks $i3SDeploymentNetworkObject -UplinkPorts $i3SUplinkSetUplinkPorts } | Should -Not -Throw
            $i3SUplinkSetResults.category | Should -Be tasks
            
            if ($i3SUplinkSetResults.taskState -ne "Completed") {

                DisplayTaskError $i3SUplinkSetResults

            }

            $i3SUplinkSetResults.taskState | Should -Be Completed

        }

        It "Will validate I3S Uplink Set configuration" {
        
            { $Script:LigObject = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8i3SLIGName -ErrorAction Stop } | Should -Not -Throw
            $LigObject | ConvertTo-Json -Depth 99 > C:\Tests\ligobject.json
            ($LigObject.uplinkSets | Where-Object ethernetNetworkType -eq 'ImageStreamer').ethernetNetworkType | Should -BeExactly 'ImageStreamer'
            ($LigObject.uplinkSets | Where-Object ethernetNetworkType -eq 'ImageStreamer').networkUris.count | Should -Be 1
        
        }

    }

    Context "Create New Synergy Vitual Connect FC Logical Interconnect Group policy" {    

        BeforeAll {

            If ( -not (Get-HPOVNetwork -Type FC -Name 'Fabric A' -ErrorAction SilentlyContinue)) {

                New-HPOVNetwork -Type FC -Name 'Fabric A' -FabricType FabricAttach

            }

            If ( -not (Get-HPOVNetwork -Type FC -Name 'Fabric B' -ErrorAction SilentlyContinue)) {

                New-HPOVNetwork -Type FC -Name 'Fabric B' -FabricType FabricAttach

            }

        }  

        It "Will get Synergy VCFC Interconnect resource type" {
        
            { $Script:SynergyCarbonModule = Get-HPOVInterconnectType -Name 'Virtual Connect SE 16Gb FC Module for Synergy' } | Should -Not -Throw
            $SynergyCarbonModule | Should -Not -BeNullOrEmpty
            $SynergyCarbonModule.partNumber | Should -Be '779227-B21'
        
        }

        It "Will create Synergy VCFC LIG" {

            $Script:LigParams = @{

                Name               = $SynergyVCFCLigName;
                FabricModuleType   = 'SEVCFC';
                FrameCount         = 1;
                InterconnectBaySet = 2;
                Bays               = @{Frame1 = @{Bay2 = 'SEVC16GbFC'; Bay5 = 'SEVC16GbFC' }}

            }

            { New-HPOVLogicalInterconnectGroup @LIGParams } | Should -Not -Throw

        }

        It "Will create FC Uplink Set for 'Fabric A'" {
        
            $Lig              = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCFCLigName -ErrorAction Stop
            $FabricA          = Get-HPOVNetwork -Type FC -Name 'Fabric A' -ErrorAction Stop
            $UplinkPorts      = "Bay2:Q1.1","Bay2:Q2.1"
            { $Script:Results = New-HPOVUplinkSet -InputObject $Lig -Type FibreChannel -Name 'Fabric A' -UplinkPorts $UplinkPorts -Networks $FabricA } | Should -Not -Throw
            $Results | Should -Not -BeNullOrEmpty
            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed
        
        }

        It "Will create FC Uplink Set for 'Fabric B'" {
        
            $Lig              = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCFCLigName -ErrorAction Stop
            $FabricB          = Get-HPOVNetwork -Type FC -Name 'Fabric B' -ErrorAction Stop
            $UplinkPorts      = "Bay5:Q1.1","Bay5:Q2.1"
            { $Script:Results = New-HPOVUplinkSet -InputObject $Lig -Type FibreChannel -Name 'Fabric B' -UplinkPorts $UplinkPorts -Networks $FabricB } | Should -Not -Throw
            $Results | Should -Not -BeNullOrEmpty

            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

    }

    Context "Create New Synergy SAS Logical Interconnect Group policy" {      

        It "Will get Synergy SAS Interconnect resource type" {
        
            { $Script:SynergyNatashaModule = Get-HPOVSasInterconnectType -Name 'Synergy 12Gb SAS Connection Module' } | Should -Not -Throw
            $SynergyNatashaModule | Should -Not -BeNullOrEmpty
            $SynergyNatashaModule.partNumber | Should -Be '755985-B21'
        
        }

        It "Will create Synergy SAS LIG" {

            $Script:LigParams = @{

                Name               = $SynergySASLigName;
                FabricModuleType   = 'SAS';
                FrameCount         = 1;
                InterconnectBaySet = 1;
                Bays               = @{Frame1 = @{Bay1 = 'SE12SAS'; Bay4 = 'SE12SAS' }}

            }

            { New-HPOVLogicalInterconnectGroup @LIGParams } | Should -Not -Throw

        }

    }

    Context "Create New Synergy Enclosure Group policy" {
    
        It "Will attempt to create Synergy Enclosure Group policy using an invalid LIG" {
    
            $ExpectedExceptionMessage = "Invalid LogicalInterconnectGroupMapping value provided 'InvalidLig'.  Please check the value and try again."
            
            { New-HPOVEnclosureGroup -Name 'Invalid LIG Test' -EnclosureCount 1 -LogicalInterconnectGroupMapping 'InvalidLig' } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will create a Synergy Enclosure Group with VC Only policy" {

            { $Script:3FrameVCLIG = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8LIGName -ErrorAction Stop } | Should -Not -Throw
        
            $Script:EgParams = @{

                Name                            = $SynergyEg1Name;
                EnclosureCount                  = 3;
                LogicalInterconnectGroupMapping = $3FrameVCLIG;
                IPv4AddressType                 = 'DHCP'

            }

            { $Script:CreateEG1Results = New-HPOVEnclosureGroup @EgParams } | Should -Not -Throw
            $CreateEG1Results | Should -Not -BeNullOrEmpty

            $CreateEG1Results.category | Should -Be 'enclosure-groups'
        
        }

        It "Will create a Synergy Enclosure Group with VC + SAS policies" {

            { $Script:3FrameVCLIG = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8LIGName -ErrorAction Stop } | Should -Not -Throw
            { $Script:SasLIG = Get-HPOVLogicalInterconnectGroup -Name $SynergySASLigName -ErrorAction Stop } | Should -Not -Throw
        
            $Script:EgParams = @{

                Name                            = ($SynergyEg1Name + 1);
                EnclosureCount                  = 3;
                LogicalInterconnectGroupMapping = $3FrameVCLIG,$SasLIG;
                IPv4AddressType                 = 'External'

            }

            { $Script:CreateEG2Results = New-HPOVEnclosureGroup @EgParams } | Should -Not -Throw
            $CreateEG2Results | Should -Not -BeNullOrEmpty
            $CreateEG2Results.category | Should -Be 'enclosure-groups'
        
        }

        It "Will create a Synergy Enclosure Group with VC + SAS policies in specific Frames" {

            { $Script:3FrameVCLIG = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8LIGName -ErrorAction Stop } | Should -Not -Throw
            { $Script:SasLIG = Get-HPOVLogicalInterconnectGroup -Name $SynergySASLigName -ErrorAction Stop } | Should -Not -Throw
        
            $Script:EgParams = @{

                Name                            = ($SynergyEg1Name + 3);
                EnclosureCount                  = 3;
                LogicalInterconnectGroupMapping = @{Frame1 = $3FrameVCLIG,$SasLIG; Frame2 = $3FrameVCLIG,$SasLIG; Frame3 = $3FrameVCLIG }
                IPv4AddressType                 = 'External'

            }

            { $Script:CreateEG3Results = New-HPOVEnclosureGroup @EgParams } | Should -Not -Throw
            $CreateEG3Results | Should -Not -BeNullOrEmpty
            $CreateEG3Results.category | Should -Be 'enclosure-groups'
        
        }
    
    }

    Context "Create New Synergy Enclosure Group with Image Streamer policy" {

        It "Will create a Synergy Enclosure Group with VC + SAS + ImageStreamer policies in specific Frames" {

            { $Script:i3SVCLIG = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8i3SLIGName -ErrorAction Stop } | Should -Not -Throw
            { $Script:SasLIG = Get-HPOVLogicalInterconnectGroup -Name $SynergySASLigName -ErrorAction Stop } | Should -Not -Throw
            { $Script:ManagementAddressPool = Get-HPOVAddressPoolSubnet -NetworkID $IPv4SubnetID -ErrorAction Stop | Get-HPOVAddressPoolRange } | Should -Not -Throw 
            { $Script:DeploymentNetwork = Get-HPOVNetwork -Type Ethernet -Name $I3SDeploymentNetworkName -ErrorAction Stop } | Should -Not -Throw
        
            $Script:EgParams = @{

                Name                            = $SynergyEgi3SName;
                EnclosureCount                  = 3;
                LogicalInterconnectGroupMapping = @{Frame1 = $i3SVCLIG,$SasLIG; Frame2 = $i3SVCLIG,$SasLIG; Frame3 = $i3SVCLIG }
                IPv4AddressType                 = 'AddressPool';
                AddressPool                     = $ManagementAddressPool;
                DeploymentNetworkType           = 'Internal'

            }

            { $Script:CreateEGResults = New-HPOVEnclosureGroup @EgParams } | Should -Not -Throw
            $CreateEGResults | Should -Not -BeNullOrEmpty
            $CreateEGResults.category | Should -Be 'enclosure-groups'
        
        }


        It "Will attempt to create an Enclosure Group with invalid Image Streamer settings" -skip {
        
            
        
        }
    
    }

    Context "Remove Synergy Group policies" {

        It "Will remove Synergy Enclosure Group resources" {
        
            { $Script:RemoveSynergyEgResults = Get-HPOVEnclosureGroup -Name $SynergyEg1Name* -ErrorAction Stop | Remove-HPOVEnclosureGroup -Confirm:$false } | Should -Not -Throw
            $RemoveSynergyEgResults | ForEach-Object { $_.Message | Should -Be 'Resource deleted successfully.' }

            { $Script:RemoveSynergyEgResults = Get-HPOVEnclosureGroup -Name $SynergyEgi3SName -ErrorAction Stop | Remove-HPOVEnclosureGroup -Confirm:$false } | Should -Not -Throw
            $RemoveSynergyEgResults.Message | Should -Be 'Resource deleted successfully.'
        
        }

        It "Will remove Logical Interconnect Group resource $SynergyVCSE40F8LIGName" {

            { $Script:RemoveLIGResults = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8LIGName -ErrorAction Stop | Remove-HPOVLogicalInterconnectGroup -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($RemoveLIGResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveLIGResults

            }

            $RemoveLIGResults.taskState | Should -Be 'Completed'

        }

        It "Will remove Logical Interconnect Group resource $SynergyVCSE40F8i3SLIGName" {

            { $Script:RemoveLIGResults = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCSE40F8i3SLIGName -ErrorAction Stop | Remove-HPOVLogicalInterconnectGroup -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($RemoveLIGResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveLIGResults

            }

            $RemoveLIGResults.taskState | Should -Be 'Completed'

        }

        It "Will remove Logical Interconnect Group resource $SynergyVCFCLigName" {

            { $Script:RemoveLIGResults = Get-HPOVLogicalInterconnectGroup -Name $SynergyVCFCLigName -ErrorAction Stop | Remove-HPOVLogicalInterconnectGroup -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($RemoveLIGResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveLIGResults

            }

            $RemoveLIGResults.taskState | Should -Be 'Completed'

        }

        It "Will remove SAS Logical Interconnect Group resource $SynergySASLigName" {

            { $Script:RemoveLIGResults = Get-HPOVLogicalInterconnectGroup -Name $SynergySASLigName -ErrorAction Stop | Remove-HPOVLogicalInterconnectGroup -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($RemoveLIGResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveLIGResults

            }

            $RemoveLIGResults.taskState | Should -Be 'Completed'

        }

    }

    Context "Remove created Synergy address pool resources" {

        It "Will remove created Management Ethernet Network" {
        
            { $Script:RemoveEthernetNetworkResults = Get-HPOVNetwork -Type Ethernet -Name $IPv4EthernetNetworkName -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            $RemoveEthernetNetworkResults | Should -Not -BeNullOrEmpty
            
            if ($RemoveEthernetNetworkResults.Status -ne "Completed") {

                DisplayTaskError $RemoveEthernetNetworkResults.Details

            }

            $RemoveEthernetNetworkResults.taskState | Should -Be Completed
        
        }

        It "Will remove created I3S Deployment Ethernet Network" {
        
            { $Script:RemoveEthernetNetworkResults = Get-HPOVNetwork -Type Ethernet -Name $I3SDeploymentNetworkName -ErrorAction Stop | Remove-HPOVNetwork -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            $RemoveEthernetNetworkResults | Should -Not -BeNullOrEmpty
            $RemoveEthernetNetworkResults.taskState | Should -Be Completed
        
        }

        It "Will remove IPv4 Subnet Pool Ranges" {

            { $Script:RemoveIPv4SubnetPoolRangeResults = Get-HPOVAddressPoolRange -Type IPv4 | Where-Object { $_.name -ne 'I3S Deployment Range 1' } | Remove-HPOVAddressPoolRange -confirm:$false } | Should -Not -Throw
            $RemoveIPv4SubnetPoolRangeResults | Should -Not -BeNullOrEmpty
            $RemoveIPv4SubnetPoolRangeResults | ForEach-Object { $_.message | Should -Be 'Resource deleted successfully.' }
        
        }

        It "Will remove IPv4 $IPv4SubnetID Subnet" {
        
            { $Script:RemoveIPv4SubnetResults = Get-HPOVAddressPoolSubnet -NetworkId $IPv4SubnetID | Remove-HPOVAddressPoolSubnet -Confirm:$false } | Should -Not -Throw
            $RemoveIPv4SubnetResults | Should -Not -BeNullOrEmpty
            $RemoveIPv4SubnetResults | ForEach-Object { $_.message | Should -Be 'Resource deleted successfully.' }
        
        }

        It "Will remove IPv4 $I3SIPv4SubnetId Subnet" {
        
            { $Script:RemoveI3SIPv4SubnetResults = Get-HPOVAddressPoolSubnet -NetworkId $I3SIPv4SubnetId | Remove-HPOVAddressPoolSubnet -Confirm:$false } | Should -Not -Throw
            $RemoveI3SIPv4SubnetResults | Should -Not -BeNullOrEmpty
            $RemoveI3SIPv4SubnetResults | ForEach-Object { $_.message | Should -Be 'Resource deleted successfully.' }
        
        }
    
    }

}

# Add Server Hardware and perform basic Operations
Describe "HPE ProLiant DL Management" -Tag All, Rackmount, ServerHardware {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Script:Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Claim DL rack mount servers" {

        It "Will attempt to claim a non-existant DL server" {

            $Results = Add-HPOVServer -Hostname foo -Username dummy -Password dummy

            $Results.taskState | Should -Be Error

        }

        It "Will claim DL360pGen8-2253" {

            { $Script:AddServerResults = Add-HPOVServer -Hostname $DL360pGen8_2253 -Username $ServeriLOUsername -Password $ServeriLOPassword } | Should -Not -Throw

            $AddServerResults.category | Should -Be tasks

            if ("Completed","Warning" -notcontains $AddServerResults.taskState) {

                DisplayTaskError $AddServerResults

            }

            "Completed","Warning" -contains $AddServerResults.taskState | Should -Be $true

        }

    }

    Context "Perform Server Operations" {

        It "Will verify DL360pGen8-2253 exists" {

            { Get-HPOVServer -Name $DL360pGen8_2253 -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will get server hardware resource via Server Name property" {

            { $script:Server = Get-HPOVServer -ServerName $ServerNameFqdn -ErrorAction Stop } | Should -Not -Throw

            ($Server | Measure-Object).Count | Should -Be 1

        }

        It "Will get server hardware resource via Server Name property using wildcard search" -skip {

            { $script:Server = Get-HPOVServer -ServerName $ServerName* -ErrorAction Stop } | Should -Not -Throw

            ($Server | Measure-Object).Count | Should -BeGreaterThan 1

        }

        It "Will perform server hardware refresh" {

            { $Script:RefreshServerResults = Get-HPOVServer -Name $DL360pGen8_2253 -ErrorAction Stop | Update-HPOVServer | Wait-HPOVTaskComplete } | Should -Not -Throw

            $RefreshServerResults.category | Should -Be tasks

            if ("Completed","Warning" -notcontains $RefreshServerResults.taskState) {

                DisplayTaskError $RefreshServerResults

            }

            "Completed","Warning" -contains $RefreshServerResults.taskState | Should -Be $true

        }

        It "Will power on DL360pGen8-2253 via pipeline" {

            { Get-HPOVServer -Name $DL360pGen8_2253 -ErrorAction Stop | Start-HPOVServer | Wait-HPOVTaskComplete } | Should -Not -Throw

        }

        It "Will validate DL360pGen8-2253 power state is On" {

            { $Script:ServerObject = Get-HPOVServer -Name $DL360pGen8_2253 -ErrorAction Stop } | Should -Not -Throw
            $ServerObject.powerState | Should -Be 'On'

        }

        It "Will power off DL360pGen8-2253" {

            $ServerObject = Get-HPOVServer -Name $DL360pGen8_2253 -ErrorAction Stop
            { Stop-HPOVServer -InputObject $ServerObject -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

        }

        It "Will get iLO SSO auth key" -Skip {
        
            { $script:iLOSsoResults = Get-HPOVServer | Select-Object -First 1 | Get-HPOVIloSso } | Should -Not -Throw
           $iLOSsoResults.iloSsoUrl | Should -Not -BeNullOrEmpty
           $iLOSsoResults.iloSsoUrl.StartsWith('https://') | Should -Be $true
        
        }

        It "Will get iLO SSO auth key for Remote Console" -Skip {
        
            { $script:iLOSsoResults = Get-HPOVServer | Select-Object -First 1 | Get-HPOVIloSso -RemoteConsoleOnly } | Should -Not -Throw
           $iLOSsoResults.remoteConsoleUrl | Should -Not -BeNullOrEmpty
           $iLOSsoResults.remoteConsoleUrl.StartsWith('hplocons://') | Should -Be $true 
        
        }

        It "Will rename the associated Server Hardware Type" {

            { $Script:ServerObject = Get-HPOVServer -Name $DL360pGen8_2253 -ErrorAction Stop } | Should -Not -Throw
            $SHT = Send-HPOVRequest -Uri $ServerObject.serverHardwareTypeUri

            $SHTOriginalName = $SHT.name.Clone()

            { $SHT | Set-HPOVServerHardwareType -Name ($SHT.name + ' 1') } | Should -Not -Throw

            { Get-HPOVServerHardwareType -Name ($SHT.name + ' 1') | Set-HPOVServerHardwareType -Name $SHTOriginalName } | Should -Not -Throw

        }

    }

    It "Will remove DL360pGen8-2253" {

        { $Script:RemoveServerResults = Get-HPOVServer -Name $DL360pGen8_2253 -ErrorAction Stop | Remove-HPOVServer -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

        $RemoveServerResults.category | Should -Be tasks

        if ("Completed","Warning" -notcontains $RemoveServerResults.taskState) {

            DisplayTaskError $RemoveServerResults

        }

        $RemoveServerResults.taskState | Should -Be Completed

    }
 
}

Describe "HPE BladeSystem Management" -Tag All, BladeSystem, ServerHardware {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Script:Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Context "Claim and monitor Enclosure" {
    
        It "Will attempt to add $Enclosure1Name as Monitored enclosure" {

            $ExpectedExceptionMessage = 'This enclosure is already being managed by this appliance.'

            { $Script:AddEnclosureResults = Add-HPOVEnclosure -Hostname $Enclosure1Address -Username $EnclosureUsername -Password $EnclosurePassword -Monitored } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will claim and add $Enclosure2Name as Monitored enclosure" {
        
            { $Script:AddEnclosureResults = Add-HPOVEnclosure -Hostname $Enclosure2Address -Username $EnclosureUsername -Password $EnclosurePassword -Monitored } | Should -Not -Throw

            $AddEnclosureResults.category | Should -Be tasks

            if ("Completed","Warning" -notcontains $AddEnclosureResults.taskState) {

                DisplayTaskError $AddEnclosureResults

            }

            "Completed","Warning" -contains $AddEnclosureResults.taskState | Should -Be $true
        
        }

        It "Will validate $Enclosure2Name resource exists" {
        
            { Get-HPOVEnclosure -Name $Enclosure2Name -ErrorAction Stop } | Should -Not -Throw

            (Get-HPOVEnclosure -Name $Enclosure2Name).state | Should -Be Monitored
        
        }

        It "Will power on Bay 1 in $Enclosure2Name" {
            
            {$Script:PowerOnServerResults = Get-HPOVServer -Name "$Enclosure2Name, Bay 1" -ErrorAction Stop | Start-HPOVServer } | Should -Not -Throw

            $PowerOnServerResults.category | Should -Be tasks

            if ($PowerOnServerResults.taskState -ne "Completed") {

                DisplayTaskError $PowerOnServerResults

            }

            $PowerOnServerResults.taskState | Should -Be Completed            
        
        }

        It "Will validate Bay 1 in $Enclosure2Name is Powered On" {
        
            (Get-HPOVServer -Name "$Enclosure2Name, Bay 1" -ErrorAction Stop).powerState | Should -Be On
        
        }

        It "Will power off Bay 1 in $Enclosure2Name" {
        
            { Get-HPOVServer -Name "$Enclosure2Name, Bay 1" -ErrorAction Stop | Stop-HPOVServer -Confirm:$false} | Should -Not -Throw
        
        }
        
        It "Will refresh $Enclosure2Name enclosure resource" {

            { Get-HPOVEnclosure -Name $Enclosure2Name -ErrorAction Stop | Update-HPOVEnclosure -Refresh -Confirm:$false } | Should -Not -Throw
            
        }
        
        It "Will remove $Enclosure2Name from appliance" {
        
            { $Script:RemoveEnclosureResults = Get-HPOVEnclosure -Name $Enclosure2Name -ErrorAction Stop | Remove-HPOVEnclosure -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            $RemoveEnclosureResults.category | Should -Be tasks

            if ($RemoveEnclosureResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveEnclosureResults

            }
            
            $RemoveEnclosureResults.taskState | Should -Be Completed
        
        }        
    
    }

    Context "Claim and manage Enclosure" {

        It "Will validate Baseline exists on appliance" {
        
            { $Script:BaselineObject = Get-HPOVBaseline -FileName $ExistingBaselineName -ErrorAction Stop } | Should -Not -Throw
            $BaselineObject | Should -Not -BeNullOrEmpty
            $BaselineObject.category | Should -Be 'firmware-drivers'
        
        }
    
        It "Will add $Enclosure2Name as a managed resource with firmware baseline" {
            
            $EnclosureGroup = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop
    
            { $Script:AddEnclosureResults = Add-HPOVEnclosure -Hostname $Enclosure2Address -Username $EnclosureUsername -Password $EnclosurePassword -EnclosureGroup $EnclosureGroup -Baseline $BaselineObject } | Should -Not -Throw

            $AddEnclosureResults.category | Should -Be tasks

            if ("Completed","Warning" -notcontains $AddEnclosureResults.taskState) {

                DisplayTaskError $AddEnclosureResults

            }

            "Completed","Warning" -contains $AddEnclosureResults.taskState | Should -Be $true
    
        }

        It "Will validate $Enclosure2Name resource exists" {
        
            { Get-HPOVEnclosure -Name $Enclosure2Name -ErrorAction Stop } | Should -Not -Throw

            (Get-HPOVEnclosure -Name $Enclosure2Name).state | Should -Be Configured
        
        }

        It "Will remove $Enclosure2Name from appliance" {
        
            { $Script:RemoveEnclosureResults = Get-HPOVEnclosure -Name $Enclosure2Name -ErrorAction Stop | Remove-HPOVEnclosure -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            $RemoveEnclosureResults.category | Should -Be tasks

            if ($RemoveEnclosureResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveEnclosureResults

            }
            
            $RemoveEnclosureResults.taskState | Should -Be Completed
        
        }        
    
    }

    Context "Peform management tasks with existing BladeSystem enclosure" {
    
        It "Will validate '$ExistingEnclosureName' Enclosure exists" {
    
            { $Script:ExistingEnclosureObject = Get-HPOVEnclosure -Name $ExistingEnclosureName -ErrorAction Stop } | Should -Not -Throw
            $ExistingEnclosureObject | Should -Not -BeNullOrEmpty
            $ExistingEnclosureObject.category | Should -Be 'enclosures'
    
        }

        It "Will update enclosure resource using refresh options" {

            { $Script:EnclosureRefreshResults = Update-HPOVEnclosure -InputObject $ExistingEnclosureObject -Refresh -Hostname $ExistingEnclosureIPAddress -Username $ExistingEnclosureUsername -Password $ExistingEnclosurePassword -Async -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            $EnclosureRefreshResults | Should -Not -BeNullOrEmpty
            $EnclosureRefreshResults.category | Should -Be 'tasks'

            if ("Completed","Warning" -notcontains $EnclosureRefreshResults.taskState) {

                DisplayTaskError $EnclosureRefreshResults

            }

            "Completed","Warning" -contains $EnclosureRefreshResults.taskState | Should -Be $true
        
        }

        It "Will validate '$ExistingEnclosureName' Logical Enclosure exists" {
    
            { $Script:ExistingLogicalEnclosureObject = Get-HPOVLogicalEnclosure -Name $ExistingEnclosureName -ErrorAction Stop } | Should -Not -Throw
            $ExistingLogicalEnclosureObject | Should -Not -BeNullOrEmpty
            $ExistingLogicalEnclosureObject.category | Should -Be 'logical-enclosures'
    
        }

        It "Will Reapply Logical Enclosure configuration to resource" {

            { $Script:EnclosureRefreshResults = Get-HPOVLogicalEnclosure -Name $ExistingEnclosureName -ErrorAction Stop | Update-HPOVLogicalEnclosure -Reapply -Async -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            $EnclosureRefreshResults | Should -Not -BeNullOrEmpty
            $EnclosureRefreshResults.category | Should -Be 'tasks'

            if ("Completed","Warning" -notcontains $EnclosureRefreshResults.taskState) {

                DisplayTaskError $EnclosureRefreshResults

            }

            "Completed","Warning" -contains $EnclosureRefreshResults.taskState | Should -Be $true
        
        }

    }

}

Describe "HPE OneView Firmware Reporting" -Tag All, ServerHardware {

    BeforeAll {

        if (-not $ConnectedSessions) {

            { $Script:Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw

        }

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        $Script:FirmwareReportBaseline = Get-HPOVBaseline -IsoFileName $ExistingBaselineName -ErrorAction Stop

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    It "Will collect Server Firmware report" {

        { $Script:ServerFirmwareReport = Get-HPOVServer | Show-HPOVFirmwareReport } | Should -Not -Throw

    }

    It "Will validate collected report" {

        $ServerFirmwareReport | ForEach-Object {

            $_ | Should -BeOfType [HPOneView.ServerHardware+Firmware]

        }

    }

    It "Will collect a Logical Enclosure firmware report compare to Baseline" {

        { $Script:LogicalEnclosureFirmwareReport = Get-HPOVLogicalEnclosure -Name Encl1 -ErrorAction Stop | Show-HPOVFirmwareReport -Baseline $FirmwareReportBaseline } | Should -Not -Throw

    }

    It "Will validate collected report" {

        0..3 | ForEach-Object { $LogicalEnclosureFirmwareReport[$_] | Should -BeOfType [HPOneView.Enclosure+Firmware] }

        4..($LogicalEnclosureFirmwareReport.Count - 1) | ForEach-Object { $LogicalEnclosureFirmwareReport[$_] | Should -BeOfType [HPOneView.ServerHardware+Firmware] }

    }

}

# This section will use Encl1 and non randomly generated networks for testing
Describe "Server Profile Policy management" -Tag All, ServerProfile {

    BeforeAll {

        $ConnectedSessions | ForEach-Object { Disconnect-HPOVMgmt -Hostname $_ }

        { $Script:Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
        { $Script:Connection2 = Connect-HPOVMgmt -Hostname $Appliance2 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
        { $Script:Connection3 = Connect-HPOVMgmt -Hostname $Appliance3 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 

        if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

            ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

        }  

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        if (-not(Get-HPOVServerHardwareType -Name 'DL360 Gen9 1' -ErrorAction SilentlyContinue)) {

            if (-not (Test-Path "C:\Tests\dl360gen9sht.json"))
            {

                $ExePath = $MyInvocation.MyCommand.Path
                $ExeDir  = Split-Path -Parent $ExePath
                $Dl360Gen9Sht = [System.String]::Join("`n",(Get-Content "$ExeDir\dl360gen9sht.json" -ErrorAction Stop))

            }

            else
            {

                $Dl360Gen9Sht = [System.String]::Join("`n",(Get-Content "C:\Tests\dl360gen9sht.json" -ErrorAction Stop))

            }

            $null = Send-HPOVRequest -uri /rest/server-hardware-types -Method POST -Body $Dl360Gen9Sht -AddHeader @{"X-API-Version" = '300'}

            Get-HPOVServerHardwareType -Name 'DL360 Gen9 1' -ErrorAction Stop

        }

    }

    AfterAll {

        If ($ConnectedSessions) {

            { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

        }

    }

    Describe -Name "HPE ProLiant DL" {

        Context -Name "Create and validate DL360 Gen9 Policies" {

            It -Name "Will create '$Dl360Gen9TemplateName' DL360 Gen9 Server Profile Template" {
        
                $Params = @{
    
                    Name                 = $Dl360Gen9TemplateName;
                    Description          = 'Testing Creation';                                 
                    FirmwareMode         = 'FirmwareOffline';
                    ForceInstallFirmware = $True;
                    PxeBootPolicy        = 'Auto';
                    BootMode             = 'UEFI';
                    Baseline             = (Get-HPOVBaseline -File $ExistingBaselineName -ErrorAction Stop);
                    ServerHardwareType   = (Get-HPOVServerHardwareType -Name 'DL360 Gen9 1' -ErrorAction Stop);
                    Firmware             = $True;
    
                }
    
                { $Script:Results = New-HPOVServerProfileTemplate @Params | Wait-HPOVTaskComplete } | Should -Not -Throw
    
                $Results.category | Should -Be tasks
    
                if ($Results.taskState -ne "Completed") {
    
                    DisplayTaskError $Results
    
                }
    
                $Results.taskState | Should -Be Completed
        
            }
    
            Describe -Name "Validate '$Dl360Gen9TemplateName'  Server Profile Template policy settings" {
    
                It "Will validate Server Profile Template '$Dl360Gen9TemplateName' exists" {
            
                    { $Script:DL360SPT = Get-HPOVServerProfileTemplate -Name $Dl360Gen9TemplateName -ErrorAction Stop } | Should -Not -Throw
                    $DL360SPT.category | Should -Be 'server-profile-templates'
        
                }
    
                It "Will validate '$Dl360Gen9TemplateName' boot mode is set to 'UEFI'" {
        
                    $DL360SPT.bootMode.mode | Should -Be UEFI
        
                }
        
                It "Will validate '$Dl360Gen9TemplateName' PXE Boot Mode policy is set to 'Auto'" {
        
                    $DL360SPT.bootMode.pxeBootPolicy | Should -Be Auto
        
                }
        
                It "Will validate '$Dl360Gen9TemplateName' Manage Firmware is set to 'True'" {
        
                    $DL360SPT.firmware.manageFirmware | Should -Be $true
        
                }
        
                It "Will validate '$Dl360Gen9TemplateName' Manage Firmware install policy is set to 'FirmwareOnlyOfflineMode'" {
        
                    $DL360SPT.firmware.firmwareInstallType | Should -Be FirmwareOnlyOfflineMode
        
                }
        
                It "Will validate '$Dl360Gen9TemplateName' Serial Number type policy is set to 'Physical'" {
        
                    $DL360SPT.serialNumberType | Should -Be Physical
        
                }
        
                It "Will validate '$Dl360Gen9TemplateName' MAC Type policy is set to 'Physical'" {
        
                    $DL360SPT.macType | Should -Be Physical
        
                }
        
                It "Will validate '$Dl360Gen9TemplateName' WWN Type policy is set to 'Physical'" {
        
                    $DL360SPT.wwnType | Should -Be Physical
        
                }
    
                It "Will validate '$Dl360Gen9TemplateName' does not contain any Disk Controller" {
        
                    $DL360SPT.localStorage.controllers.Count | Should -Be 0
        
                }
    
            }
    
            It -Name "Will create '$Dl360Gen9MLDTemplateName' DL360 Gen9 Server Profile Template with multiple Logical Disks" {
    
                { $Script:Disk1 = New-HPOVServerProfileLogicalDisk -name 'Boot' -NumberofDrives 2 } | Should -Not -Throw
                { $Script:Disk2 = New-HPOVServerProfileLogicalDisk -name 'Data' -RAID RAID5 -NumberofDrives 8 -DriveType Sas } | Should -Not -Throw
        
                $Params = @{
    
                    Name                 = $Dl360Gen9MLDTemplateName;
                    Description          = 'PESTER';                                 
                    Firmware             = $True;
                    Baseline             = (Get-HPOVBaseline -File $ExistingBaselineName -ErrorAction Stop);
                    FirmwareMode         = 'FirmwareOffline';
                    ForceInstallFirmware = $True;
                    PxeBootPolicy        = 'Auto';
                    BootMode             = 'UEFI';
                    ServerHardwareType   = (Get-HPOVServerHardwareType -Name 'DL360 Gen9 1' -ErrorAction Stop);
                    LocalStorage         = $True;
                    StorageController    = (New-HPOVServerProfileLogicalDiskController -Initialize -LogicalDisk $Disk1,$Disk2)
    
                }
    
                { $Script:Results = New-HPOVServerProfileTemplate @Params | Wait-HPOVTaskComplete } | Should -Not -Throw
                $Results.category | Should -Be tasks
    
                if ($Results.taskState -ne "Completed") {
    
                    DisplayTaskError $Results
    
                }
    
                $Results.taskState | Should -Be Completed
        
            }
    
            Describe -Name "Validate '$Dl360Gen9MLDTemplateName' Server Profile Template policy settings" {
    
                It "Will validate Server Profile Template '$Dl360Gen9MLDTemplateName' exists" {
            
                    { $Script:DL360MDPSPT = Get-HPOVServerProfileTemplate -Name $Dl360Gen9MLDTemplateName -ErrorAction Stop } | Should -Not -Throw
                    $DL360SPT.category | Should -Be 'server-profile-templates'
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' boot mode is set to 'UEFI'" {
        
                    $DL360MDPSPT.bootMode.mode | Should -Be UEFI
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' PXE Boot Mode policy is set to 'Auto'" {
        
                    $DL360MDPSPT.bootMode.pxeBootPolicy | Should -Be Auto
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Manage Firmware is set to 'True'" {
        
                    $DL360MDPSPT.firmware.manageFirmware | Should -Be $true
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Manage Firmware install policy is set to 'FirmwareOnlyOfflineMode'" {
        
                    $DL360MDPSPT.firmware.firmwareInstallType | Should -Be FirmwareOnlyOfflineMode
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Serial Number type policy is set to 'Physical'" {
        
                    $DL360MDPSPT.serialNumberType | Should -Be Physical
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' MAC Type policy is set to 'Physical'" {
        
                    $DL360MDPSPT.macType | Should -Be Physical
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' WWN Type policy is set to 'Physical'" {
        
                    $DL360MDPSPT.wwnType | Should -Be Physical
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' should contain a single Disk Controller" {
        
                    $DL360MDPSPT.localStorage.controllers.Count | Should -Be 1
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller set to 'RAID' type" {
        
                    $DL360MDPSPT.localStorage.controllers[0].mode | Should -Be RAID
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller Logical Disk policy contains 2" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives.Count | Should -Be 2
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller LD1 Name is 'Boot'" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives[0].name | Should -Be 'Boot'
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller LD1 number of drives is '2'" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives[0].numPhysicalDrives | Should -Be 2
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller LD1 Drive Technology is 'Null' (aka Auto)" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives[0].driveTechnology | Should -Be $null
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller LD1 RAID Level is 'RAID1'" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives[0].raidLevel | Should -Be 'RAID1'
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller LD2 Name is 'Data'" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives[1].name | Should -Be 'Data'
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller LD2 number of drives is '8'" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives[1].numPhysicalDrives | Should -Be 8
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller LD2 Drive Technology is 'SasHdd'" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives[1].driveTechnology | Should -Be 'SasHdd'
        
                }
        
                It "Will validate '$Dl360Gen9MLDTemplateName' Disk Controller LD2 RAID Level is 'RAID5'" {
        
                    $DL360MDPSPT.localStorage.controllers[0].logicalDrives[1].raidLevel | Should -Be 'RAID5'
                
                }
    
            }
        
        }
    
        Context -Name "Create basic DL Server Profiles for DL360 Gen9" {
    
            It "Will create '$Dl360Gen9ServerProfileName' basic DL360 Gen9 Server Profile (no SPT)" {
        
                $Params = @{
    
                    Name                 = $Dl360Gen9ServerProfileName;
                    Description          = 'Testing Creation';                                 
                    FirmwareMode         = 'FirmwareOffline';
                    ForceInstallFirmware = $True;
                    PxeBootPolicy        = 'Auto';
                    BootMode             = 'UEFI';
                    Baseline             = (Get-HPOVBaseline -File $ExistingBaselineName -ErrorAction Stop);
                    ServerHardwareType   = (Get-HPOVServerHardwareType -Name 'DL360 Gen9 1' -ErrorAction Stop);
                    AssignmentType       = 'Unassigned';
                    Firmware             = $True;
    
                }
    
                { $Script:Results = New-HPOVServerProfile -Confirm:$False @Params | Wait-HPOVTaskComplete } | Should -Not -Throw
                $Results.category | Should -Be tasks
    
                if ($Results.taskState -ne "Completed") {
    
                    DisplayTaskError $Results
    
                }
    
                $Results.taskState | Should -Be Completed
        
            }
    
            It "Will validate DL Boot Order Management isn't set" {
            
                { $Script:ServerProfile = Get-HPOVServerProfile -Name $Dl360Gen9ServerProfileName -ErrorAction Stop } | Should -Not -Throw
                $ServerProfile.bootMode.manageMode | Should -Be $true
                $ServerProfile.bootMode.mode | Should -Be UEFI
                $ServerProfile.boot.manageBoot | Should -Be $false
                $ServerProfile.boot.order | Should -Be $null
            
            }
    
            It "Will associate '$Dl360Gen9ServerProfileName' DL360 Gen9 Server Profile with SPT '$Dl360Gen9TemplateName'" {
            
                { $Script:ServerProfile = Get-HPOVServerProfile -Name $Dl360Gen9ServerProfileName -ErrorAction Stop } | Should -Not -Throw
                { $Script:ServerProfileTemplate = Get-HPOVServerProfileTemplate -Name $Dl360Gen9TemplateName -ErrorAction Stop } | Should -Not -Throw
                { $Script:JoinResults = Join-HPOVServerProfileToTemplate -Template $ServerProfileTemplate -ServerProfile $ServerProfile | Wait-HPOVTaskComplete } | Should -Not -Throw
                $JoinResults.category | Should -Be tasks
    
                if ($JoinResults.taskState -ne "Completed") {
    
                    DisplayTaskError $JoinResults
    
                }
    
                $JoinResults.taskState | Should -Be Completed
            
            }
        
        }

    }

    Context "HPE BladeSystem - Server Profile operations" {

        Context "Basic Server Profile resource with Ethernet and Baseline only for BL460c Gen8" {

            It "Will validate BL460c Gen8 Server Hardware Type exists" {
            
                { $Script:BL460cGen8SHT = Get-HPOVServerHardwareType -Name 'BL460c Gen8 1' -ErrorAction Stop } | Should -Not -Throw
                $BL460cGen8SHT | Should -Not -BeNullOrEmpty
                $BL460cGen8SHT.category | Should -BeExactly 'server-hardware-types'
            
            }
    
            It "Will validate $DCSDefaultEGName exists" {
            
                { $Script:EnclosureGroup = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop } | Should -Not -Throw
                $EnclosureGroup | Should -Not -BeNullOrEmpty
                $EnclosureGroup.category | Should -Be 'enclosure-groups'
            
            }
    
            It "Will validate Baseline exists on appliance" {
            
                { $Script:BaselineObject = Get-HPOVBaseline -FileName $ExistingBaselineName -ErrorAction stop } | Should -Not -Throw
                $BaselineObject | Should -Not -BeNullOrEmpty
                $BaselineObject.category | Should -Be 'firmware-drivers'
            
            }
        
            It "Will attempt to create Server Profile Connection with invalid Ethernet Network" {
        
                $ExpectedExceptionMessage = "The specified 'Foo' Network resource was not found on '{0}' appliance connection.  Please check the name and try again." -f $Appliance1
                { Get-HPOVNetwork -Name Foo -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage
        
            }
    
            It "Will validate VLAN 1-A Ethernet network exsits" {
            
                $Vlan1A = Get-HPOVNetwork -Name "VLAN 1-A" -ErrorAction Stop
                $Vlan1A | Should -Not -BeNullOrEmpty
                $Vlan1A.category | Should -Be 'ethernet-networks'
            
            }
    
            It "Will create bootable Server Profile Ethernet Connection using VLAN 1-A (FlexNIC1:a)" {
    
                $Vlan1A = Get-HPOVNetwork -Name "VLAN 1-A" -ErrorAction Stop
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection -ConnectionID 1 -Name 'VLAN 1-A Connection' -Network $Vlan1A -Bootable -Priority Primary
                $ProfileConnection1 | Should -Not -BeNullOrEmpty
                $ProfileConnection1.functionType | Should -Be 'Ethernet'
                $ProfileConnection1.id | Should -Be 1
                $ProfileConnection1.boot.priority | Should -Be Primary
                $ProfileConnection1.networkUri | Should -BeExactly $Vlan1A.uri
    
            }
    
            It "Will validate VLAN 1-B Ethernet Network exists" {
    
                $Vlan1B = Get-HPOVNetwork -Name "VLAN 1-B" -ErrorAction Stop
                $Vlan1B | Should -Not -BeNullOrEmpty
                $Vlan1B.category | Should -Be 'ethernet-networks'
    
            }
    
            It "Will create Server Profile Ethernet Connection2 using VLAN 1-B (FlexNIC2:a)" {
    
                $Vlan1B = Get-HPOVNetwork -Name "VLAN 1-B" -ErrorAction Stop
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection -ConnectionID 2 -Name 'VLAN 1-B Connection' -Network $Vlan1B
                $ProfileConnection2 | Should -Not -BeNullOrEmpty
                $ProfileConnection2.functionType | Should -Be 'Ethernet'
                $ProfileConnection2.id | Should -Be 2
                $ProfileConnection2.networkUri | Should -BeExactly $Vlan1B.uri
    
            }        
    
            It "Will attempt to create basic Server Profile with 2 Ethernet Connections without -EnclosureGroup parameter" {
    
                $ExpectedExceptionMessage = 'Enclosure Group is missing.  Please provide an Enclosure Group using the -EnclosureGroup Parameter and try again.'
            
                { New-HPOVServerProfile -Name $BasicServerProfileName -AssignmentType Unassigned -ServerHardwareType $BL460cGen8SHT -Connections $ProfileConnection1,$ProfileConnection2 | Wait-HPOVTaskComplete } | Should -Throw $ExpectedExceptionMessage
            
            }
        
            It "Will attempt to create basic Server Profile with bootable Ethernet Connection and not provide the -ManageBoot parameter" {
            
                $ExpectedExceptionMessage = 'Bootable Connections 1 were found, however the -ManageBoot switch Parameter was not provided.  Please correct your command syntax and try again.'
                
                { New-HPOVServerProfile -Name $BasicServerProfileName -AssignmentType Unassigned -ServerHardwareType $BL460cGen8SHT -EnclosureGroup $EnclosureGroup -Connections $ProfileConnection1,$ProfileConnection2 } | Should -Throw $ExpectedExceptionMessage
            
            }
    
            It "Will attempt to create basic Server Profile with unsupport RAID6 type for LogicalDisk" {
            
                $UnsupportedLogicalDisk1 = New-HPOVServerProfileLogicalDisk -Name 'Invalid Disk 1' -RAID RAID6
                $UnsupportedStorageController = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $UnsupportedLogicalDisk1
                $ParamHash = @{
                                
                    Name               = $BasicServerProfileName
                    AssignmentType     = 'Unassigned';
                    ServerHardwareType = $BL460cGen8SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ProfileConnection1,$ProfileConnection2;
                    LocalStorage       = $true;
                    StorageController  = $UnsupportedStorageController;
                    ManageBoot         = $true;
                    Firmware           = $true;
                    Baseline           = $BaselineObject;
                    FirmwareMode       = 'FirmwareAndSoftware'
                
                }
                
                $ExpectedExceptionMessage = 'Unsupported LogicalDisk RAID Level RAID6 policy with Invalid Disk 1 logical disk.'
                
                { New-HPOVServerProfile @ParamHash } | Should -Throw $ExpectedExceptionMessage
            
            }
    
            It "Will create basic BL460c Gen8 Server Profile '$BasicServerProfileName' with 2 Ethernet Connections" {
    
                $ParamHash = @{
                    
                    Name               = $BasicServerProfileName
                    AssignmentType     = 'Unassigned';
                    ServerHardwareType = $BL460cGen8SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ProfileConnection1,$ProfileConnection2;
                    ManageBoot         = $true;
                    Firmware           = $true;
                    Baseline           = $BaselineObject;
                    FirmwareMode       = 'FirmwareAndSoftware'
                    
                }            
            
                { $Script:CreateBasicServerProfileResults = New-HPOVServerProfile -Confirm:$False @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
    
                $CreateBasicServerProfileResults.category | Should -Be tasks
                
                if ($CreateBasicServerProfileResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateBasicServerProfileResults
    
                }
    
                $CreateBasicServerProfileResults.taskState | Should -Be Completed
            
            }
    
            It "Will validate $BasicServerProfileName exists" {
            
                { $Script:BasicServerProfileObject = Get-HPOVServerProfile -Name $BasicServerProfileName -ErrorAction Stop } | Should -Not -Throw
                $BasicServerProfileObject | Should -Not -BeNullOrEmpty
                $BasicServerProfileObject.category | Should -Be 'server-profiles'
    
            }
        
        }
    
        Context "Create basic Server Profile with iSCSI Connections for BL460c Gen9" {
    
            $Script:BL460cGen9SHT  = Get-HPOVServerHardwareType -Name 'BL460c Gen9 1' -ErrorAction Stop
            $Script:EnclosureGroup = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop
            $Script:Vlan1A         = Get-HPOVNetwork -Name "VLAN 1-A" -ErrorAction Stop
            $Script:Vlan1B         = Get-HPOVNetwork -Name "VLAN 1-B" -ErrorAction Stop
            $Script:DecryptedChapSecret       = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ChapSecret))
            $Script:DecryptedMutualChapSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($MutualChapSecret))
            
            It "Will create primary bootable iSCSI Connection" {
    
                $IscsiParams = @{
                    ConnectionID                  = 1;
                    Name                          = 'iSCSI Connection 1';
                    ConnectionType                = 'iSCSI';
                    Network                       = $Vlan1A;
                    Bootable                      = $true;
                    BootVolumeSource              = 'UserDefined';
                    Priority                      = 'IscsiPrimary';
                    IscsiIPv4AddressSource        = 'UserDefined';
                    IscsiIPv4Address              = $Con1IscsiIPv4Address;
                    IscsiIPv4SubnetMask           = $Con1IscsiIPv4SubnetMask;
                    IscsiBootTargetIqn            = $Con1IscsiBootTargetIqn;
                    IscsiPrimaryBootTargetAddress = $IscsiPrimaryBootTargetAddress;
                }
    
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection @IscsiParams
                
                $ProfileConnection1 | Should -Not -BeNullOrEmpty
    
            }
    
            It "Will verify Connection 1 functionType is 'iSCSI'" {
    
                $ProfileConnection1.functionType | Should -Be 'iSCSI'
    
            }
    
            It "Will verify Connection 1 connection ID is '1'" {
                
                $ProfileConnection1.id | Should -Be 1
            
            }
    
            It "WIll verify Connection 1 boot priority is 'Primary'" {
    
                $ProfileConnection1.boot.priority | Should -Be Primary
    
            }
    
            It "Will verify Connection 1 bootVolumeSource is 'UserDefined'" {
    
                $ProfileConnection1.boot.bootVolumeSource | Should -Be UserDefined
            
            }
    
            It "Will verify Connection 1 ipAddressSource is 'UserDefined'" {
    
                $ProfileConnection1.ipv4.ipAddressSource | Should -Be UserDefined
            
            }
                
            It "Will verify Connection 1 ipAddress is '$Con1IscsiIPv4Address'" {
    
                $ProfileConnection1.ipv4.ipAddress | Should -Be $Con1IscsiIPv4Address
            
            }
    
            It "Will verify Connection 1 the subnetmask is '$Con1IscsiIPv4SubnetMask'" {
    
                $ProfileConnection1.ipv4.subnetMask | Should -Be $Con1IscsiIPv4SubnetMask
            
            }
    
            It "Will verify Connection 1 the bootTargetName is '$Con1IscsiBootTargetIqn'" {
    
                $ProfileConnection1.boot.iscsi.bootTargetName | Should -Be $Con1IscsiBootTargetIqn
            
            }
    
            It "Will verify Connection 1 the firstBootTargetIp is '$IscsiPrimaryBootTargetAddress'"{
    
                $ProfileConnection1.boot.iscsi.firstBootTargetIp | Should -Be $IscsiPrimaryBootTargetAddress
            
            }
    
            It "Will verify Connection 1 the initiatorNameSource is 'ProfileInitiatorName'" {
    
                $ProfileConnection1.boot.iscsi.initiatorNameSource | Should -Be ProfileInitiatorName
            
            }
    
            It "Will verify Connection 1 the connection network URI matches the exact VLAN-1A URI" {
    
                $ProfileConnection1.networkUri | Should -BeExactly $Vlan1A.uri
    
            }
    
            It "Will create secondary bootable iSCSI Connection" {
    
                $IscsiParams = @{
                    ConnectionID                    = 2;
                    Name                            = 'iSCSI Connection 2';
                    Type                            = 'iSCSI';
                    Network                         = $Vlan1B;
                    Bootable                        = $true;
                    Priority                        = 'IscsiSecondary';
                    BootVolumeSource                = 'UserDefined';
                    IscsiIPv4AddressSource          = 'UserDefined';
                    IscsiIPv4Address                = $Con2IscsiIPv4Address;
                    IscsiIPv4SubnetMask             = $Con2IscsiIPv4SubnetMask;
                    IscsiBootTargetIqn              = $Con2IscsiBootTargetIqn;
                    IscsiPrimaryBootTargetAddress   = $IscsiPrimaryBootTargetAddress;
                    IscsiSecondaryBootTargetAddress = $IscsiSecondaryBootTargetAddress;
                    IscsiAuthenticationProtocol     = $IscsiAuthenticationProtocol;
                    ChapName                        = $ChapName;
                    ChapSecret                      = $ChapSecret;
                    MutualChapName                  = $MutualChapName;
                    MutualChapSecret                = $MutualChapSecret
                }
    
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection @IscsiParams
    
                $ProfileConnection2 | Should -Not -BeNullOrEmpty
    
            }
            
            It "Will verify Connection 2 functionType is 'iSCSI'" {
    
                $ProfileConnection2.functionType | Should -Be 'iSCSI'
    
            }
    
            It "Will verify Connection 2 connection ID is '2'" {
                
                $ProfileConnection2.id | Should -Be 2
            
            }
    
            It "WIll verify Connection 2 boot priority is 'Secondary'" {
    
                $ProfileConnection2.boot.priority | Should -Be Secondary
    
            }
    
            It "Will verify Connection 2 bootVolumeSource is 'UserDefined'" {
    
                $ProfileConnection2.boot.bootVolumeSource | Should -Be UserDefined
            
            }
    
            It "Will verify Connection 2 ipAddressSource is 'UserDefined'" {
    
                $ProfileConnection2.ipv4.ipAddressSource | Should -Be UserDefined
            
            }
                
            It "Will verify Connection 2 ipAddress is '$Con2IscsiIPv4Address'" {
    
                $ProfileConnection2.ipv4.ipAddress | Should -Be $Con2IscsiIPv4Address
            
            }
    
            It "Will verify Connection 2 the subnetmask is '$Con1IscsiIPv4SubnetMask'" {
    
                $ProfileConnection2.ipv4.subnetMask | Should -Be $Con1IscsiIPv4SubnetMask
            
            }
    
            It "Will verify Connection 2 the bootTargetName is '$Con2IscsiBootTargetIqn'" {
    
                $ProfileConnection2.boot.iscsi.bootTargetName | Should -Be $Con2IscsiBootTargetIqn
            
            }
    
            It "Will verify Connection 2 the firstBootTargetIp is '$IscsiPrimaryBootTargetAddress'"{
    
                $ProfileConnection2.boot.iscsi.firstBootTargetIp | Should -Be $IscsiPrimaryBootTargetAddress
            
            }
    
            It "Will verify Connection 2 secondBootTargetIp Should -Be " {
    
                $ProfileConnection2.boot.iscsi.secondBootTargetIp | Should -Be $IscsiSecondaryBootTargetAddress
            
            }
    
            It "Will verify Connection 2 bootTargetName is '$Con2IscsiBootTargetIqn'" {
    
                $ProfileConnection2.boot.iscsi.bootTargetName | Should -Be $Con2IscsiBootTargetIqn
                
            }
    
            It "Will verify Connection 2 chapLevel is '$IscsiAuthenticationProtocol'" {
    
                $ProfileConnection2.boot.iscsi.chapLevel | Should -Be $IscsiAuthenticationProtocol
                
            }
    
            It "Will verify Connection 2 chapName is '$ChapName'" {
                
                $ProfileConnection2.boot.iscsi.chapName | Should -Be $ChapName
                
            }
    
            It "Will verify Connection 2 chapSecret is '$ChapSecret'" {
                
                $ProfileConnection2.boot.iscsi.chapSecret | Should -Be $DecryptedChapSecret
                
            }
    
            It "Will verify Connection 2 mututalChapName is '$MutualChapName'" {
                
                $ProfileConnection2.boot.iscsi.mutualChapName | Should -Be $MutualChapName
                
            }
    
            It "Will verify Connection 2 mutualChapSecret is '$MutualChapSecret'" {
                
                $ProfileConnection2.boot.iscsi.mutualChapSecret | Should -Be $DecryptedMutualChapSecret
                
            }
    
            It "Will verify Connection 2 the initiatorNameSource is 'ProfileInitiatorName'" {
    
                $ProfileConnection2.boot.iscsi.initiatorNameSource | Should -Be ProfileInitiatorName
            
            }
    
            It "Will verify Connection 2 the connection network URI matches the exact VLAN-1B URI" {
    
                $ProfileConnection2.networkUri | Should -BeExactly $Vlan1B.uri
    
            }
    
            It "Will create iSCSI basic Server Profile '$BasicIscsiServerProfileName' with 2 iSCSI Connections" {
    
                $ParamHash = @{
                    Name               = $BasicIscsiServerProfileName;
                    AssignmentType     = 'Unassigned';
                    ServerHardwareType = $BL460cGen9SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ProfileConnection1, $ProfileConnection2;
                    ManageBoot         = $true
                }
    
                { $Script:CreateBasiciSCSIServerProfileResults = New-HPOVServerProfile -Confirm:$False @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
    
                $CreateBasiciSCSIServerProfileResults.category | Should -Be tasks
    
                if ($CreateBasiciSCSIServerProfileResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateBasiciSCSIServerProfileResults
    
                }
    
                $CreateBasiciSCSIServerProfileResults.taskState | Should -Be Completed
    
            }
    
        }
    
        Context "Create Server Profile with Software iSCSI connections and StoreVirtual Volume attachments" {
    
            BeforeAll {
    
                $IscsiNetwork = Get-HPOVNetwork -Purpose ISCSI | Select-Object -first 1
                    
                $IscsiNetwork | Should -Not -BeNullOrEmpty
    
                if (-not(Get-HPOVStoragePool -Name $StoreVirtual1SystemPoolName -ErrorAction SilentlyContinue)) {
    
                    #Add StoreVirtual Storage System
                    $Results = Add-HPOVStorageSystem -Family StoreVirtual -Hostname $StoreVirtual1Address -Credential $StorageSystemPSCredential -VIPS @{ "$StoreVirtual1Address" = $IscsiNetwork }
    
                    if ($Results.taskState -ne "Completed") {
    
                        DisplayTaskError $Results
    
                    }
    
                    $Results.taskState | Should -Be Completed
    
                }
    
            }
    
            It "Will validate a StoreVirtual Storage Pool exists" {
    
                { $Script:StoragePool = Get-HPOVStoragePool -Name $StoreVirtual1SystemPoolName -ErrorAction Stop } | Should -Not -Throw
    
            }
    
            It "Will validate BL460c Gen9 1 Server Hardware Type exists" {
        
                { $Script:BL460cGen9SHT = Get-HPOVServerHardwareType -Name 'BL460c Gen9 1' } | Should -Not -Throw
                $BL460cGen9SHT | Should -Not -BeNullOrEmpty
                $BL460cGen9SHT.category | Should -Be 'server-hardware-types'
        
            }
    
            It "Will validate $DCSDefaultEGName exists" {
            
                { $Script:EnclosureGroup = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop } | Should -Not -Throw
                $EnclosureGroup | Should -Not -BeNullOrEmpty
                $EnclosureGroup.category | Should -Be 'enclosure-groups'
            
            }
    
            It "Will create Ethernet '$ServerProfileConnection1NetName' Connection 1 (FlexNIC1:a)" {
    
                $ServerProfileConnection1NetObject = Get-HPOVNetwork -Name $ServerProfileConnection1NetName -ErrorAction Stop
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection -ConnectionID 1 -Name "$ServerProfileConnection1NetName Connection" -Network $ServerProfileConnection1NetObject
                $ProfileConnection1 | Should -Not -BeNullOrEmpty
                $ProfileConnection1.functionType | Should -Be $ServerProfileConnection1Type
                $ProfileConnection1.id | Should -Be 1
                $ProfileConnection1.boot | Should -Be $null
                $ProfileConnection1.networkUri | Should -BeExactly $ServerProfileConnection1NetObject.uri
    
            }
    
            It "Will create Ethernet '$ServerProfileConnection2NetName' Connection 2 (FlexNIC2:a)" {
    
                $ServerProfileConnection2NetObject = Get-HPOVNetwork -Name $ServerProfileConnection2NetName -ErrorAction Stop
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection -ConnectionID 2 -Name "$ServerProfileConnection2NetName Connection" -Network $ServerProfileConnection2NetObject
                $ProfileConnection2 | Should -Not -BeNullOrEmpty
                $ProfileConnection2.functionType | Should -Be $ServerProfileConnection2Type
                $ProfileConnection2.id | Should -Be 2
                $ProfileConnection2.boot | Should -Be $null
                $ProfileConnection2.networkUri | Should -BeExactly $ServerProfileConnection2NetObject.uri
    
            }
    
            It "Will create Software iSCSI '$($IscsiNetwork.name)' Connection 3 (FlexNIC1:c)" {
    
                { $Script:ProfileConnection3 = New-HPOVServerProfileConnection -ConnectionID 3 -Name "$($IscsiNetwork.name) Connection 3" -Network $IscsiNetwork } | Should -Not -Throw
                $ProfileConnection3 | Should -Not -BeNullOrEmpty
                $ProfileConnection3.functionType | Should -Be $ServerProfileConnection1Type
                $ProfileConnection3.id | Should -Be 3
                $ProfileConnection3.boot | Should -Be $null
                $ProfileConnection3.networkUri | Should -BeExactly $IscsiNetwork.uri
    
            }
    
            It "Will create Software iSCSI '$($IscsiNetwork.name)' Connection 4 (FlexNIC2:c)" {
    
                { $Script:ProfileConnection4 = New-HPOVServerProfileConnection -ConnectionID 4 -Name "$($IscsiNetwork.name) Connection 4" -Network $IscsiNetwork } | Should -Not -Throw
                $ProfileConnection4 | Should -Not -BeNullOrEmpty
                $ProfileConnection4.functionType | Should -Be $ServerProfileConnection2Type
                $ProfileConnection4.id | Should -Be 4
                $ProfileConnection4.boot | Should -Be $null
                $ProfileConnection4.networkUri | Should -BeExactly $IscsiNetwork.uri
    
            }
            
            It "Will create Logical Disk policy for embedded SA Controller" {
            
                { $Script:ServerProfileLogicalDiskObject = New-HPOVServerProfileLogicalDisk -Name 'OS Disk' -RAID RAID1 -NumberofDrives 2 -DriveType Auto -Bootable $true } | Should -Not -Throw
                $ServerProfileLogicalDiskObject | Should -Not -BeNullOrEmpty
                $ServerProfileLogicalDiskObject.name | Should -Be 'OS Disk'
                $ServerProfileLogicalDiskObject.bootable | Should -Be $true
            
            }
    
            It "Will create local storage controller policy" {
            
                { $Script:ServerProfileController = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $ServerProfileLogicalDiskObject } | Should -Not -Throw
                $ServerProfileController | Should -Not -BeNullOrEmpty
                $ServerProfileController.deviceSlot | Should -Be 'Embedded'
                $ServerProfileController.initialize | Should -Be $true
                $ServerProfileController.logicalDrives.Count | Should -Be 1
            
            }
    
            It "Will create ephemeral private Bootable volume object '$BfSAdvancedServerProfileName Private Vol 1'" {
            
                { $Script:StorageVolumeObject = New-HPOVServerProfileAttachVolume -Name "$BfSAdvancedServerProfileName Private Vol 1" -StoragePool $StoragePool -Capacity 60 -LunIdType Auto -DataProtectionLevel networkraid5singleparity } | Should -Not -Throw
                $StorageVolumeObject | Should -Not -BeNullOrEmpty
                $StorageVolumeObject.volume.properties.storagePool | Should -Be $StoragePool.uri
                $StorageVolumeObject.isBootVolume | Should -Be $false
            
            }
    
            It "Will create Server Profile resource $SANAttachIscsiServerProfileName" {
    
                $ParamHash = @{
                    
                    Name               = $SANAttachIscsiServerProfileName
                    AssignmentType     = 'Unassigned';
                    ServerHardwareType = $BL460cGen9SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ProfileConnection1,$ProfileConnection2,$ProfileConnection3,$ProfileConnection4;
                    LocalStorage       = $true;
                    StorageController  = $ServerProfileController;
                    SanStorage         = $true;
                    HostOStype         = 'Win2k12';
                    StorageVolume      = $StorageVolumeObject;
                    Bios               = $true;
                    BiosSettings       = $Gen9BiosSettings;
                    ManageBoot         = $true;
                    BootMode           = "UEFI";
                    
                }
            
                { $Script:CreateSANAttachIscsiServerProfileResults = New-HPOVServerProfile -Confirm:$False @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
                $CreateSANAttachIscsiServerProfileResults | Should -Not -BeNullOrEmpty
    
                $CreateSANAttachIscsiServerProfileResults.category | Should -Be 'tasks'
    
                if ($CreateSANAttachIscsiServerProfileResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateSANAttachIscsiServerProfileResults
    
                }
    
                $CreateSANAttachIscsiServerProfileResults.taskState | Should -Be Completed
            
            }
        
        }    
    
        Context "Create and assign Complex Server Profile (ETH, FC, LD) resource for BL460c Gen9" {
        
            It "Will validate BL460c Gen9 1 Server Hardware Type exists" {
        
                { $Script:BL460cGen9SHT = Get-HPOVServerHardwareType -Name 'BL460c Gen9 1' } | Should -Not -Throw
                $BL460cGen9SHT | Should -Not -BeNullOrEmpty
                $BL460cGen9SHT.category | Should -Be 'server-hardware-types'
        
            }
    
            It "Will validate $DCSDefaultEGName exists" {
            
                { $Script:EnclosureGroup = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop } | Should -Not -Throw
                $EnclosureGroup | Should -Not -BeNullOrEmpty
                $EnclosureGroup.category | Should -Be 'enclosure-groups'
            
            }
    
            It "Will create Ethernet '$ServerProfileConnection1NetName' Connection 1 (FlexNIC1:a) - Bootable" {
    
                $ServerProfileConnection1NetObject = Get-HPOVNetwork -Name $ServerProfileConnection1NetName -ErrorAction Stop
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection -ConnectionID 1 -Name "$ServerProfileConnection1NetName Connection" -Network $ServerProfileConnection1NetObject -Bootable -Priority Primary
                $ProfileConnection1 | Should -Not -BeNullOrEmpty
                $ProfileConnection1.functionType | Should -Be $ServerProfileConnection1Type
                $ProfileConnection1.id | Should -Be 1
                $ProfileConnection1.boot.priority | Should -Be Primary
                $ProfileConnection1.networkUri | Should -BeExactly $ServerProfileConnection1NetObject.uri
    
            }
    
            It "Will create Ethernet '$ServerProfileConnection2NetName' Connection 2 (FlexNIC2:a)" {
    
                $ServerProfileConnection2NetObject = Get-HPOVNetwork -Name $ServerProfileConnection2NetName -ErrorAction Stop
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection -ConnectionID 2 -Name "$ServerProfileConnection2NetName Connection" -Network $ServerProfileConnection2NetObject
                $ProfileConnection2 | Should -Not -BeNullOrEmpty
                $ProfileConnection2.functionType | Should -Be $ServerProfileConnection2Type
                $ProfileConnection2.id | Should -Be 2
                $ProfileConnection2.boot | Should -Be $null
                $ProfileConnection2.networkUri | Should -BeExactly $ServerProfileConnection2NetObject.uri
    
            }
    
            It "Will create Fibre Channel '$ServerProfileConnection3NetName' Connection 3 (FlexNIC1:b)" {
    
                $ServerProfileConnection3NetObject = Get-HPOVNetwork -Name $ServerProfileConnection3NetName -Type $ServerProfileConnection3Type -ErrorAction Stop
                $Script:ProfileConnection3 = New-HPOVServerProfileConnection -ConnectionID 3 -Name "$ServerProfileConnection3NetName Connection" -Network $ServerProfileConnection3NetObject
                $ProfileConnection3 | Should -Not -BeNullOrEmpty
                $ProfileConnection3.functionType | Should -Be $ServerProfileConnection3Type
                $ProfileConnection3.id | Should -Be 3
                $ProfileConnection3.networkUri | Should -BeExactly $ServerProfileConnection3NetObject.uri
    
            }
    
            It "Will create Fibre Channel '$ServerProfileConnection4NetName' Connection 4 (FlexNIC2:b)" {
    
                $ServerProfileConnection4NetObject = Get-HPOVNetwork -Name $ServerProfileConnection4NetName -Type $ServerProfileConnection4Type -ErrorAction Stop
                $Script:ProfileConnection4 = New-HPOVServerProfileConnection -ConnectionID 4 -Name "$ServerProfileConnection4NetName Connection" -Network $ServerProfileConnection4NetObject
                $ProfileConnection4 | Should -Not -BeNullOrEmpty
                $ProfileConnection4.functionType | Should -Be $ServerProfileConnection4Type
                $ProfileConnection4.id | Should -Be 4
                $ProfileConnection4.networkUri | Should -BeExactly $ServerProfileConnection4NetObject.uri
    
            }
    
            It "Will create Ethernet '$ServerProfileConnection5NetName' Connection 5 (FlexNIC1:c)" {
    
                $ServerProfileConnection5NetObject = Get-HPOVNetworkSet -Name $ServerProfileConnection5NetName -ErrorAction Stop
                $Script:ProfileConnection5 = New-HPOVServerProfileConnection -ConnectionID 5 -Name "$ServerProfileConnection5NetName Connection" -Network $ServerProfileConnection5NetObject
                $ProfileConnection5 | Should -Not -BeNullOrEmpty
                $ProfileConnection5.functionType | Should -Be $ServerProfileConnection5Type
                $ProfileConnection5.id | Should -Be 5
                $ProfileConnection5.networkUri | Should -BeExactly $ServerProfileConnection5NetObject.uri
    
            }
    
            It "Will create Ethernet '$ServerProfileConnection6NetName' Connection 6 (FlexNIC2:c)" {
    
                $ServerProfileConnection6NetObject = Get-HPOVNetworkSet -Name $ServerProfileConnection6NetName -ErrorAction Stop
                $Script:ProfileConnection6 = New-HPOVServerProfileConnection -ConnectionID 6 -Name "$ServerProfileConnection6NetName Connection" -Network $ServerProfileConnection6NetObject
                $ProfileConnection6 | Should -Not -BeNullOrEmpty
                $ProfileConnection6.functionType | Should -Be $ServerProfileConnection6Type
                $ProfileConnection6.id | Should -Be 6
                $ProfileConnection6.networkUri | Should -BeExactly $ServerProfileConnection6NetObject.uri
    
            }
    
            It "Will create Ethernet '$ServerProfileConnection7NetName' Connection 7 (FlexNIC1:d)" {
    
                $ServerProfileConnection7NetObject = Get-HPOVNetwork -Name $ServerProfileConnection7NetName -type $ServerProfileConnection7Type -ErrorAction Stop
                $Script:ProfileConnection7 = New-HPOVServerProfileConnection -ConnectionID 7 -Name "$ServerProfileConnection7NetName Connection" -Network $ServerProfileConnection7NetObject
                $ProfileConnection7 | Should -Not -BeNullOrEmpty
                $ProfileConnection7.functionType | Should -Be $ServerProfileConnection7Type
                $ProfileConnection7.id | Should -Be 7
                $ProfileConnection7.networkUri | Should -BeExactly $ServerProfileConnection7NetObject.uri
    
            }
    
            It "Will create Ethernet '$ServerProfileConnection8NetName' Connection 8 (FlexNIC2:d)" {
    
                $ServerProfileConnection8NetObject = Get-HPOVNetwork -Name $ServerProfileConnection8NetName -type $ServerProfileConnection8Type -ErrorAction Stop
                $Script:ProfileConnection8 = New-HPOVServerProfileConnection -ConnectionID 8 -Name "$ServerProfileConnection8NetName Connection #2" -Network $ServerProfileConnection8NetObject
                $ProfileConnection8 | Should -Not -BeNullOrEmpty
                $ProfileConnection8.functionType | Should -Be $ServerProfileConnection8Type
                $ProfileConnection8.id | Should -Be 8
                $ProfileConnection8.networkUri | Should -BeExactly $ServerProfileConnection8NetObject.uri
    
            }
    
            It "Will attempt to create invalid Logical Disk policy for embedded RAID 1 configuration" {
            
                $ExpectedExceptionMessage = "The specified RAID Mode 'RAID1' is invalid with more or less than 2 drives."
                
                { New-HPOVServerProfileLogicalDisk -Name FooDisk -RAID RAID1 -NumberofDrives 8 } | Should -Throw $ExpectedExceptionMessage
            
            }
    
            It "Will create Logical Disk policy for embedded SA Controller" {
            
                { $Script:ServerProfileLogicalDiskObject = New-HPOVServerProfileLogicalDisk -Name 'OS Disk' -RAID RAID1 -NumberofDrives 2 -DriveType Auto } | Should -Not -Throw
                $ServerProfileLogicalDiskObject | Should -Not -BeNullOrEmpty
                $ServerProfileLogicalDiskObject.name | Should -Be 'OS Disk'
            
            }
    
            It "Will create local storage controller policy" {
            
                { $Script:ServerProfileController = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $ServerProfileLogicalDiskObject } | Should -Not -Throw
                $ServerProfileController | Should -Not -BeNullOrEmpty
                $ServerProfileController.deviceSlot | Should -Be 'Embedded'
                $ServerProfileController.initialize | Should -Be $true
                $ServerProfileController.logicalDrives.Count | Should -Be 1
            
            }
    
            It "Will get first available BL460c Gen9 server hardware device" {
                
                { $Script:ServerResource = Get-HPOVServerHardwareType -Name $BL460cGen9SHT.name -ErrorAction Stop | Get-HPOVServer -NoProfile -ErrorAction Stop | Select-Object -First 1 } | Should -Not -Throw
                $ServerResource | Should -Not -BeNullOrEmpty
                $ServerResource.category | Should -Be server-hardware
        
            }
    
            It "Will create and assign complex Server Profile resource $AdvancedServerProfileName to $($ServerResource.name)" {
    
                $ParamHash = @{
                    
                    Name               = $AdvancedServerProfileName
                    AssignmentType     = 'Server';
                    Server             = $ServerResource;
                    Connections        = $ProfileConnection1,$ProfileConnection2,$ProfileConnection3,$ProfileConnection4,$ProfileConnection5,$ProfileConnection6,$ProfileConnection7,$ProfileConnection8;
                    LocalStorage       = $true;
                    StorageController  = $ServerProfileController;
                    Bios               = $true;
                    BiosSettings       = $Gen9BiosSettings;
                    ManageBoot         = $true;
                    BootMode           = "UEFI";
                    
                }
            
                { $Script:CreateAdvancedServerProfileResults = New-HPOVServerProfile -Confirm:$False @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
                $CreateAdvancedServerProfileResults | Should -Not -BeNullOrEmpty
    
                $CreateAdvancedServerProfileResults.category | Should -Be 'tasks'
    
                if ('Warning','Completed' -notcontains $CreateAdvancedServerProfileResults.taskState) {
                    
                    DisplayTaskError $CreateAdvancedServerProfileResults
    
                }
    
                'Warning','Completed' -contains $CreateAdvancedServerProfileResults.taskState | Should -Be $true
            
            }
            
            It "Will attempt reapply the server profile with server powered on" {
    
                $ExpectedExceptionMessage = 'The associated server resource {0} to the Server Profile {1} is powered on.  This operation only supports servers in a powered off state.  Please use Stop-HPOVServer before continuing.' -f $ServerResource.name, $AdvancedServerProfileName
                { Get-HPOVServerProfile -Name $AdvancedServerProfileName -ErrorAction Stop | Start-HPOVServer } | Should -Not -Throw
    
                { Get-HPOVServerProfile -Name $AdvancedServerProfileName -ErrorAction Stop | Update-HPOVServerProfile -Reapply -AdapterAndBoot -Bios -Confirm:$False } | Should -Throw $ExpectedExceptionMessage
    
            }
            
            It "Will reapply the server profile" {
    
                { Get-HPOVServerProfile -Name $AdvancedServerProfileName -ErrorAction Stop | Stop-HPOVServer -Force -Confirm:$false } | Should -Not -Throw
    
                { Get-HPOVServer -Name $ServerResource.name -ErrorAction Stop | Update-HPOVServerProfile -Reapply -AdapterAndBoot -Bios -Confirm:$false } | Should -Not -Throw
    
            }
        
        }

        Context "Create 'Unassigned' Complex (ETH, FC, LD) BfS Server Profile resource for BL460c Gen9" {
    
            It "Will validate BL460c Gen9 1 Server Hardware Type exists" {
        
                { $Script:BL460cGen9SHT = Get-HPOVServerHardwareType -Name 'BL460c Gen9 1' } | Should -Not -Throw
        
            }

            It 'Will validate returned Server Hardware Type object' {

                $BL460cGen9SHT | Should -Not -BeNullOrEmpty
                $BL460cGen9SHT.category | Should -Be 'server-hardware-types'

            }
    
            It "Will validate $DCSDefaultEGName exists" {
            
                $Script:EnclosureGroup = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName
            
            }

            It "Will validate returned Enclosure Group object" {

                $EnclosureGroup | Should -Not -BeNullOrEmpty
                $EnclosureGroup.category | Should -Be 'enclosure-groups'

            }
    
            It "Will create Ethernet '$ServerProfileConnection1NetName' Connection 1 (FlexNIC1:a)" {
    
                $Script:ServerProfileConnection1NetObject = Get-HPOVNetwork -Name $ServerProfileConnection1NetName -ErrorAction Stop
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection -ConnectionID 1 -Name "$ServerProfileConnection1NetName Connection" -Network $ServerProfileConnection1NetObject
                $ProfileConnection1 | Should -Not -BeNullOrEmpty
                        
            }

            It "Will validate created Connection 1 properties (ID and NetworkUri)" {

                $ProfileConnection1.functionType | Should -Be $ServerProfileConnection1Type
                $ProfileConnection1.id | Should -Be 1
                $ProfileConnection1.networkUri | Should -BeExactly $ServerProfileConnection1NetObject.uri

            }
    
            It "Will create Ethernet '$ServerProfileConnection2NetName' Connection 2 (FlexNIC2:a)" {
    
                $Script:ServerProfileConnection2NetObject = Get-HPOVNetwork -Name $ServerProfileConnection2NetName -ErrorAction Stop
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection -ConnectionID 2 -Name "$ServerProfileConnection2NetName Connection" -Network $ServerProfileConnection2NetObject
                $ProfileConnection2 | Should -Not -BeNullOrEmpty
                        
            }
            
            It "Will validate created Connection 2 properties (ID and NetworkUri)" {

                $ProfileConnection2.functionType | Should -Be $ServerProfileConnection2Type
                $ProfileConnection2.id | Should -Be 2
                $ProfileConnection2.networkUri | Should -BeExactly $ServerProfileConnection2NetObject.uri

            }
    
            It "Will create Fibre Channel '$ServerProfileConnection3NetName' Connection 3 (Bootable:Primary) (FlexNIC1:b)" {
    
                $Script:ServerProfileConnection3NetObject = Get-HPOVNetwork -Name $ServerProfileConnection3NetName -Type $ServerProfileConnection3Type -ErrorAction Stop
                $Script:ProfileConnection3 = New-HPOVServerProfileConnection -ConnectionID 3 -ConnectionType FC -Name "$ServerProfileConnection3NetName Connection" -Network $ServerProfileConnection3NetObject -Bootable -Priority Primary -BootVolumeSource ManagedVolume 
                $ProfileConnection3 | Should -Not -BeNullOrEmpty
                        
            }
                            
            It "Will validate created Connection 3 properties (FunctionType, ID, NetworkUri, boot volume source and priority)" {

                $ProfileConnection3.functionType | Should -Be $ServerProfileConnection3Type
                $ProfileConnection3.id | Should -Be 3
                $ProfileConnection3.networkUri | Should -BeExactly $ServerProfileConnection3NetObject.uri
                $ProfileConnection3.boot.bootVolumeSource | Should -BeExactly 'ManagedVolume'
                $ProfileConnection3.boot.priority | Should -BeExactly 'Primary'

            }
    
            It "Will create Fibre Channel '$ServerProfileConnection4NetName' Connection 4 (Bootable:Secondary) (FlexNIC2:b)" {
    
                $Script:ServerProfileConnection4NetObject = Get-HPOVNetwork -Name $ServerProfileConnection4NetName -Type $ServerProfileConnection4Type -ErrorAction Stop
                $Script:ProfileConnection4 = New-HPOVServerProfileConnection -ConnectionID 4 -Name "$ServerProfileConnection4NetName Connection" -Network $ServerProfileConnection4NetObject -Bootable -Priority Secondary -BootVolumeSource ManagedVolume
                $ProfileConnection4 | Should -Not -BeNullOrEmpty
                
            }
                                            
            It "Will validate created Connection 4 properties (FunctionType, ID, NetworkUri, boot volume source and priority)" {

                $ProfileConnection4.functionType | Should -Be $ServerProfileConnection4Type
                $ProfileConnection4.id | Should -Be 4
                $ProfileConnection4.networkUri | Should -BeExactly $ServerProfileConnection4NetObject.uri
                $ProfileConnection4.boot.bootVolumeSource | Should -BeExactly 'ManagedVolume'
                $ProfileConnection4.boot.priority | Should -BeExactly 'Secondary'

            }
    
            It "Will create ephemeral private Bootable volume object '$BfSAdvancedServerProfileName Private Vol 1'" {
            
                $Script:FSTCPG1 = Get-HPOVStoragePool -Name FST_CPG1
                { $Script:EphemeralStorageVolumeObject = New-HPOVServerProfileAttachVolume -Name "$BfSAdvancedServerProfileName Private Vol 1" -StoragePool $FSTCPG1 -Capacity 60 -LunIdType Auto -BootVolume } | Should -Not -Throw
                $EphemeralStorageVolumeObject | Should -Not -BeNullOrEmpty
                                
            }

            It 'Will validate ephemeral object properties' {

                $EphemeralStorageVolumeObject.volume.properties.storagePool | Should -Be $FSTCPG1.uri
                $EphemeralStorageVolumeObject.isBootVolume | Should -Be $true

            }
    
            It "Will create Logical Disk policy for embedded SA Controller" {
            
                { $Script:ServerProfileLogicalDiskObject = New-HPOVServerProfileLogicalDisk -Name 'Scratch Disk' -RAID RAID1 -NumberofDrives 2 -DriveType Auto } | Should -Not -Throw
                $ServerProfileLogicalDiskObject | Should -Not -BeNullOrEmpty
            
            }

            It "Will validate logical disk properties" {

                $ServerProfileLogicalDiskObject.name | Should -Be 'Scratch Disk'
                $ServerProfileLogicalDiskObject.bootable | Should -Be $False
                $ServerProfileLogicalDiskObject.raidLevel | Should -Be 'RAID1'
                $ServerProfileLogicalDiskObject.numPhysicalDrives | Should -Be '2'
                $ServerProfileLogicalDiskObject.driveTechnology | Should -BeNullOrEmpty

            }

            It "Will create embedded controller object for internal logical disk" {

                { $Script:ServerProfileController = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $ServerProfileLogicalDiskObject } | Should -Not -Throw
                $ServerProfileController | Should -Not -BeNullOrEmpty

            }

            It "Will validate embedded logical disk controller properties" {

                $ServerProfileController.deviceSlot | Should -Be 'Embedded'
                $ServerProfileController.importConfiguration | Should -Be $false
                $ServerProfileController.initialize | Should -Be $true
                $ServerProfileController.logicalDrives.Count | Should -Be 1
                $ServerProfileController.logicalDrives[0].name | Should -Be $ServerProfileLogicalDiskObject.name

            }
    
            It "Will create BfS Server Profile resource '$BfSAdvancedServerProfileName'" {
    
                $ServerProfileConnections = $ProfileConnection1,$ProfileConnection2,$ProfileConnection3,$ProfileConnection4
    
                $ParamHash = @{
                    
                    Name               = $BfSAdvancedServerProfileName
                    AssignmentType     = 'Unassigned';
                    ServerHardwareType = $BL460cGen9SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ServerProfileConnections;
                    LocalStorage       = $true;
                    StorageController  = $ServerProfileController;
                    SanStorage         = $true;
                    HostOStype         = 'Win2k12';
                    StorageVolume      = $EphemeralStorageVolumeObject;
                    Bios               = $true;
                    BiosSettings       = $Gen9BiosSettings;
                    ManageBoot         = $true;
                    BootMode           = "UEFI";
                    
                }
            
                { $Script:CreateBfSAdvancedServerProfileResults = New-HPOVServerProfile -Confirm:$False @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
                $CreateBfSAdvancedServerProfileResults | Should -Not -BeNullOrEmpty
                $CreateBfSAdvancedServerProfileResults.category | Should -Be 'tasks'

                if ($CreateBfSAdvancedServerProfileResults.taskState -ne 'Completed') {
    
                    DisplayTaskError $CreateBfSAdvancedServerProfileResults
    
                }
    
                $CreateBfSAdvancedServerProfileResults.taskState | Should -Be Completed
            
            }
    
            It "Will create a new shared storage volume" {
    
                $FSTCPG1 = Get-HPOVStoragePool -Name FST_CPG1 -ErrorAction Stop
                { $Script:StorageVolumeTask = New-HPOVStorageVolume -Name "$BfSAdvancedServerProfileName Vol 2" -StoragePool $FSTCPG1 -Capacity 1 -Shared } | Should -Not -Throw
                $StorageVolumeTask | Should -Not -BeNullOrEmpty
                $StorageVolumeTask.category | Should -Be 'tasks'
    
                if ($StorageVolumeTask.taskState -ne "Completed") {
    
                    DisplayTaskError $StorageVolumeTask
    
                }
    
                $StorageVolumeTask.taskState | Should -Be Completed
    
            }
    
            It "Will attach new storage volume to existing '$BfSAdvancedServerProfileName'" {
    
                { $Script:ServerProfile = Get-HPOVServerProfile -name $BfSAdvancedServerProfileName -ErrorAction Stop } | Should -Not -Throw
    
                { $Script:Volume = Get-HPOVStorageVolume -Name "$BfSAdvancedServerProfileName Vol 2" } | Should -Not -Throw
                    
                { $Script:TaskResults = New-HPOVServerProfileAttachVolume -ServerProfile $ServerProfile -Volume $Volume | Wait-HPOVTaskComplete } | Should -Not -Throw
    
                $TaskResults | Should -Not -BeNullOrEmpty
                $TaskResults.category | Should -Be 'tasks'
    
                if ($TaskResults.taskState -ne "Completed") {
    
                    DisplayTaskError $TaskResults
    
                }
    
                $TaskResults.taskState | Should -Be Completed
    
    
            }
        
        }

        Context "Copy and assign Complex Server Profile resource" {
    
            It "Will validate Complex Server Profile $AdvancedServerProfileName exists" {
        
                { $Script:AdvServerProfileObject = Get-HPOVServerProfile -Name $AdvancedServerProfileName -ErrorAction Stop } | Should -Not -Throw
                $AdvServerProfileObject | Should -Not -BeNullOrEmpty
                $AdvServerProfileObject.category | Should -Be 'server-profiles'
        
            }
    
            It "Will copy Complex Server Profile '$AdvancedServerProfileName' -> 'Copy of $AdvancedServerProfileName'" {
            
                { $Script:CopyServerProfileResults = Get-HPOVServerProfile -Name $AdvancedServerProfileName -ErrorAction Stop | Copy-HPOVServerProfile | Wait-HPOVTaskComplete } | Should -Not -Throw
                $CopyServerProfileResults | Should -Not -BeNullOrEmpty
                $CopyServerProfileResults.category | Should -Be 'tasks'
    
                if ('Completed','Warning' -notcontains $CopyServerProfileResults.taskState) {
    
                    DisplayTaskError $CopyServerProfileResults
    
                }
    
                'Completed','Warning' -contains $CopyServerProfileResults.taskState | Should -Be $true
            
            }
            
            It "Will validate 'Copy of $AdvancedServerProfileName' Server Profile exists" {
            
                { $Script:CopyOfServerProfileObject = Get-HPOVServerProfile -Name "Copy of $AdvancedServerProfileName" -ErrorAction Stop } | Should -Not -Throw
                $CopyOfServerProfileObject | Should -Not -BeNullOrEmpty
                $CopyOfServerProfileObject.category | Should -Be 'server-profiles'
                $CopyOfServerProfileObject.connectionSettings.connections.count | Should -Be 8
    
            }
    
            It "Will compare Manage BIOS and OverriddenSettings policy between '$AdvancedServerProfileName' and 'Copy of $AdvancedServerProfileName'" {
            
                (Compare-Object -ReferenceObject $AdvServerProfileObject.bios -DifferenceObject $CopyOfServerProfileObject.bios -IncludeEqual -Property manageBios,overriddenSettings).SideIndicator -eq '==' | Should -Be $true
            
            }
    
            It "Will compare Boot Mode and BIOS Mode policy between '$AdvancedServerProfileName' and 'Copy of $AdvancedServerProfileName'" {
            
                (Compare-Object -ReferenceObject $AdvServerProfileObject.bootMode -DifferenceObject $CopyOfServerProfileObject.bootMode -IncludeEqual -Property mode,manageMode).SideIndicator -eq '==' | Should -Be $true
            
            }
        
        }

    }

    Context "HPE BladeSystem - Server Profile Template operations" {

        Context "Create Server Profile Template from Server Profile" {
    
            It "Will clone '$($CopyOfServerProfileObject.name)' to Template" {
        
                { $Script:CopyOfAdvServerProfileObject = Get-HPOVServerProfile -Name $CopyOfServerProfileObject.name -ErrorAction Stop } | Should -Not -Throw
                { $Script:CloneToTemplateResults = ConvertTo-HPOVServerProfileTemplate -InputObject $CopyOfAdvServerProfileObject } | Should -Not -Throw
                $CloneToTemplateResults | Should -Not -BeNullOrEmpty
                $CloneToTemplateResults.category | Should -Be 'tasks'
    
                if ($CloneToTemplateResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CloneToTemplateResults
    
                }
    
                $CloneToTemplateResults.taskState | Should -Be Completed
        
            }
    
            It "Will validate cloned Server Profile Template 'Temporary Name - $($CopyOfServerProfileObject.name)' exists" {
            
                { $Script:ClonedServerProfileTemplateObject = Get-HPOVServerProfileTemplate -Name "Temporary Name - $($CopyOfServerProfileObject.name)" -ErrorAction Stop } | Should -Not -Throw
                $ClonedServerProfileTemplateObject | Should -Not -BeNullOrEmpty
                $ClonedServerProfileTemplateObject.category | Should -Be 'server-profile-templates'
            
            }
        
        }

        Context "Create basic Server Profile Template resource for BL460c Gen8" {

            # Get the necessary objects we need, which have alrady been verified and should have passed in the prior Server Profile create tests.
            BeforeAll {
    
                $Script:BL460cGen8SHT      = Get-HPOVServerHardwareType -Name 'BL460c Gen8 1' -ErrorAction Stop
                $Script:EnclosureGroup     = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop
                $Script:BaselineObject     = Get-HPOVBaseline -FileName $ExistingBaselineName -ErrorAction Stop
                $Vlan1A                    = Get-HPOVNetwork -Name "VLAN 1-A" -ErrorAction Stop
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection -ConnectionID 1 -Name 'VLAN 1-A Connection' -Network $Vlan1A -Bootable -Priority Primary
                $Vlan1B                    = Get-HPOVNetwork -Name "VLAN 1-B" -ErrorAction Stop
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection -ConnectionID 2 -Name 'VLAN 1-B Connection' -Network $Vlan1B -Bootable -Priority Secondary
                $LogicalDisk1              = New-HPOVServerProfileLogicalDisk -Name 'Disk 1' -RAID RAID1
                $Script:StorageController  = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $LogicalDisk1
    
            }
    
            It "Will attempt to crete basic Server Profile Template without -EnclosureGroup parameter" {
            
                { New-HPOVServerProfileTemplate -Name "$BasicServerProfileName Template" -ServerHardwareType $BL460cGen8SHT -Connections $ProfileConnection1,$ProfileConnection2 | Wait-HPOVTaskComplete } | Should -Throw
            
            }
        
            It "Will attempt to create basic Server Profile Template and not provide the -ManageBoot parameter" {
            
                $ExpectedExceptionMessage = 'Bootable Connections 1, 2 were found, however the -ManageBoot switch Parameter was not provided.  Please correct your command syntax and try again.'
                
                { New-HPOVServerProfileTemplate -Name "$BasicServerProfileName Template" -ServerHardwareType $BL460cGen8SHT -EnclosureGroup $EnclosureGroup -Connections $ProfileConnection1,$ProfileConnection2 } | Should -Throw $ExpectedExceptionMessage
            
            }
    
            It "Will attempt to create basic Server Profile Template with unsupport RAID6 type for LogicalDisk" {
            
                $UnsupportedLogicalDisk1 = New-HPOVServerProfileLogicalDisk -Name 'Invalid Disk 1' -RAID RAID6
                $UnsupportedStorageController = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $UnsupportedLogicalDisk1
                $ParamHash = @{
                                
                    Name               = "InvalidLogicalDiskTest Template 1"
                    ServerHardwareType = $BL460cGen8SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ProfileConnection1,$ProfileConnection2;
                    LocalStorage       = $true;
                    StorageController  = $UnsupportedStorageController;
                    ManageBoot         = $true;
                    Firmware           = $true;
                    Baseline           = $BaselineObject;
                    FirmwareMode       = 'FirmwareAndSoftware'
                
                }
                
                $ExpectedExceptionMessage = "Unsupported LogicalDisk RAID Level 'RAID6' policy with 'Invalid Disk 1' logical disk."
                
                { New-HPOVServerProfileTemplate @ParamHash } | Should -Throw $ExpectedExceptionMessage
            
            }
    
            It "Will attempt to create basic Server Profile with unsupport ImportExisting LogicalDisk policy." {
            
                $UnsupportedStorageController = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -ImportExisting
                $ParamHash = @{
                                
                    Name               = "InvalidLogicalDiskTest Template 2"
                    ServerHardwareType = $BL460cGen8SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ProfileConnection1,$ProfileConnection2;
                    LocalStorage       = $true;
                    StorageController  = $UnsupportedStorageController;
                    ManageBoot         = $true;
                    Firmware           = $true;
                    Baseline           = $BaselineObject;
                    FirmwareMode       = 'FirmwareAndSoftware'
                
                }
                
                $ExpectedExceptionMessage = 'The StorageController configuration contains the -ImportExistingConfiguration option set, which is not supported with Server Profile Templates.'
                
                { New-HPOVServerProfileTemplate @ParamHash } | Should -Throw $ExpectedExceptionMessage
            
            }
    
            It "Will create basic '$BasicServerProfileName Template' with 2 Ethernet Connections" {
    
                $ParamHash = @{
                    
                    Name               = "$BasicServerProfileName Template";
                    ServerHardwareType = $BL460cGen8SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ProfileConnection1,$ProfileConnection2;
                    LocalStorage       = $true;
                    StorageController  = $StorageController;
                    ManageBoot         = $true;
                    Firmware           = $true;
                    Baseline           = $BaselineObject;
                    FirmwareMode       = 'FirmwareAndSoftware'
                    
                }            
            
                { $Script:CreateBasicServerProfileTemplateResults = New-HPOVServerProfileTemplate @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
    
                if ($CreateBasicServerProfileTemplateResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateBasicServerProfileTemplateResults
    
                }
    
                $CreateBasicServerProfileTemplateResults.taskState | Should -Be Completed
            
            }
    
            It "Will validate '$BasicServerProfileName Template' exists" {
            
                { $Script:BasicServerProfileTemplateObject = Get-HPOVServerProfileTemplate -Name "$BasicServerProfileName Template" -ErrorAction Stop } | Should -Not -Throw
                $BasicServerProfileTemplateObject | Should -Not -BeNullOrEmpty
                $BasicServerProfileTemplateObject.category | Should -Be 'server-profile-templates'
                $BasicServerProfileTemplateObject.connectionSettings.connections.Count | Should -Be 2
                $BasicServerProfileTemplateObject.localStorage.controllers.Count | Should -Be 1
                $BasicServerProfileTemplateObject.localStorage.controllers[0].logicalDrives.Count | Should -Be 1
    
            }
        
        }
    
        Context "Create basic Server Profile Template with 2 Hardware iSCSI Connections for BL460c Gen9" {
    
            $Script:BL460cGen9SHT  = Get-HPOVServerHardwareType -Name 'BL460c Gen9 1' -ErrorAction Stop
            $Script:EnclosureGroup = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop
            $Script:Vlan1A         = Get-HPOVNetwork -Name "VLAN 1-A" -ErrorAction Stop
            $Script:Vlan1B         = Get-HPOVNetwork -Name "VLAN 1-B" -ErrorAction Stop
            $Script:DecryptedChapSecret       = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ChapSecret))
            $Script:DecryptedMutualChapSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($MutualChapSecret))
            
            It "Will create primary bootable iSCSI Connection" {
                
                $IscsiParams = @{
                    ConnectionID                  = 1;
                    Name                          = 'iSCSI Connection 1';
                    ConnectionType                = 'iSCSI';
                    Network                       = $Vlan1A;
                    Bootable                      = $true;
                    BootVolumeSource              = 'UserDefined';
                    Priority                      = 'IscsiPrimary';
                    IscsiIPv4AddressSource        = 'UserDefined';
                    IscsiIPv4SubnetMask           = $Con1IscsiIPv4SubnetMask;
                    IscsiPrimaryBootTargetAddress = $IscsiPrimaryBootTargetAddress;
                }
    
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection @IscsiParams
                
                $ProfileConnection1 | Should -Not -BeNullOrEmpty    
        
            }
    
            It "Will verify Connection 1 functionType is 'iSCSI'" {
    
                $ProfileConnection1.functionType | Should -Be 'iSCSI'
    
            }
    
            It "Will verify Connection 1 connection ID is '1'" {
                
                $ProfileConnection1.id | Should -Be 1
            
            }
    
            It "WIll verify Connection 1 boot priority is 'Primary'" {
    
                $ProfileConnection1.boot.priority | Should -Be Primary
    
            }
            
            It "Will verify Connection 1 bootVolumeSource is 'UserDefined'" {
    
                $ProfileConnection1.boot.bootVolumeSource | Should -Be UserDefined
            
            }
    
            It "Will verify Connection 1 ipAddressSource is 'UserDefined'" {
    
                $ProfileConnection1.ipv4.ipAddressSource | Should -Be UserDefined
            
            }
                
            It "Will verify Connection 1 ipAddress is null" {
    
                $ProfileConnection1.ipv4.ipAddress | Should -BeNullOrEmpty
            
            }
    
            It "Will verify Connection 1 the subnetmask is '$Con1IscsiIPv4SubnetMask'" {
    
                $ProfileConnection1.ipv4.subnetMask | Should -Be $Con1IscsiIPv4SubnetMask
            
            }
    
            It "Will verify Connection 1 the bootTargetName is null" {
    
                $ProfileConnection1.boot.iscsi.bootTargetName | Should -BeNullOrEmpty
            
            }
    
            It "Will verify Connection 1 the firstBootTargetIp is '$IscsiPrimaryBootTargetAddress'"{
    
                $ProfileConnection1.boot.iscsi.firstBootTargetIp | Should -Be $IscsiPrimaryBootTargetAddress
            
            }
    
            It "Will verify Connection 1 the network associated is correct"{
    
                $ProfileConnection1.networkUri | Should -Be $Vlan1A.uri
            
            }
            
            It "Will create secondary bootable iSCSI Connection" {
    
                $Vlan1B = Get-HPOVNetwork -Name "VLAN 1-B" -ErrorAction Stop
                
                $IscsiParams = @{
                    ConnectionID                    = 2;
                    Name                            = 'iSCSI Connection 2';
                    Type                            = 'iSCSI';
                    Network                         = $Vlan1B;
                    Bootable                        = $true;
                    Priority                        = 'IscsiSecondary';
                    BootVolumeSource                = 'UserDefined';
                    IscsiIPv4AddressSource          = 'DHCP';
                    IscsiPrimaryBootTargetAddress   = $IscsiPrimaryBootTargetAddress;
                    IscsiSecondaryBootTargetAddress = $IscsiSecondaryBootTargetAddress;
                    IscsiAuthenticationProtocol     = $IscsiAuthenticationProtocol
                }
    
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection @IscsiParams
                $ProfileConnection2 | Should -Not -BeNullOrEmpty
    
            }
            
            It "Will verify Connection 2 functionType is 'iSCSI'" {
    
                $ProfileConnection2.functionType | Should -Be 'iSCSI'
    
            }
    
            It "Will verify Connection 2 connection ID is '1'" {
                
                $ProfileConnection2.id | Should -Be 2
            
            }
    
            It "WIll verify Connection 2 boot priority is 'Secondary'" {
    
                $ProfileConnection2.boot.priority | Should -Be Secondary
    
            }
    
            It "Will verify Connection 2 bootVolumeSource is 'UserDefined'" {
    
                $ProfileConnection2.boot.bootVolumeSource | Should -Be UserDefined
            
            }
    
            It "Will verify Connection 2 ipAddressSource is 'DHCP'" {
    
                $ProfileConnection2.ipv4.ipAddressSource | Should -Be DHCP
            
            }
                
            It "Will verify Connection 2 ipAddress is null" {
    
                $ProfileConnection2.ipv4.ipAddress | Should -BeNullOrEmpty
            
            }
    
            It "Will verify Connection 2 the subnetmask is null" {
    
                $ProfileConnection2.ipv4.subnetMask | Should -BeNullOrEmpty
            
            }
    
            It "Will verify Connection 2 the bootTargetName is null" {
    
                $ProfileConnection2.boot.iscsi.bootTargetName | Should -BeNullOrEmpty
            
            }
    
            It "Will verify Connection 2 the firstBootTargetIp is '$IscsiPrimaryBootTargetAddress'"{
    
                $ProfileConnection2.boot.iscsi.firstBootTargetIp | Should -Be $IscsiPrimaryBootTargetAddress
            
            }
    
            It "Will verify Connection 2 secondBootTargetIp is '$IscsiSecondaryBootTargetAddress' " {
    
                $ProfileConnection2.boot.iscsi.secondBootTargetIp | Should -Be $IscsiSecondaryBootTargetAddress
            
            }
    
            It "Will verify Connection 2 bootTargetName is null" {
    
                $ProfileConnection2.boot.iscsi.bootTargetName | Should -BeNullOrEmpty
                
            }
    
            It "Will verify Connection 2 chapLevel is '$IscsiAuthenticationProtocol'" {
    
                $ProfileConnection2.boot.iscsi.chapLevel | Should -Be $IscsiAuthenticationProtocol
                
            }
    
            It "Will verify Connection 2 chapName is null" {
                
                $ProfileConnection2.boot.iscsi.chapName | Should -BeNullOrEmpty
                
            }
    
            It "Will verify Connection 2 chapSecret is null" {
                
                $ProfileConnection2.boot.iscsi.chapSecret | Should -BeNullOrEmpty
                
            }
    
            It "Will verify Connection 2 mututalChapName is null" {
                
                $ProfileConnection2.boot.iscsi.mutualChapName | Should -BeNullOrEmpty
                
            }
    
            It "Will verify Connection 2 mutualChapSecret is null" {
                
                $ProfileConnection2.boot.iscsi.mutualChapSecret | Should -BeNullOrEmpty
                
            }
    
            It "Will verify Connection 2 the initiatorNameSource is 'ProfileInitiatorName'" {
    
                $ProfileConnection2.boot.iscsi.initiatorNameSource | Should -Be ProfileInitiatorName
            
            }
    
            It "Will verify Connection 2 the connection network URI matches the exact VLAN-1B URI" {
    
                $ProfileConnection2.networkUri | Should -BeExactly $Vlan1B.uri
    
            }
    
            It "Will create iSCSI basic Server Profile Template '$IscsiServerProfileTemplateName' with 2 iSCSI Connections" {
    
                $ParamHash = @{
                    Name               = $IscsiServerProfileTemplateName;
                    ServerHardwareType = $BL460cGen9SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ProfileConnection1, $ProfileConnection2;
                    ManageBoot         = $true;
                    BootMode           = 'BIOS'
                }
    
                { $Script:CreateBasiciSCSISPTResults = New-HPOVServerProfileTemplate @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
    
                $CreateBasiciSCSISPTResults.category | Should -Be tasks
    
                if ($CreateBasiciSCSISPTResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateBasiciSCSISPTResults
    
                }
    
                $CreateBasiciSCSISPTResults.taskState | Should -Be Completed
    
            }
    
        }
    
        Context "Create Complex Server Profile Template resource for BL460c Gen9" {
        
            BeforeAll {
        
                $Script:BL460cGen9SHT                  = Get-HPOVServerHardwareType -Name 'BL460c Gen9 1' 
                $Script:EnclosureGroup                 = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName
                $ServerProfileConnection1NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection1NetName -ErrorAction Stop
                $Script:ProfileConnection1             = New-HPOVServerProfileConnection -ConnectionID 1 -Name "$ServerProfileConnection1NetName Connection" -Network $ServerProfileConnection1NetObject -Bootable -Priority Primary
                $ServerProfileConnection2NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection2NetName -ErrorAction Stop
                $Script:ProfileConnection2             = New-HPOVServerProfileConnection -ConnectionID 2 -Name "$ServerProfileConnection2NetName Connection" -Network $ServerProfileConnection2NetObject
                $ServerProfileConnection3NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection3NetName -Type $ServerProfileConnection3Type -ErrorAction Stop
                $Script:ProfileConnection3             = New-HPOVServerProfileConnection -ConnectionID 3 -Name "$ServerProfileConnection3NetName Connection" -Network $ServerProfileConnection3NetObject
                $ServerProfileConnection4NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection4NetName -Type $ServerProfileConnection4Type -ErrorAction Stop
                $Script:ProfileConnection4             = New-HPOVServerProfileConnection -ConnectionID 4 -Name "$ServerProfileConnection4NetName Connection" -Network $ServerProfileConnection4NetObject
                $ServerProfileConnection5NetObject     = Get-HPOVNetworkSet -Name $ServerProfileConnection5NetName -ErrorAction Stop
                $Script:ProfileConnection5             = New-HPOVServerProfileConnection -ConnectionID 5 -Name "$ServerProfileConnection5NetName Connection" -Network $ServerProfileConnection5NetObject
                $ServerProfileConnection6NetObject     = Get-HPOVNetworkSet -Name $ServerProfileConnection6NetName -ErrorAction Stop
                $Script:ProfileConnection6             = New-HPOVServerProfileConnection -ConnectionID 6 -Name "$ServerProfileConnection6NetName Connection" -Network $ServerProfileConnection6NetObject
                $ServerProfileConnection7NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection7NetName -type $ServerProfileConnection7Type -ErrorAction Stop
                $Script:ProfileConnection7             = New-HPOVServerProfileConnection -ConnectionID 7 -Name "$ServerProfileConnection7NetName Connection" -Network $ServerProfileConnection7NetObject
                $ServerProfileConnection8NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection8NetName -type $ServerProfileConnection8Type -ErrorAction Stop
                $Script:ProfileConnection8             = New-HPOVServerProfileConnection -ConnectionID 8 -Name "$ServerProfileConnection8NetName Connection #2" -Network $ServerProfileConnection8NetObject
                $Script:ServerProfileConnections       = $ProfileConnection1,$ProfileConnection2,$ProfileConnection3,$ProfileConnection4,$ProfileConnection5,$ProfileConnection6,$ProfileConnection7,$ProfileConnection8
                $Script:ServerProfileLogicalDiskObject = New-HPOVServerProfileLogicalDisk -Name 'OS Disk' -RAID RAID1 -NumberofDrives 2 -DriveType Auto
                $Script:ServerProfileController        = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $ServerProfileLogicalDiskObject
    
            }
    
            It "Will create complex Server Profile Template resource '$AdvancedServerProfileName Template 2'" {
    
                $ParamHash = @{
                    
                    Name               = "$AdvancedServerProfileName Template 2"
                    ServerHardwareType = $BL460cGen9SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ServerProfileConnections;
                    LocalStorage       = $true;
                    StorageController  = $ServerProfileController;
                    Bios               = $true;
                    BiosSettings       = $Gen9BiosSettings;
                    ManageBoot         = $true;
                    BootMode           = "UEFI";
                    
                }
            
                { $Script:CreateAdvancedServerProfileResults = New-HPOVServerProfileTemplate @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
                $CreateAdvancedServerProfileResults | Should -Not -BeNullOrEmpty
                $CreateAdvancedServerProfileResults.category | Should -Be 'tasks'
    
                if ($CreateAdvancedServerProfileResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateAdvancedServerProfileResults
    
                }
    
                $CreateAdvancedServerProfileResults.taskState | Should -Be Completed
            
            }
    
            It "Will validate Server Profile Template BIOS Settings were configured correctly" {
            
                { $Script:SPT = Get-HPOVServerProfileTemplate -Name "$AdvancedServerProfileName Template 2" -ErrorAction Stop } | Should -Not -Throw
                $SPT.bios.overriddenSettings.Count | Should -Be $Gen9BiosSettings.Count
    
                $SPT.bios.overriddenSettings | ForEach-Object {
    
                    $_.Value | Should -Be ($Gen9BiosSettings | Where-Object id -eq $_.id).value
    
                }
            
            }
        
        }

        Context "Create Server Profile Template and Server Profile with Scheduled Firmware Policies for BL460c Gen8" {

            BeforeAll {
    
                $Script:BL460cGen8SHT      = Get-HPOVServerHardwareType -Name 'BL460c Gen8 1' -ErrorAction Stop
                $Script:EnclosureGroup     = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop
                $Script:BaselineObject     = Get-HPOVBaseline -FileName $ExistingBaselineName -ErrorAction Stop
                $Vlan1A                    = Get-HPOVNetwork -Name "VLAN 1-A" -ErrorAction Stop
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection -ConnectionID 1 -Name 'VLAN 1-A Connection' -Network $Vlan1A -Bootable -Priority Primary
                $Vlan1B                    = Get-HPOVNetwork -Name "VLAN 1-B" -ErrorAction Stop
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection -ConnectionID 2 -Name 'VLAN 1-B Connection' -Network $Vlan1B -Bootable -Priority Secondary
                $LogicalDisk1              = New-HPOVServerProfileLogicalDisk -Name 'Disk 1' -RAID RAID1
                $Script:StorageController  = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $LogicalDisk1
    
            }
    
            It "Will create a Server Profile Template with Scheduled Firmware activation" {
    
                $ParamHash = @{
                    
                    Name                   = "$ServerProfileScheduledFirmwareName Template";
                    ServerHardwareType     = $BL460cGen8SHT;
                    EnclosureGroup         = $EnclosureGroup;
                    Connections            = $ProfileConnection1,$ProfileConnection2;
                    LocalStorage           = $true;
                    StorageController      = $StorageController;
                    ManageBoot             = $true;
                    Firmware               = $true;
                    Baseline               = $BaselineObject;
                    FirmwareMode           = 'FirmwareAndSoftware'
                    FirmwareActivationMode = 'Scheduled'
                    
                }            
            
                { $Script:CreateBasicServerProfileTemplateResults = New-HPOVServerProfileTemplate @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
    
                if ($CreateBasicServerProfileTemplateResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateBasicServerProfileTemplateResults
    
                }
    
                $CreateBasicServerProfileTemplateResults.taskState | Should -Be Completed
    
            }
    
            It "Will validate Server Profile Template firmware policy is to schedule firmware activation" {
    
                { $Script:ServerProfileTemplate = Get-HPOVServerProfileTemplate -Name "$ServerProfileScheduledFirmwareName Template" -ErrorAction Stop } | Should -Not -Throw
                $ServerProfileTemplate.firmware.manageFirmware | Should -Be $true
                $ServerProfileTemplate.firmware.firmwareInstallType | Should -Be FirmwareAndOSDrivers
                $ServerProfileTemplate.firmware.firmwareActivationType | Should -Be Scheduled
    
            }
            
            It "Will create Server Profile '$ServerProfileScheduledFirmwareName' from Template specifying Schedule" {
    
                $Script:ScheduledDateTime = ([DateTime]::Now).AddDays('1')
    
                { $Script:ServerProfileTemplate = Get-HPOVServerProfileTemplate -Name "$ServerProfileScheduledFirmwareName Template" -ErrorAction Stop } | Should -Not -Throw
                { $Script:Results = New-HPOVServerProfile -Confirm:$False -ServerProfileTemplate $ServerProfileTemplate -Name $ServerProfileScheduledFirmwareName -FirmwareActivateDateTime $ScheduledDateTime -AssignmentType Unassigned } | Should -Not -Throw            
                
                if ($Results.taskState -ne "Completed") {
    
                    DisplayTaskError $Results
    
                }
    
                $Results.taskState | Should -Be Completed
            
            }
    
            It "Will validate firmware activation is scheduled" {
    
                { $Script:ServerProfileObject = Get-HPOVServerProfile -Name $ServerProfileScheduledFirmwareName -ErrorAction Stop } | Should -Not -Throw
                
                $ServerProfileObject.firmware.manageFirmware | Should -Be $true
                $ServerProfileObject.firmware.firmwareInstallType | Should -Be FirmwareAndOSDrivers
                $ServerProfileObject.firmware.firmwareActivationType | Should -Be Scheduled
                ([DateTime]$ServerProfileObject.firmware.firmwareScheduleDateTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") | Should -Be $ScheduledDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    
            }
    
        }
    
        Context "Create Server Profile Template with Unmanaged Connections management for BL460c Gen8" {
    
                BeforeAll {
    
                $Script:BL460cGen8SHT      = Get-HPOVServerHardwareType -Name 'BL460c Gen8 1' -ErrorAction Stop
                $Script:EnclosureGroup     = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName -ErrorAction Stop
                $Script:BaselineObject     = Get-HPOVBaseline -FileName $ExistingBaselineName -ErrorAction Stop
                $Vlan1A                    = Get-HPOVNetwork -Name "VLAN 1-A" -ErrorAction Stop
                $Script:ProfileConnection1 = New-HPOVServerProfileConnection -ConnectionID 1 -Name 'VLAN 1-A Connection' -Network $Vlan1A -Bootable -Priority Primary
                $Vlan1B                    = Get-HPOVNetwork -Name "VLAN 1-B" -ErrorAction Stop
                $Script:ProfileConnection2 = New-HPOVServerProfileConnection -ConnectionID 2 -Name 'VLAN 1-B Connection' -Network $Vlan1B -Bootable -Priority Secondary
                $LogicalDisk1              = New-HPOVServerProfileLogicalDisk -Name 'Disk 1' -RAID RAID1
                $Script:StorageController  = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $LogicalDisk1
    
            }
    
            It "Will create a Server Profile Template with Unmanaged Connections" {
    
                $ParamHash = @{
                    
                    Name               = "$BasicServerProfileName UnmanagedConnections Template";
                    ServerHardwareType = $BL460cGen8SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    ManageConnections  = $false;
                    LocalStorage       = $true;
                    StorageController  = $StorageController;
                    ManageBoot         = $true
                    
                }            
            
                { $Script:CreateBasicServerProfileTemplateResults = New-HPOVServerProfileTemplate @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
    
                if ($CreateBasicServerProfileTemplateResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateBasicServerProfileTemplateResults
    
                }
    
                $CreateBasicServerProfileTemplateResults.taskState | Should -Be Completed
    
            }
    
            It "Will verify connections are unmanaged in template" {
    
                { $Script:ServerProfileTemplate = Get-HPOVServerProfileTemplate -Name "$BasicServerProfileName UnmanagedConnections Template" -ErrorAction Stop } | Should -Not -Throw
    
                $ServerProfileTemplate.category | Should -Be 'server-profile-templates'
                $ServerProfileTemplate.connectionSettings.manageConnections | Should -Be $false
                $ServerProfileTemplate.connectionSettings.connections.Count | Should -Be 0
    
            }
    
            It "Will create server profile from template specifying connections" {
    
                $Params = @{
    
                    Name                  = $ServerProfileUnmanagedConnectionsName;
                    ServerProfileTemplate = $ServerProfileTemplate;
                    AssignmentType        = 'Unassigned';
                    Connections           = $ProfileConnection1,$ProfileConnection2 ;
                    ManageBoot            = $true
    
                }
    
                { $Script:CreateServerProfileResults = New-HPOVServerProfile -Confirm:$False @Params } | Should -Not -Throw
    
                if ($CreateServerProfileResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateServerProfileResults
    
                }
    
                $CreateServerProfileResults.taskState | Should -Be Completed
                
            }
    
        }
    
        Context "Create Server Profile Template with Private Volume from SVT for BL460c Gen9" {
    
            $Script:BL460cGen9SHT                  = Get-HPOVServerHardwareType -Name 'BL460c Gen9 1' 
            $Script:EnclosureGroup                 = Get-HPOVEnclosureGroup -Name $DCSDefaultEGName
            $ServerProfileConnection1NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection1NetName -ErrorAction Stop
            $Script:ProfileConnection1             = New-HPOVServerProfileConnection -ConnectionID 1 -Name "$ServerProfileConnection1NetName Connection" -Network $ServerProfileConnection1NetObject -Bootable -Priority Primary
            $ServerProfileConnection2NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection2NetName -ErrorAction Stop
            $Script:ProfileConnection2             = New-HPOVServerProfileConnection -ConnectionID 2 -Name "$ServerProfileConnection2NetName Connection" -Network $ServerProfileConnection2NetObject
            $ServerProfileConnection3NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection3NetName -Type $ServerProfileConnection3Type -ErrorAction Stop
            $Script:ProfileConnection3             = New-HPOVServerProfileConnection -ConnectionID 3 -Name "$ServerProfileConnection3NetName Connection" -Network $ServerProfileConnection3NetObject
            $ServerProfileConnection4NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection4NetName -Type $ServerProfileConnection4Type -ErrorAction Stop
            $Script:ProfileConnection4             = New-HPOVServerProfileConnection -ConnectionID 4 -Name "$ServerProfileConnection4NetName Connection" -Network $ServerProfileConnection4NetObject
            $ServerProfileConnection5NetObject     = Get-HPOVNetworkSet -Name $ServerProfileConnection5NetName -ErrorAction Stop
            $Script:ProfileConnection5             = New-HPOVServerProfileConnection -ConnectionID 5 -Name "$ServerProfileConnection5NetName Connection" -Network $ServerProfileConnection5NetObject
            $ServerProfileConnection6NetObject     = Get-HPOVNetworkSet -Name $ServerProfileConnection6NetName -ErrorAction Stop
            $Script:ProfileConnection6             = New-HPOVServerProfileConnection -ConnectionID 6 -Name "$ServerProfileConnection6NetName Connection" -Network $ServerProfileConnection6NetObject
            $ServerProfileConnection7NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection7NetName -type $ServerProfileConnection7Type -ErrorAction Stop
            $Script:ProfileConnection7             = New-HPOVServerProfileConnection -ConnectionID 7 -Name "$ServerProfileConnection7NetName Connection" -Network $ServerProfileConnection7NetObject
            $ServerProfileConnection8NetObject     = Get-HPOVNetwork -Name $ServerProfileConnection8NetName -type $ServerProfileConnection8Type -ErrorAction Stop
            $Script:ProfileConnection8             = New-HPOVServerProfileConnection -ConnectionID 8 -Name "$ServerProfileConnection8NetName Connection #2" -Network $ServerProfileConnection8NetObject
            $Script:ServerProfileConnections       = $ProfileConnection1,$ProfileConnection2,$ProfileConnection3,$ProfileConnection4,$ProfileConnection5,$ProfileConnection6,$ProfileConnection7,$ProfileConnection8
            $Script:ServerProfileLogicalDiskObject = New-HPOVServerProfileLogicalDisk -Name 'OS Disk' -RAID RAID1 -NumberofDrives 2 -DriveType Auto
            $Script:ServerProfileController        = New-HPOVServerProfileLogicalDiskController -ControllerID Embedded -Mode RAID -Initialize -LogicalDisk $ServerProfileLogicalDiskObject
            $Script:SVT = Get-HPOVStoragePool -Name $StoreServeSSDPoolName -StorageSystem $StorageSystem1Name -ErrorAction Stop | New-HPOVStorageVolumeTemplate -Name "$StorageVolumeTPDDName-SVT" -Description 'TPDD Pester SVT Test' -Capacity 10 -LockCapacity -ProvisionType TPDD -LockProvisionType
    
            $Script:StorageVolumeObject = New-HPOVServerProfileAttachVolume -Name "$AdvancedServerProfileName Template 3 Private Vol 1" -VolumeTemplate $SVT
    
            It "Will create complex Server Profile Template resource '$AdvancedServerProfileName Template 3'" {
    
                $ParamHash = @{
                    
                    Name               = "$AdvancedServerProfileName Template 3"
                    ServerHardwareType = $BL460cGen9SHT;
                    EnclosureGroup     = $EnclosureGroup;
                    Connections        = $ServerProfileConnections;
                    LocalStorage       = $true;
                    StorageController  = $ServerProfileController;
                    Bios               = $true;
                    BiosSettings       = $Gen9BiosSettings;
                    ManageBoot         = $true;
                    BootMode           = "UEFI";
                    SanStorage         = $true;
                    HostOStype         = 'Win2k12';
                    StorageVolume      = $StorageVolumeObject
                    
                }
            
                { $Script:CreateAdvancedServerProfileResults = New-HPOVServerProfileTemplate @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
                $CreateAdvancedServerProfileResults | Should -Not -BeNullOrEmpty
                $CreateAdvancedServerProfileResults.category | Should -Be 'tasks'
    
                if ($CreateAdvancedServerProfileResults.taskState -ne "Completed") {
    
                    DisplayTaskError $CreateAdvancedServerProfileResults
    
                }
    
                $CreateAdvancedServerProfileResults.taskState | Should -Be Completed
            
            }
    
            It "Will validate Server Profile Template contains SVT volume is set" {
            
                { $Script:SPT = Get-HPOVServerProfileTemplate -Name "$AdvancedServerProfileName Template 3" -ErrorAction Stop } | Should -Not -Throw
                $SPT.sanStorage.volumeAttachments.Count | Should -Be 1
                $SPT.sanStorage.volumeAttachments[0].volume.templateUri | Should -Be $SVT.uri
    
            }
    
            It "Will validate Server Profile Template SVT volume size is set correctly" {
    
                $SPT.sanStorage.volumeAttachments[0].volume.properties.size | Should -Be $SVT.properties.size.default
                
            }
    
        }

    }
    
    Context "HPE BladeSystem - Create Server Profile with Server Profile Template Management Operations for BL460 Gen9" {

        It "Will attempt to create a Server Profile with Server AssignmentType without providing a Server resource" {
        
            { $script:ServerProfileTemplate = Get-HPOVServerProfileTemplate -Name "$AdvancedServerProfileName Template 2" -ErrorAction Stop } | Should -Not -Throw

            $ExpectedExceptionMessage = 'A Server resource object or name must be provided when using the "Server" AssignmentType parameter.'

            { New-HPOVServerProfile -Name 'Foo' -ServerProfileTemplate $ServerProfileTemplate -AssignmentType Server } | Should -Throw $ExpectedExceptionMessage
        
        }

        It "Will create Server Profile from Template using first available BL460 Gen9" {

            { $script:ServerProfileTemplate = Get-HPOVServerProfileTemplate -Name "$AdvancedServerProfileName Template 2" -ErrorAction Stop } | Should -Not -Throw

            { $Script:ServerHardwareType = Get-HPOVServerHardwareType -Name 'BL460c Gen9 1' } | Should -Not -Throw

            { $script:AvailableServerHardware = Get-HPOVServer -NoProfile -ServerHardwareType $ServerHardwareType } | Should -Not -Throw

            $AvailableServerHardware | Should -Not -BeNullOrEmpty

            { $Script:CreateServerProfileFromTemplateResults = New-HPOVServerProfile -Confirm:$False -Name $ServerProfileFromTemplateName -ServerProfileTemplate $ServerProfileTemplate -AssignmentType Server -Server ($AvailableServerHardware | Select-Object -First 1) | Wait-HPOVTaskComplete } | Should -Not -Throw
            $CreateServerProfileFromTemplateResults | Should -Not -BeNullOrEmpty
            $CreateServerProfileFromTemplateResults.category | Should -Be 'tasks'

            if ($CreateServerProfileFromTemplateResults.taskState -ne "Completed") {

                DisplayTaskError $CreateServerProfileFromTemplateResults

            }

            $CreateServerProfileFromTemplateResults.taskState | Should -Be 'Completed'

        }

        It "Will validate Server Profile '$ServerProfileFromTemplateName' is compliant with Template" {
        
            { $Script:ServerProfileResource = Get-HPOVServerProfile -Name $ServerProfileFromTemplateName -ErrorAction Stop } | Should -Not -Throw
            $ServerProfileResource.templateCompliance | Should -Be Compliant
        
        }

        It "Will Update Server Profile Template with new BIOS settings" {
        
            { $Script:ServerProfileTemplateResource = Get-HPOVServerProfileTemplate -Name "$AdvancedServerProfileName Template 2" -ErrorAction Stop } | Should -Not -Throw

            $ServerProfileTemplateResource.bios.overriddenSettings = $NewGen9BiosSettings

            { $Script:UpdateSPTResults = Send-HPOVRequest -Uri $ServerProfileTemplateResource.uri -Method PUT -Body $ServerProfileTemplateResource | Wait-HPOVTaskComplete } | Should -Not -Throw

            $UpdateSPTResults.category | Should -Be tasks

            if ($UpdateSPTResults.taskState -ne "Completed") {

                DisplayTaskError $UpdateSPTResults

            }

            $UpdateSPTResults.taskState | Should -Be Completed
        
        }

        It "Will validate Server Profile '$ServerProfileFromTemplateName' is no longer compliant with Template" {
        
            { $Script:ServerProfileResource = Get-HPOVServerProfile -Name $ServerProfileFromTemplateName -NonCompliant -ErrorAction Stop } | Should -Not -Throw

            $ServerProfileResource | Should -Not -BeNullOrEmpty
            $ServerProfileResource.templateCompliance | Should -Be NonCompliant
        
        }

        It "Will validate Server Profile ComplianceReview object using -WhatIf parameter" {

            $SPUpdateWhatIfResults = Get-HPOVServerProfile -Name $ServerProfileFromTemplateName -NonCompliant -ErrorAction Stop | Update-HPOVServerProfile -WhatIf

            $SPUpdateWhatIfResults | Should -BeOfType HPOneView.ServerProfile.CompliancePreview
            $SPUpdateWhatIfResults.Name | Should -Be $ServerProfileFromTemplateName

        }

        It "Will make Server Profile '$ServerProfileFromTemplateName' compliant with Template" {
        
            { $Script:ServerProfileUpdateFromTemplateResults = Get-HPOVServerProfile -Name $ServerProfileFromTemplateName -NonCompliant -ErrorAction Stop | Update-HPOVServerProfile -Async -Confirm:$False | Wait-HPOVTaskComplete } | Should -Not -Throw

            $ServerProfileUpdateFromTemplateResults | Should -Not -BeNullOrEmpty
            
            if ($ServerProfileUpdateFromTemplateResults.taskState -ne "Completed") {

                DisplayTaskError $ServerProfileUpdateFromTemplateResults

            }

            $ServerProfileUpdateFromTemplateResults.taskState | Should -Be Completed
        
        }

    }

    Context "HPE Synergy - Create Server Profile Template and Server Profile resources with D3940 Storage and LAG" {

        BeforeAll {

            if ($null -eq ($ConnectedSessions | Where-Object Name -eq $Appliance3)) {
    
                { $Script:Connection3 = Connect-HPOVMgmt -Hostname $Appliance3 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
    
            }

            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance3).Default) {

                ($ConnectedSessions | Where-Object Name -eq $Appliance3) | Set-HPOVApplianceDefaultConnection
    
            }

            Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow            

            $Script:SY480Gen9SHT       = Get-HPOVServerHardwareType -Name 'SY 480 Gen9*' -ErrorAction Stop | Where-Object { $_.adapters.model -match 'Smart Array' } | Where-Object { $_.adapters.model -match 'Smart Array' }
            $Script:EnclosureGroup     = Get-HPOVEnclosureGroup -Name $SynergyDCSDefaultEGName -ErrorAction Stop
            $Script:BaselineObject     = Get-HPOVBaseline -FileName $ExistingSynergyBaselineName -ErrorAction Stop
            $Script:MLagVLan100Con1    = Get-HPOVNetwork -Name "MLAG VLAN 100" -ErrorAction Stop | New-HPOVServerProfileConnection -ConnectionID 1 -Name 'VLAN 100 Connection 1' -LagName LAG1
            $Script:MLagVLan100Con2    = Get-HPOVNetwork -Name "MLAG VLAN 100" -ErrorAction Stop | New-HPOVServerProfileConnection -ConnectionID 2 -Name 'VLAN 100 Connection 2' -LagName LAG1
            $LogicalDisk1              = New-HPOVServerProfileLogicalDisk -Name 'Local Scratch' -RAID RAID1
            $LogicalDisk2              = New-HPOVServerProfileLogicalDisk -Name 'Boot' -RAID RAID1 -MinDriveSize 300 -MaxDriveSize 300 -DriveType SAS -Bootable $True
            $LogicalDisk3              = New-HPOVServerProfileLogicalDisk -Name 'Data' -RAID RAID5 -NumberofDrives 5 -MinDriveSize 300 -MaxDriveSize 300 -DriveType SAS
            $Script:StorageController1 = New-HPOVServerProfileLogicalDiskController -Mode RAID -Initialize -LogicalDisk $LogicalDisk1
            $Script:StorageController2 = New-HPOVServerProfileLogicalDiskController -ControllerID 'Mezz 1' -Mode RAID -LogicalDisk $LogicalDisk2,$LogicalDisk3

        }            

        It "Will create '$SynergyServerProfileTemplateName' Server Profile Template" {

            $ParamHash = @{
                
                Name               = $SynergyServerProfileTemplateName
                ServerHardwareType = $SY480Gen9SHT;
                EnclosureGroup     = $EnclosureGroup;
                Connections        = $MLagVLan100Con1,$MLagVLan100Con2;
                LocalStorage       = $true;
                StorageController  = $StorageController1,$StorageController2;
                Bios               = $true;
                BiosSettings       = $Gen9BiosSettings;
                ManageBoot         = $true;
                BootMode           = "UEFI"
                
            }
        
            { $Script:CreateSynergyTemplateWithDASServerProfileResults = New-HPOVServerProfileTemplate @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
            $CreateSynergyTemplateWithDASServerProfileResults | Should -Not -BeNullOrEmpty
            $CreateSynergyTemplateWithDASServerProfileResults.category | Should -Be 'tasks'

            if ($CreateSynergyTemplateWithDASServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $CreateSynergyTemplateWithDASServerProfileResults

            }

            $CreateSynergyTemplateWithDASServerProfileResults.taskState | Should -Be Completed
    
        }

        It "Will create '$SynergyServerProfileName' Server Profile" {

            $ParamHash = @{
                
                Name               = $SynergyServerProfileName
                AssignmentType     = 'Unassigned';
                ServerHardwareType = $SY480Gen9SHT;
                EnclosureGroup     = $EnclosureGroup;
                Connections        = $MLagVLan100Con1,$MLagVLan100Con2;
                LocalStorage       = $true;
                StorageController  = $StorageController1,$StorageController2;
                Bios               = $true;
                BiosSettings       = $Gen9BiosSettings;
                ManageBoot         = $true;
                BootMode           = "UEFI"
                
            }
        
            { $Script:CreateSynergyWithDASServerProfileResults = New-HPOVServerProfile @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw
            $CreateSynergyWithDASServerProfileResults | Should -Not -BeNullOrEmpty
            $CreateSynergyWithDASServerProfileResults.category | Should -Be 'tasks'

            if ($CreateSynergyWithDASServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $CreateSynergyWithDASServerProfileResults

            }

            $CreateSynergyWithDASServerProfileResults.taskState | Should -Be Completed
    
        }

        It "Will validate Server Profile Template '$SynergyServerProfileTemplateName' exists." {
        
            { $Script:ServerProfileTemplateObject = Get-HPOVServerProfileTemplate -Name $SynergyServerProfileTemplateName -ErrorAction Stop -ApplianceConnection $Connection3 } | Should -Not -Throw

        }

        It "Will validate LocalStorage Controller Count in SPT Should -Be 2" {

            $ServerProfileTemplateObject.localStorage.Controllers.count | Should -Be 2

        }

        It "Will validate Embedded storage controller configuration in SPT is RAID and contains 1 LD" {

            $EmbeddedController = $ServerProfileTemplateObject.localStorage.Controllers | Where-Object deviceSlot -eq 'Embedded'
            $EmbeddedController | Should -Not -BeNullOrEmpty
            $EmbeddedController.mode | Should -Be RAID
            $EmbeddedController.initialize | Should -Be $true
            $EmbeddedController.logicalDrives.count | Should -Be 1
            $EmbeddedController.logicalDrives[0].name | Should -Be 'Local Scratch'
            $EmbeddedController.logicalDrives[0].raidLevel | Should -Be RAID1
            $EmbeddedController.logicalDrives[0].bootable | Should -Be $false
            $EmbeddedController.logicalDrives[0].numPhysicalDrives | Should -Be 2
            $EmbeddedController.logicalDrives[0].driveTechnology | Should -BeNullOrEmpty
            $EmbeddedController.logicalDrives[0].sasLogicalJBODId | Should -BeNullOrEmpty
            $EmbeddedController.logicalDrives[0].driveNumber | Should -BeNullOrEmpty

        }

        It "Will validate D3940 Storage Configuration in SPT" {

            $SasLogicalJBODs = $ServerProfileTemplateObject.localStorage.sasLogicalJBODs

            #'Mezz 1' Controller
            $Mezz1Controller = $ServerProfileTemplateObject.localStorage.Controllers | Where-Object deviceSlot -eq 'Mezz 1'
            $Mezz1Controller | Should -Not -BeNullOrEmpty
            $Mezz1Controller.mode | Should -Be RAID
            $Mezz1Controller.initialize | Should -Be $false
            $Mezz1Controller.logicalDrives.count | Should -Be 2

            #LogicalDisk 1
            $BootD3940DiskJbod = $SasLogicalJBODs | Where-Object name -EQ 'Boot'
            $BootD3940DiskJbod | Should -Not -BeNullOrEmpty
            $Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id | Should -Not -BeNullOrEmpty
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).raidLevel | Should -Be RAID1
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).bootable | Should -Be $true
            $BootD3940DiskJbod.numPhysicalDrives | Should -Be 2
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).numPhysicalDrives | Should -BeNullOrEmpty
            $BootD3940DiskJbod.driveMinSizeGB | Should -Be 300
            $BootD3940DiskJbod.driveMaxSizeGB | Should -Be 300
            $BootD3940DiskJbod.driveTechnology | Should -Be 'SasHdd'
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).driveTechnology | Should -BeNullOrEmpty
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).driveNumber | Should -BeNullOrEmpty

            #LogicalDisk 2
            $DataD3940DiskJbod = $SasLogicalJBODs | Where-Object name -EQ 'Data'
            $DataD3940DiskJbod | Should -Not -BeNullOrEmpty
            $Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id | Should -Not -BeNullOrEmpty
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).raidLevel | Should -Be RAID5
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).bootable | Should -Be $false
            $DataD3940DiskJbod.numPhysicalDrives | Should -Be 5
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).numPhysicalDrives | Should -BeNullOrEmpty
            $BootD3940DiskJbod.driveMinSizeGB | Should -Be 300
            $BootD3940DiskJbod.driveMaxSizeGB | Should -Be 300
            $DataD3940DiskJbod.driveTechnology | Should -Be 'SasHdd'
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).driveTechnology | Should -BeNullOrEmpty
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).driveNumber | Should -BeNullOrEmpty
        
        }

        It "Will validate Server Profile '$SynergyServerProfileName' exists." {
        
            { $Script:ServerProfileObject = Get-HPOVServerProfile -Name $SynergyServerProfileName -ErrorAction Stop -ApplianceConnection $Connection3 } | Should -Not -Throw

        }

        It "Will validate LocalStorage Controller Count in specific Should -Be 2" {

            $ServerProfileObject.localStorage.Controllers.count | Should -Be 2

        }

        It "Will validate Embedded storage controller configuration in SP is RAID and contains 1 LD" {

            $EmbeddedController = $ServerProfileObject.localStorage.Controllers | Where-Object deviceSlot -eq 'Embedded'
            $EmbeddedController | Should -Not -BeNullOrEmpty
            $EmbeddedController.mode | Should -Be RAID
            $EmbeddedController.initialize | Should -Be $true
            $EmbeddedController.logicalDrives.count | Should -Be 1
            $EmbeddedController.logicalDrives[0].name | Should -Be 'Local Scratch'
            $EmbeddedController.logicalDrives[0].raidLevel | Should -Be RAID1
            $EmbeddedController.logicalDrives[0].bootable | Should -Be $false
            $EmbeddedController.logicalDrives[0].numPhysicalDrives | Should -Be 2
            $EmbeddedController.logicalDrives[0].driveTechnology | Should -BeNullOrEmpty
            $EmbeddedController.logicalDrives[0].sasLogicalJBODId | Should -BeNullOrEmpty
            $EmbeddedController.logicalDrives[0].driveNumber | Should -BeNullOrEmpty

        }

        It "Will validate D3940 Storage Configuration in SP" {

            $SasLogicalJBODs = $ServerProfileObject.localStorage.sasLogicalJBODs

            #'Mezz 1' Controller
            $Mezz1Controller = $ServerProfileObject.localStorage.Controllers | Where-Object deviceSlot -eq 'Mezz 1'
            $Mezz1Controller | Should -Not -BeNullOrEmpty
            $Mezz1Controller.mode | Should -Be RAID
            $Mezz1Controller.initialize | Should -Be $false
            $Mezz1Controller.logicalDrives.count | Should -Be 2

            #LogicalDisk 1
            $BootD3940DiskJbod = $SasLogicalJBODs | Where-Object name -EQ 'Boot'
            $BootD3940DiskJbod | Should -Not -BeNullOrEmpty
            $Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id | Should -Not -BeNullOrEmpty
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).raidLevel | Should -Be RAID1
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).bootable | Should -Be $true
            $BootD3940DiskJbod.numPhysicalDrives | Should -Be 2
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).numPhysicalDrives | Should -BeNullOrEmpty
            $BootD3940DiskJbod.driveMinSizeGB | Should -Be 300
            $BootD3940DiskJbod.driveMaxSizeGB | Should -Be 300
            $BootD3940DiskJbod.driveTechnology | Should -Be 'SasHdd'
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).driveTechnology | Should -BeNullOrEmpty
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $BootD3940DiskJbod.id).driveNumber | Should -BeNullOrEmpty

            #LogicalDisk 2
            $DataD3940DiskJbod = $SasLogicalJBODs | Where-Object name -EQ 'Data'
            $DataD3940DiskJbod | Should -Not -BeNullOrEmpty
            $Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id | Should -Not -BeNullOrEmpty
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).raidLevel | Should -Be RAID5
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).bootable | Should -Be $false
            $DataD3940DiskJbod.numPhysicalDrives | Should -Be 5
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).numPhysicalDrives | Should -BeNullOrEmpty
            $BootD3940DiskJbod.driveMinSizeGB | Should -Be 300
            $BootD3940DiskJbod.driveMaxSizeGB | Should -Be 300
            $DataD3940DiskJbod.driveTechnology | Should -Be 'SasHdd'
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).driveTechnology | Should -BeNullOrEmpty
            ($Mezz1Controller.logicalDrives | Where-Object sasLogicalJBODId -eq $DataD3940DiskJbod.id).driveNumber | Should -BeNullOrEmpty
        
        }

        It "Will retrieve an available 900GB SASHDD disk drive available" {

            { $Script:AvailableDriveType = Get-HPOVSasLogicalInterconnect -name 'LE1-DCS Default SAS Synergy LIG-3' -ErrorAction Stop -ApplianceConnection $Connection3 | Get-HPOVAvailableDriveType | Where-Object { $_.Type -eq 'SASHDD' -and $_.capacity -eq 900 } } | Should -Not -Throw
            $AvailableDriveType | Should -Not -BeNullOrEmpty

        }

        It "Will validate available disk object" {

            $AvailableDriveType | Should -BeOfType HPOneView.Storage.AvailableDriveType

        }

        It "Will validate available drive capacity is 900" {

            $AvailableDriveType.Capacity | Should -BeExactly 900

        }

        It "Will validate available disk object contains more than 1 available" {

            $AvailableDriveType.NumberAvailable | Should -BeGreaterThan 1

        }

        It "Will validate disk type is SASHDD" {

            $AvailableDriveType.Type | Should -Be SASHDD

        }

        It "Will create a Synergy Logical Disk using available disk drive object" {

            { $Script:NewLogicalDisk = $AvailableDriveType | New-HPOVServerProfileLogicalDisk -Name 'LD1_RAID1_900GB_SASHDD' -DriveSelectionBy DriveType -NumberofDrives 2 -RAID RAID1 } | Should -Not -Throw

        }

        It "Will validate created Logical Disk contains the SasLogicalJBOD property" {

            $NewLogicalDisk.SasLogicalJBOD | Should -Not -BeNullOrEmpty

        }

        It "Will validate created Logical Disk RAID is RAID1" {

            $NewLogicalDisk.SasLogicalJBOD.name | Should -Be LD1_RAID1_900GB_SASHDD

        }

        It "Will validate created Logical Disk RAID is RAID1" {

            $NewLogicalDisk.raidLevel | Should -Be RAID1

        }

        It "Will validate created Logical Disk drive technology" {

            $NewLogicalDisk.SasLogicalJBOD.driveTechnology | Should -Be $AvailableDriveType.Type

        }

        It "Will validate created Logical Disk drive Min and Max size" {

            $NewLogicalDisk.SasLogicalJBOD.driveMinSizeGB | Should -Be $AvailableDriveType.Capacity
            $NewLogicalDisk.SasLogicalJBOD.driveMaxSizeGB | Should -Be $AvailableDriveType.Capacity

        }

    }

    Context "HPE Synergy - Create ImageStreamer Server Profile Template Operations (DHCP)" {

        BeforeAll {

            if ($null -eq ($ConnectedSessions | Where-Object Name -eq $Appliance3)) {
    
                { $Script:Connection3 = Connect-HPOVMgmt -Hostname $Appliance3 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
    
            }

            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance3).Default) {

                ($ConnectedSessions | Where-Object Name -eq $Appliance3) | Set-HPOVApplianceDefaultConnection
    
            }

            Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

            $Script:SY480cGen9SHT = Get-HPOVServerHardwareType -Name 'SY 480 Gen9 1' -ErrorAction Stop
            $Script:EnclosureGroup = Get-HPOVEnclosureGroup -Name $SynergyDCSDefaultEGName -ErrorAction Stop
            $Script:BaselineObject = Get-HPOVBaseline -File $ExistingSynergyBaselineName -ErrorAction Stop

        }

        It "Will create ImageStreamer iCSSI Connection #1" {

            $ISCSINetwork = Get-HPOVNetwork -Purpose ISCSI -ErrorAction Stop | Select-Object -First 1

            $IscsiParams = @{
                ConnectionID           = 1;
                Name                   = 'ImageStreamer Connection 1';
                ConnectionType         = 'Ethernet';
                Network                = $ISCSINetwork;
                Bootable               = $true;
                Priority               = 'IscsiPrimary';
                IscsiIPv4AddressSource = 'SubnetPool'
            }

            { $Script:I3SCon1 = New-HPOVServerProfileConnection @IscsiParams } | Should -Not -Throw
        
        }

        It "Will validate connection type is 'Ethernet'" {

            $I3SCon1.functionType | Should -Be Ethernet

        }

        It "Will validate connection boot priority is 'Primary'" {

            $I3SCon1.boot.priority | Should -Be Primary

        }

        It "Will validate connection IPv4Address Source is SubnetPool" {

            $I3SCon1.ipv4.ipAddressSource | Should -Be SubnetPool

        }

        It "Will validate ImageStreamer compliant iCSSI Connection" { 
            
            $I3SCon1.boot.iscsi.initiatorNameSource | Should -Be ProfileInitiatorName

            #Check for properties that need to -Exist but without value
            'firstBootTargetIp', 'secondBootTargetIp', 'initiatorName', 'bootTargetName', 'chapLevel', 'chapName', 'chapSecret', 'mutualChapName', 'mutualChapSecret' | ForEach-Object {

                [Bool]$I3SCon1.boot.iscsi.PSObject.Properties.Match("$_") | Should -Be $true

            }

            "ipAddress", "subnetMask", "gateway", "ipAddressSource" | ForEach-Object {

                [Bool]$I3SCon1.ipv4.PSObject.Properties.Match("$_") | Should -Be $true

            }

        }

        It "Will create ImageStreamer iCSSI Connection #2" {

            $ISCSINetwork = Get-HPOVNetwork -Purpose ISCSI -ApplianceConnection $Connection3 -ErrorAction Stop | Select-Object -First 1

            $IscsiParams = @{
                ConnectionID           = 2;
                Name                   = 'ImageStreamer Connection 2';
                ConnectionType         = 'Ethernet';
                Network                = $ISCSINetwork;
                Bootable               = $true;
                Priority               = 'Secondary';
                IscsiIPv4AddressSource = 'SubnetPool'
            }

            { $Script:I3SCon2 = New-HPOVServerProfileConnection @IscsiParams } | Should -Not -Throw
        
        }

        It "Will validate connection type is 'Ethernet'" {

            $I3SCon2.functionType | Should -Be Ethernet

        }

        It "Will validate connection boot priority is 'Primary'" {

            $I3SCon2.boot.priority | Should -Be Secondary

        }

        It "Will validate connection IPv4Address Source is SubnetPool" {

            $I3SCon2.ipv4.ipAddressSource | Should -Be SubnetPool

        }

        It "Will validate ImageStreamer compliant iCSSI Connection" { 
            
            $I3SCon2.boot.iscsi.initiatorNameSource | Should -Be ProfileInitiatorName

            #Check for properties that need to -Exist but without value
            'firstBootTargetIp', 'secondBootTargetIp', 'initiatorName', 'bootTargetName', 'chapLevel', 'chapName', 'chapSecret', 'mutualChapName', 'mutualChapSecret' | ForEach-Object {

                [Bool]$I3SCon2.boot.iscsi.PSObject.Properties.Match("$_") | Should -Be $true

            }

            "ipAddress", "subnetMask", "gateway", "ipAddressSource" | ForEach-Object {

                [Bool]$I3SCon2.ipv4.PSObject.Properties.Match("$_") | Should -Be $true

            }

        }

        It "Will create SPT Connection #3" {

            $Script:I3SCon3 = Get-HPOVNetwork -Name "MLAG VLAN 10" -ErrorAction Stop | New-HPOVServerProfileConnection -Name 'Connection 3' `
                -ConnectionID 3 `
                -ConnectionType Ethernet
                                                                                                                
        }

        It "Will create SPT Connection #4" {

            $Script:I3SCon4 = Get-HPOVNetwork -Name "MLAG VLAN 10" -ErrorAction Stop | New-HPOVServerProfileConnection -Name 'Connection 4' `
                -ConnectionID 4 `
                -ConnectionType Ethernet

        }

        It "Will validate Image Streamer exists" {

            { $Script:OSDeploymentServer = Get-HPOVOSDeploymentServer -Name $OSDeploymentServerName -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will get and validate OS Deployment Plan" -Skip:(-not $OSDeploymentServer) {

            { $Script:OSDeploymentPlan = Get-HPOVOSDeploymentPlan -Name $OSDeploymentPlanName -ErrorAction Stop } | Should -Not -Throw
            $OSDeploymentPlan.type | Should -Be Osdp

        }

        It "Will get and validate OS Deployment Plan Properties and object type" -Skip:(-not $OSDeploymentServer) {

            { $Script:OSDeploymentAttributes = Get-HPOVOSDeploymentPlanAttribute -InputObject $OSDeploymentPlan -ErrorAction Stop } | Should -Not -Throw
            #$OSDeploymentAttributes | Should -BeOfType HPOneView.ServerProfile.OSDeployment.OsDeploymentPlanParameter

            $OSDeploymentAttributes | ForEach-Object {

                $_ | Should -BeOfType HPOneView.ServerProfile.OSDeployment.OSDeploymentParameter

            }

        }

        It "Will set NIC OS Deployment Attributes required for the OS Deployment Plan" {

            $script:OSDeploymentAttributes = $script:OSDeploymentAttributes | Where-Object name -NotMatch 'dns|gateway|ipaddress|netmask'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.connectionid").value = 3
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.networkuri").value = $I3SCon3.networkUri
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.constraint").value = 'dhcp'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.dhcp").value = $true
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.connectionid").value = 4
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.networkuri").value = $I3SCon4.networkUri
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.constraint").value = 'dhcp'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.dhcp").value = $true

        }

        It "Will create Server Profile Template with Image Streamer with baseline" -Skip:(-not $OSDeploymentServer) {

            $ParamHash = @{
                
                Name                       = $Synergyi3SSPTName;
                ServerHardwareType         = $SY480cGen9SHT;
                EnclosureGroup             = $EnclosureGroup;
                Connections                = $I3SCon1, $I3SCon2, $I3SCon3, $I3SCon4;
                ManageBoot                 = $true;
                Firmware                   = $true;
                BootMode                   = 'UEFI';
                Baseline                   = $BaselineObject;
                FirmwareMode               = 'FirmwareAndSoftware';
                FirmwareActivationMode     = 'Scheduled';
                OSDeploymentPlan           = $OSDeploymentPlan;
                OSDeploymentPlanAttributes = $OSDeploymentAttributes
                
            }            
        
            { $Script:I3SSPTResults = New-HPOVServerProfileTemplate @ParamHash | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($I3SSPTResults.taskState -ne "Completed")
            {

                DisplayTaskError $I3SSPTResults

            }

            $I3SSPTResults.taskState | Should -Be Completed

        }

        # Validate OSDeploymentSettings
        It "Will validate OS Deployment Settings -Exist within SPT" -Skip:(-not $OSDeploymentServer) {

            $SPT = Get-HPOVServerProfileTemplate -Name $Synergyi3SSPTName -ErrorAction Stop

            $SPT.osDeploymentSettings.osDeploymentPlanUri | Should -Be $OSDeploymentPlan.uri
            $SPT.osDeploymentSettings.osCustomAttributes | Should -Not -BeNullOrEmpty

        }

    }

    Context "HPE Synergy - Create ImageStreamer Server Profile Template Operations (Static IPv4)" {

        BeforeAll {

            if ($null -eq ($ConnectedSessions | Where-Object Name -eq $Appliance3)) 
            {
    
                { $Script:Connection3 = Connect-HPOVMgmt -Hostname $Appliance3 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
    
            }

            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance3).Default) {

                ($ConnectedSessions | Where-Object Name -eq $Appliance3) | Set-HPOVApplianceDefaultConnection
    
            }  

            Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

            $Script:SY480cGen9SHT = Get-HPOVServerHardwareType -Name 'SY 480 Gen9 1' -ErrorAction Stop
            $Script:EnclosureGroup = Get-HPOVEnclosureGroup -Name $SynergyDCSDefaultEGName -ErrorAction Stop
            $Script:BaselineObject = Get-HPOVBaseline -File $ExistingSynergyBaselineName -ErrorAction Stop

        }

        It "Will create ImageStreamer iCSSI Connection #1" {

            $ISCSINetwork = Get-HPOVNetwork -Purpose ISCSI -ErrorAction Stop | Select-Object -First 1

            $IscsiParams = @{
                ConnectionID           = 1;
                Name                   = 'ImageStreamer Connection 1';
                ConnectionType         = 'Ethernet';
                Network                = $ISCSINetwork;
                Bootable               = $true;
                Priority               = 'IscsiPrimary';
                IscsiIPv4AddressSource = 'SubnetPool'
            }

            { $Script:I3SCon1 = New-HPOVServerProfileConnection @IscsiParams } | Should -Not -Throw
        
        }

        It "Will validate connection type is 'Ethernet'" {

            $I3SCon1.functionType | Should -Be Ethernet

        }

        It "Will validate connection boot priority is 'Primary'" {

            $I3SCon1.boot.priority | Should -Be Primary

        }

        It "Will validate connection IPv4Address Source is SubnetPool" {

            $I3SCon1.ipv4.ipAddressSource | Should -Be SubnetPool

        }

        It "Will validate ImageStreamer compliant iCSSI Connection" { 
            
            $I3SCon1.boot.iscsi.initiatorNameSource | Should -Be ProfileInitiatorName

            #Check for properties that need to -Exist but without value
            'firstBootTargetIp', 'secondBootTargetIp', 'initiatorName', 'bootTargetName', 'chapLevel', 'chapName', 'chapSecret', 'mutualChapName', 'mutualChapSecret' | ForEach-Object {

                [Bool]$I3SCon1.boot.iscsi.PSObject.Properties.Match("$_") | Should -Be $true

            }

            "ipAddress", "subnetMask", "gateway", "ipAddressSource" | ForEach-Object {

                [Bool]$I3SCon1.ipv4.PSObject.Properties.Match("$_") | Should -Be $true

            }

        }

        It "Will create ImageStreamer iCSSI Connection #2" {

            $ISCSINetwork = Get-HPOVNetwork -Purpose ISCSI -ErrorAction Stop | Select-Object -First 1

            $IscsiParams = @{
                ConnectionID           = 2;
                Name                   = 'ImageStreamer Connection 2';
                ConnectionType         = 'Ethernet';
                Network                = $ISCSINetwork;
                Bootable               = $true;
                Priority               = 'Secondary';
                IscsiIPv4AddressSource = 'SubnetPool'
            }

            { $Script:I3SCon2 = New-HPOVServerProfileConnection @IscsiParams } | Should -Not -Throw
        
        }

        It "Will validate connection type is 'Ethernet'" {

            $I3SCon2.functionType | Should -Be Ethernet

        }

        It "Will validate connection boot priority is 'Primary'" {

            $I3SCon2.boot.priority | Should -Be Secondary

        }

        It "Will validate connection IPv4Address Source is SubnetPool" {

            $I3SCon2.ipv4.ipAddressSource | Should -Be SubnetPool

        }

        It "Will validate ImageStreamer compliant iCSSI Connection" { 
            
            $I3SCon2.boot.iscsi.initiatorNameSource | Should -Be ProfileInitiatorName

            #Check for properties that need to -Exist but without value
            'firstBootTargetIp', 'secondBootTargetIp', 'initiatorName', 'bootTargetName', 'chapLevel', 'chapName', 'chapSecret', 'mutualChapName', 'mutualChapSecret' | ForEach-Object {

                [Bool]$I3SCon2.boot.iscsi.PSObject.Properties.Match("$_") | Should -Be $true

            }

            "ipAddress", "subnetMask", "gateway", "ipAddressSource" | ForEach-Object {

                [Bool]$I3SCon2.ipv4.PSObject.Properties.Match("$_") | Should -Be $true

            }

        }

        It "Will create SPT Connection #3" {

            $Script:I3SCon3 = Get-HPOVNetwork -Name "MLAG VLAN 10" -ErrorAction Stop | New-HPOVServerProfileConnection -Name 'Connection 3' `
                -ConnectionID 3 `
                -ConnectionType Ethernet
                                                                                                                
        }

        It "Will create SPT Connection #4" {

            $Script:I3SCon4 = Get-HPOVNetwork -Name "MLAG VLAN 10" -ErrorAction Stop | New-HPOVServerProfileConnection -Name 'Connection 4' `
                -ConnectionID 4 `
                -ConnectionType Ethernet

        }

        It "Will validate Image Streamer exists" {

            { $Script:OSDeploymentServer = Get-HPOVOSDeploymentServer -Name $OSDeploymentServerName -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will get and validate OS Deployment Plan" -Skip:(-not $OSDeploymentServer) {

            { $Script:OSDeploymentPlan = Get-HPOVOSDeploymentPlan -Name $OSDeploymentPlanName -ErrorAction Stop } | Should -Not -Throw
            $OSDeploymentPlan.type | Should -Be Osdp

        }

        It "Will get and validate OS Deployment Plan Properties and object type" -Skip:(-not $OSDeploymentServer) {

            { $Script:OSDeploymentAttributes = Get-HPOVOSDeploymentPlanAttribute -InputObject $OSDeploymentPlan -ErrorAction Stop } | Should -Not -Throw

            $OSDeploymentAttributes | ForEach-Object {

                $_ | Should -BeOfType HPOneView.ServerProfile.OSDeployment.OSDeploymentParameter

            }

        }

        It "Will set OS Static NIC Deployment Attributes required for the OS Deployment Plan" {
            
            # NIC1
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.connectionid").value = 3
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.networkuri").value = $I3SCon3.networkUri
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.constraint").value = 'userspecified'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.netmask").value = '255.255.255.0'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.gateway").value = '192.168.19.1'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.dns1").value = '192.168.19.11'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.dns2").value = '192.168.19.12'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC1.dhcp").value = $false

            # NIC2
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.connectionid").value = 4
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.networkuri").value = $I3SCon4.networkUri
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.constraint").value = 'userspecified'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.netmask").value = '255.255.255.0'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.gateway").value = '192.168.19.1'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.dns1").value = '192.168.19.11'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.dns2").value = '192.168.19.12'
            ($script:OSDeploymentAttributes | Where-Object name -eq "NIC2.dhcp").value = $false

        }

        It "Will create Server Profile Template with Image Streamer" -Skip:(-not $OSDeploymentServer) {

            $ParamHash = @{
                
                Name                       = "$Synergyi3SSPTName-STATIC";
                ServerHardwareType         = $SY480cGen9SHT;
                EnclosureGroup             = $EnclosureGroup;
                Connections                = $I3SCon1, $I3SCon2, $I3SCon3, $I3SCon4;
                ManageBoot                 = $true;
                BootMode                   = 'UEFI';
                OSDeploymentPlan           = $OSDeploymentPlan;
                OSDeploymentPlanAttributes = $OSDeploymentAttributes
                
            }            
        
            { $Script:I3SSPTResults = New-HPOVServerProfileTemplate @ParamHash } | Should -Not -Throw

            if ($I3SSPTResults.taskState -ne "Completed")
            {

                DisplayTaskError $I3SSPTResults

            }

            $I3SSPTResults.taskState | Should -Be Completed

        }

        # Validate OSDeploymentSettings
        It "Will validate OS Deployment Settings -Exist within SPT" -Skip:(-not $OSDeploymentServer) {

            $SPT = Get-HPOVServerProfileTemplate -Name $Synergyi3SSPTName -ErrorAction Stop

            $SPT.osDeploymentSettings.osDeploymentPlanUri | Should -Be $OSDeploymentPlan.uri
            $SPT.osDeploymentSettings.osCustomAttributes | Should -Not -BeNullOrEmpty

        }

    }

    Context "HPE Synergy - Create ImageStreamer Server Profile Operations" {

        BeforeAll {

            if ($null -eq ($ConnectedSessions | Where-Object Name -eq $Appliance3)) 
            {
    
                { $Script:Connection3 = Connect-HPOVMgmt -Hostname $Appliance3 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
    
            }

            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance3).Default) {

                ($ConnectedSessions | Where-Object Name -eq $Appliance3) | Set-HPOVApplianceDefaultConnection
    
            }  

            Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

        }

        It "Will validate Server Profile Template exists" -Skip:(-not $OSDeploymentServer) {

            { $script:ImageStreamerSPTResource = Get-HPOVServerProfileTemplate -Name $Synergyi3SSPTName -ErrorAction Stop } | Should -Not -Throw

            $ImageStreamerSPTResource.category | Should -Be 'server-profile-templates'

        }

        It "Will validate OS Deployment Settings -Exist" -Skip:(-not $OSDeploymentServer) {

            $SPTOsDeploymentSettings = Get-HPOVOSDeploymentPlanAttribute -InputObject $ImageStreamerSPTResource
            $SPTOsDeploymentSettings | Should -Not -BeNullOrEmpty
            $SPTOsDeploymentSettings | Should -BeOfType HPOneView.ServerProfile.OSDeployment.OSDeploymentParameter

        } 

    }
    
    Context "Server Profile Lifecycle Operations" {

        BeforeAll {

            if ($null -eq ($ConnectedSessions | Where-Object Name -eq $Appliance1)) 
            {
    
                { $Script:Connection1 = Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential -LoginAcknowledge } | Should -Not -Throw 
    
            }

            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default) {

                ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection
    
            }

            Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow            

        }

        It "Will get '$AdvancedServerProfileName'" {

            { $script:ExistingServerProfile = Get-HPOVServerProfile -Name $AdvancedServerProfileName -ErrorAction Stop } | Should -Not -Throw

        }

        It "Will get shared storage volume" {

            { $script:SharedStorageVolume = Get-HPOVStorageVolume -Available | Where-Object isShareable | Select-Object -First 1 } | Should -Not -Throw

        }

        It "Will add shared storage volume to '$AdvancedServerProfileName' Server Profile" {

            { $script:ServerProfileModifiedObject = New-HPOVServerProfileAttachVolume -ServerProfile $script:ExistingServerProfile -Volume $SharedStorageVolume -HostOSType Win2k12 -PassThru } | Should -Not -Throw
           
        }

        It "Will validate 'ManageSANStorage' is set to True" {

            $ServerProfileModifiedObject.sanStorage.manageSanStorage | Should -Be $true

        }

        It "Will validate HostOSType has been set" {

            $ServerProfileModifiedObject.sanStorage.hostOSType | Should -Not -BeNullOrEmpty

        }

        It "WIll validate volume is attached" {

            $ServerProfileModifiedObject.sanStorage.volumeAttachments.Count | Should -Be 1
            $ServerProfileModifiedObject.sanStorage.volumeAttachments[0].volumeUri | Should -Be $SharedStorageVolume.uri

        }

        It "Will save Server Profile object" {

            { $script:SaveProfileResults = Save-HPOVServerProfile -InputObject $ServerProfileModifiedObject } | Should -Not -Throw

            $SaveProfileResults.category | Should -Be tasks

            if ($SaveProfileResults.taskState -ne "Completed") {

                DisplayTaskError $SaveProfileResults

            }

            $SaveProfileResults.taskState | Should -Be Completed

        }

    }

    Context "Remove Server Profile and Server Profile Template Resources Created" {

        It "Will remove '$SANAttachIscsiServerProfileName' Server Profile" {
        
            { $Script:RemoveResults = Get-HPOVServerProfile -Name $SANAttachIscsiServerProfileName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
        
            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }

            $RemoveResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$ServerProfileUnmanagedConnectionsName' Server Profile" {
        
            { $Script:RemoveResults = Get-HPOVServerProfile -Name $ServerProfileUnmanagedConnectionsName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
        
            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }

            $RemoveResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$BasicServerProfileName UnmanagedConnections Template' Server Profile Template resource" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfileTemplate -name "$BasicServerProfileName UnmanagedConnections Template" -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$ServerProfileScheduledFirmwareName' Server Profile" {
        
            { $Script:RemoveResults = Get-HPOVServerProfile -Name $ServerProfileScheduledFirmwareName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
        
            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }

            $RemoveResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$ServerProfileScheduledFirmwareName Template' Server Profile Template resource" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfileTemplate -name "$ServerProfileScheduledFirmwareName Template" -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$Dl360Gen9ServerProfileName' Server Profile" {
        
            { $Script:RemoveResults = Get-HPOVServerProfile -Name $Dl360Gen9ServerProfileName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
        
            if ($RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveResults

            }

            $RemoveResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$Dl360Gen9TemplateName' Server Profile Template resource" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfileTemplate -name $Dl360Gen9TemplateName -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$Dl360Gen9MLDTemplateName' Server Profile Template resource" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfileTemplate -name $Dl360Gen9MLDTemplateName -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$BasicServerProfileName' Server Profile resource" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfile -name $BasicServerProfileName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            if ($RemoveServerProfileResults.taskState -ne "Completed") {
                DisplayTaskError $RemoveServerProfileResults
            }
            $RemoveServerProfileResults.taskState | Should -Be Completed
        }

        It "Will remove '$IscsiServerProfileTemplateName' Server Profile resource" {

            { $Script:RemoveServerProfileResults = Get-HPOVServerProfileTemplate -name $IscsiServerProfileTemplateName -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed

        }

        It "Will remove '$BasicIscsiServerProfileName' Server Profile resource" {
            
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfile -name $BasicIscsiServerProfileName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$AdvancedServerProfileName' Server Profile resource" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfile -name $AdvancedServerProfileName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed
        
        }

        It "Will remove '$BfSAdvancedServerProfileName' Server Profile resource" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfile -name $BfSAdvancedServerProfileName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed

            { $Script:RemoveVolumeResults = Get-HPOVStorageVolume -Name "$BfSAdvancedServerProfileName Vol 2" -ErrorAction Stop | Remove-HPOVStorageVolume -Confirm:$false } | Should -Not -Throw

            if ($RemoveVolumeResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveVolumeResults

            }

            $RemoveVolumeResults.taskState | Should -Be Completed
        
        }

        It "Will remove copied 'Copy Of $AdvancedServerProfileName' Server Profile resource" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfile -name "Copy Of $AdvancedServerProfileName" -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed
        
        }

        It "Will remove cloned Server Profile Template 'Temporary Name - $($CopyOfServerProfileObject.name)'" {
        
            { $Script:RemoveClonedServerProfileTemplateResults = Get-HPOVServerProfileTemplate -Name "Temporary Name - $($CopyOfServerProfileObject.name)" -ErrorAction Stop | Remove-HPOVServerProfileTemplate -confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveClonedServerProfileTemplateResults.taskState | Should -Be Completed
        
        }

        It "Will remove created Basic Server Profile Template '$BasicServerProfileName Template' resource" {
        
            { $Script:Results = Get-HPOVServerProfileTemplate -Name "$BasicServerProfileName Template" -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 
            
            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed
        
        }

        It "Will attempt to remove created Advanced Server Profile Template '$AdvancedServerProfileName Template 2' as it still has an associated Profile" {
        
            { $Script:Results = Get-HPOVServerProfileTemplate -Name "$AdvancedServerProfileName Template 2" -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 
            $Results.taskState | Should -Be Error
            $Results.stateReason | Should -Be ValidationError
            $Results.taskErrors.message | Should -Be 'A server profile template cannot be deleted while it is being referenced by server profiles'
        
        }

        It "Will remove created Server Profile from Template $ServerProfileFromTemplateName" {

            { $Script:RemoveServerProfileResults = Get-HPOVServerProfile -name $ServerProfileFromTemplateName -ErrorAction Stop | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed            
        
        }

        It "Will remove created Advanced Server Profile Template '$AdvancedServerProfileName Template 2'" {
        
            { $Script:RemoveServerProfileTemplateResults = Get-HPOVServerProfileTemplate -Name "$AdvancedServerProfileName Template 2" -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 
            
            if ($RemoveServerProfileTemplateResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileTemplateResults

            }

            $RemoveServerProfileTemplateResults.taskState | Should -Be Completed
        
        }

        It "Will remove created Advanced Server Profile Template '$AdvancedServerProfileName Template 3'" {
        
            { $Script:RemoveServerProfileTemplateResults = Get-HPOVServerProfileTemplate -Name "$AdvancedServerProfileName Template 3" -ErrorAction Stop | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 
            
            if ($RemoveServerProfileTemplateResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileTemplateResults

            }

            $RemoveServerProfileTemplateResults.taskState | Should -Be Completed
        
        }

        It "Will remove SVT" {

            { Get-HPOVStorageVolumeTemplate -Name "$StorageVolumeTPDDName-SVT" -ErrorAction Stop | Remove-HPOVStorageVolumeTemplate -Confirm:$false } | Should -Not -Throw

        }

        It "Will remove HPE Synergy Server Profile '$SynergyServerProfileName'" {
        
            { $Script:RemoveServerProfileResults = Get-HPOVServerProfile -Name $SynergyServerProfileName -ErrorAction Stop -ApplianceConnection $Connection3  | Remove-HPOVServerProfile -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 
            
            if ($RemoveServerProfileResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileResults

            }

            $RemoveServerProfileResults.taskState | Should -Be Completed
        
        }

        It "Will remove HPE Synergy Server Profile Template '$SynergyServerProfileTemplateName'" {
        
            { $Script:RemoveServerProfileTemplateResults = Get-HPOVServerProfileTemplate -Name $SynergyServerProfileTemplateName -ErrorAction Stop -ApplianceConnection $Connection3 | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 
            
            if ($RemoveServerProfileTemplateResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveServerProfileTemplateResults

            }

            $RemoveServerProfileTemplateResults.taskState | Should -Be Completed
        
        }

        It "Will remove HPE Synergy Server Profile Templates '$Synergyi3SSPTName'" -Skip:(-not $OSDeploymentServer) {
        
            { $Script:RemoveServerProfileTemplateResults = Get-HPOVServerProfileTemplate -Name $Synergyi3SSPTName* -ErrorAction Stop -ApplianceConnection $Connection3 | Remove-HPOVServerProfileTemplate -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw 
            
            $RemoveServerProfileTemplateResults | ForEach-Object {

                if ($_.taskState -ne "Completed") {

                    DisplayTaskError $_

                }

                $_.taskState | Should -Be Completed

            }            
        
        }

    }

}

Describe "Cisco Fabric Extendor and Logical Switch Management" -Tag All, LogicalSwitch, Networking {

    BeforeAll {

        if (-not ($ConnectedSessions | Where-Object Name -eq $FexAppliance)) {

            { Connect-HPOVMgmt -Hostname $FexAppliance -Credential $AppliancePSCredential } | Should -Not -Throw

        }

        #Check if multiple connections and if '$FexAppliance' is not Default
        if (-not ($ConnectedSessions | Where-Object Name -eq $FexAppliance).Default)
        {

            ($ConnectedSessions | Where-Object Name -eq $FexAppliance) | Set-HPOVApplianceDefaultConnection

        }

        Microsoft.PowerShell.Utility\write-host ('Default Appliance Connection: {0}' -f ($ConnectedSessions | Where-Object Default ).Name) -ForegroundColor Yellow

    }

    AfterAll {

        { Disconnect-HPOVMgmt ($ConnectedSessions | Where-Object Name -eq $FexAppliance) -ErrorAction Stop } | Should -Not -Throw

    }

    Context "Create Cisco Fabric Extender LIG Policy" {

        It "Will Cisco FEX validate Interconnect Type" {

            { $Script:CiscoFEXInterconnectType = Get-HPOVInterconnectType -Name 'Cisco Fabric Extender for HP BladeSystem' -ErrorAction Stop } | Should -Not -Throw
            $CiscoFEXInterconnectType.category | Should -Be interconnect-types

        }

        It "Will create a Logical Interconnect Group with the Cisco Fabric Extender" {

            $FexLIGParams = @{

                Name = $CiscoFexLogicalInterconnectGroupName;
                Bays = @{ 1 = 'FEX'; 2 = 'FEX'}

            }            
   
            { $Script:Results = New-HPOVLogicalInterconnectGroup @FexLIGParams | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will add Uplink Set 1 to the LIG" {

            { $Script:Networks = Get-HPOVNetwork -Name VLAN* -ErrorAction Stop } | Should -Not -Throw
            
            { $Script:LIGObject = Get-HPOVLogicalInterconnectGroup -Name $CiscoFexLogicalInterconnectGroupName -ErrorAction Stop } | Should -Not -Throw

            $UplinkSetParamSplat = @{

                Resource         = $LIGObject;
                Name             = 'Uplink Set 1';
                Type             = 'Ethernet';
                Networks         = $Networks;
                UplinkPorts      = "Bay1:1","Bay1:2","Bay1:3","Bay1:4"

            }

            { $Script:Results = New-HPOVUplinkSet @UplinkSetParamSplat } | Should -Not -Throw
            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will add Uplink Set 2 to the LIG" {

            { $Script:Networks = Get-HPOVNetwork -Name VLAN* -ErrorAction Stop } | Should -Not -Throw
            
            { $Script:LIGObject = Get-HPOVLogicalInterconnectGroup -Name $CiscoFexLogicalInterconnectGroupName -ErrorAction Stop } | Should -Not -Throw

            $UplinkSetParamSplat = @{

                Resource         = $LIGObject;
                Name             = 'Uplink Set 2';
                Type             = 'Ethernet';
                Networks         = $Networks;
                UplinkPorts      = "Bay2:1","Bay2:2","Bay2:3","Bay2:4"

            }

            { $Script:Results = New-HPOVUplinkSet @UplinkSetParamSplat } | Should -Not -Throw
            $Results.category | Should -Be tasks

            if ($Results.taskState -ne "Completed") {

                DisplayTaskError $Results

            }

            $Results.taskState | Should -Be Completed

        }

        It "Will remote created LIG" {

            { $Script:RemoveLIGResults = Get-HPOVLogicalInterconnectGroup -Name $CiscoFexLogicalInterconnectGroupName -ErrorAction Stop | Remove-HPOVLogicalInterconnectGroup -Confirm:$false } | Should -Not -Throw

            if ($RemoveLIGResults.taskState -ne "Completed") {

                DisplayTaskError $RemoveLIGResults

            }

            $RemoveLIGResults.taskState | Should -Be 'Completed'

        }

    }

    Context "Create Logical Switch Groups for Nexus 56xx and 600x switch types" {

        It "Will retrieve all Switch Type resources" {

            { Get-HPOVSwitchType } | Should -Not -Throw

        }

        It "Will attempt invalid Switch Type with: -Name Foo" {

            { Get-HPOVSwitchType -Name 'Foo' } | Should -Throw ("No Switch Types with 'Foo' name were found on appliance {0}." -f $FexAppliance)
        
        }

        It "Will attempt invalid Switch Type with: -PartNumber Foo" {

            { Get-HPOVSwitchType -PartNumber 'Foo' } | Should -Throw ("No Switch Types with 'Foo' partnumber were found on appliance {0}." -f $FexAppliance)
        
        }

        It "Will get valid '$LogicalSwitchGroup1Type' switch type" {

            { $Script:LogicalSwitchGroup1SwitchType = Get-HPOVSwitchType -Name $LogicalSwitchGroup1Type } | Should -Not -Throw

            $LogicalSwitchGroup1SwitchType | Should -Not -BeNullOrEmpty
            $LogicalSwitchGroup1SwitchType.category | Should -Be 'switch-types'
            $LogicalSwitchGroup1SwitchType.type | Should -Be 'interconnect-typeV300'
            $LogicalSwitchGroup1SwitchType.uri | Should -Not -BeNullOrEmpty
            
        }

        It "Will attempt to create Logical Switch Group with invalid parameter: -SwitchType FooBar " {

            { New-HPOVLogicalSwitchGroup -Name 'Smoke Test1' -SwitchType FooBar -NumberOfSwitches 2 } | Should -Throw ("No Switch Types with 'FooBar' name were found on appliance {0}." -f $FexAppliance)

        }

        It "Will attempt to create Logical Switch Group with invalid parameter: -NumberOfSwitches 3" {

            { New-HPOVLogicalSwitchGroup -Name 'Smoke Test1' -SwitchType $LogicalSwitchGroup1SwitchType -NumberOfSwitches 3 } | Should -Throw "Cannot validate argument on parameter 'NumberOfSwitches'. The 3 argument is greater than the maximum allowed range of 2. Supply an argument that is less than or equal to 2 and then try the command again."
            
        }        

        It "Will create Logical Switch Group: $LogicalSwitchGroup1Name" {

            { $Global:LogicalSwitchGroup1Results = New-HPOVLogicalSwitchGroup -Name $LogicalSwitchGroup1Name -SwitchType $LogicalSwitchGroup1SwitchType -NumberOfSwitches 2 } | Should -Not -Throw

            $LogicalSwitchGroup1Results | Should -Not -BeNullOrEmpty
            $LogicalSwitchGroup1Results.category | Should -Be 'tasks'

            if ($LogicalSwitchGroup1Results.taskState -ne "Completed") {

                DisplayTaskError $LogicalSwitchGroup1Results

            }

            $LogicalSwitchGroup1Results.taskState | Should -Be 'Completed'

        }

        It "Will create Logical Switch Group: $LogicalSwitchGroup2Name" {

            { $Script:LogicalSwitchGroup2SwitchType = Get-HPOVSwitchType -Name $LogicalSwitchGroup2Type } | Should -Not -Throw

            { $Script:LogicalSwitchGroup2Results = New-HPOVLogicalSwitchGroup -Name $LogicalSwitchGroup2Name -SwitchType $LogicalSwitchGroup2SwitchType -NumberOfSwitches 2 } | Should -Not -Throw

            $LogicalSwitchGroup2Results | Should -Not -BeNullOrEmpty
            $LogicalSwitchGroup2Results.category | Should -Be 'tasks'

            if ($LogicalSwitchGroup2Results.taskState -ne "Completed") {

                DisplayTaskError $LogicalSwitchGroup2Results

            }

            $LogicalSwitchGroup2Results.taskState | Should -Be 'Completed'

        }

        It "Will retrieve all Logical Switch Groups" {

            { $Script:AllLogicalSwitchGroups = Get-HPOVLogicalSwitchGroup } | Should -Not -Throw

            $AllLogicalSwitchGroups | Should -Not -BeNullOrEmpty

        }

        It "Will retrieve Logical Switch Groups $LogicalSwitchGroup1Name and $LogicalSwitchGroup2Name using -Name parameter" {

            { Get-HPOVLogicalSwitchGroup -Name $LogicalSwitchGroup1Name } | Should -Not -Throw
            { Get-HPOVLogicalSwitchGroup -Name $LogicalSwitchGroup2Name } | Should -Not -Throw
            
        }

    }

    Context "Logical Switch Management" {

        it "Will create Monitored Logical Switch 1 (SNMPv1): $LogicalSwitch1Name" {
        
            $CreatedLogicalSwitchGroup1 = Get-HPOVLogicalSwitchGroup -Name $LogicalSwitchGroup1Name
        
            { $Script:CreatedLogicalSwitch1Results =  New-HPOVLogicalSwitch -Name $LogicalSwitch1Name -LogicalSwitchGroup $CreatedLogicalSwitchGroup1 -Monitored -Switch1Address $NexusSwitch1DCSIPv4Address -Switch2Address $NexusSwitch2DCSIPv4Address -SshUserName $NexusSwitchDcsSshUsername -SshPassword $NexusSwitchDcsSshPassword -Snmpv1 -SnmpCommunity $NexusSwitchDcsSnmpCommunityName | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($CreatedLogicalSwitch1Results.taskState -ne "Completed") {

                DisplayTaskError $CreatedLogicalSwitch1Results

            }

            $CreatedLogicalSwitch1Results.taskState | Should -Be Completed

            
        }

        it "Will create Managed Logical Switch 2 (SNMPv3): $LogicalSwitch2Name" {

            $CreatedLogicalSwitchGroup2 = Get-HPOVLogicalSwitchGroup -Name $LogicalSwitchGroup2Name

            { $Script:CreatedLogicalSwitch2Results = New-HPOVLogicalSwitch -Name $LogicalSwitch2Name -LogicalSwitchGroup $CreatedLogicalSwitchGroup2 -Managed -Switch1Address $NexusSwitch3DCSIPv4Address -Switch2Address $NexusSwitch4DCSIPv4Address -SshUserName $NexusSwitchDcsSshUsername -SshPassword $NexusSwitchDcsSshPassword -Snmpv3 -SnmpUserName $NexusSwitchSnmpv3Username -SnmpAuthLevel AuthAndPriv -SnmpAuthProtocol $NexusSwitchSnmpv3AuthProtocol -SnmpAuthPassword $NexusSwitchSnmpv3AuthPassword -SnmpPrivProtocol $NexusSwitchSnmpv3PrivProtocol -SnmpPrivPassword $NexusSwitchSnmpv3PrivPassword | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($CreatedLogicalSwitch2Results.taskState -ne "Completed") {

                DisplayTaskError $CreatedLogicalSwitch2Results

            }

            $CreatedLogicalSwitch2Results.taskState | Should -Be Completed


        }

        It "Will retrieve '$LogicalSwitch1Name' resource" {

            { Get-HPOVLogicalSwitch } | Should -Not -BeNullOrEmpty

            { $Script:LogicalSwitch1Object = Get-HPOVLogicalSwitch -Name $LogicalSwitch1Name -ErrorAction Stop } | Should -Not -Throw

            $LogicalSwitch1Object.category | Should -Be 'logical-switches'

        }

        It "Will retrieve '$LogicalSwitch2Name' resources" {

            { Get-HPOVLogicalSwitch } | Should -Not -BeNullOrEmpty
            
            { $Script:LogicalSwitch2Object = Get-HPOVLogicalSwitch -Name $LogicalSwitch2Name -ErrorAction Stop } | Should -Not -Throw

            $LogicalSwitch2Object.category | Should -Be 'logical-switches'

        }

        It "Will refresh '$LogicalSwitch1Name' state" {
        
            { $Script:RefreshLogicalSwitch1Results = Get-HPOVLogicalSwitch -Name $LogicalSwitch1Name -ErrorAction Stop | Update-HPOVLogicalSwitch -confirm:$false } | Should -Not -Throw
            $RefreshLogicalSwitch1Results | Should -Not -BeNullOrEmpty
            $RefreshLogicalSwitch1Results.category | Should -Be 'tasks'

            if ('Completed','Warning' -notcontains $RefreshLogicalSwitch1Results.taskState) {

                DisplayTaskError $RefreshLogicalSwitch1Results

            }

            'Completed','Warning' -contains $RefreshLogicalSwitch1Results.taskState | Should -Be $true
        
        }

    }

    Context "Switch Management" {

        It "Will attempt to get unknown Switch" {

            $ExpectedExceptionMessage = "Specified Switch 'foo' was not found on {0} appliance connection." -f $FexAppliance
            
            { Get-HPOVSwitch -name foo -ErrorAction Stop } | Should -Throw $ExpectedExceptionMessage

        }

        It "Will retrieve '$NexusSwitch1DCSIPv4Address' resource" {
        
            { $Script:Switch1ResourceObject = Get-HPOVSwitch -Name $NexusSwitch1DCSIPv4Address -ErrorAction Stop } | Should -Not -Throw
            $Switch1ResourceObject | Should -Not -BeNullOrEmpty
            $Switch1ResourceObject.category | Should -Be 'switches'
            $Switch1ResourceObject.state | Should -Be 'Monitored'
        
        }

        It "Will retrieve '$NexusSwitch2DCSIPv4Address' resource" {
        
            { $Script:Switch2ResourceObject = Get-HPOVSwitch -Name $NexusSwitch2DCSIPv4Address -ErrorAction Stop } | Should -Not -Throw
            $Switch2ResourceObject | Should -Not -BeNullOrEmpty
            $Switch2ResourceObject.category | Should -Be 'switches'
            $Switch2ResourceObject.state | Should -Be 'Monitored'
        
        }

        It "Will retrieve '$NexusSwitch3DCSIPv4Address' resource" {
        
            { $Script:Switch3ResourceObject = Get-HPOVSwitch -Name $NexusSwitch3DCSIPv4Address -ErrorAction Stop } | Should -Not -Throw
            $Switch3ResourceObject | Should -Not -BeNullOrEmpty
            $Switch3ResourceObject.category | Should -Be 'switches'
            $Switch3ResourceObject.state | Should -Be 'Configured'
        
        }

        It "Will retrieve '$NexusSwitch4DCSIPv4Address' resource" {
        
            { $Script:Switch4ResourceObject = Get-HPOVSwitch -Name $NexusSwitch4DCSIPv4Address -ErrorAction Stop } | Should -Not -Throw
            $Switch4ResourceObject | Should -Not -BeNullOrEmpty
            $Switch4ResourceObject.category | Should -Be 'switches'
            $Switch4ResourceObject.state | Should -Be 'Configured'
        
        }

    }

    Context "Remove Logical Switch Group and Logical Switch created resources" {

        It "Remove Logical Switch1 using parameter: $LogicalSwitch1Name" {

            { $Script:LogicalSwitch1RemoveResults = Remove-HPOVLogicalSwitch -InputObject $LogicalSwitch1Object -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ($LogicalSwitch1RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $LogicalSwitch1RemoveResults

            }

            $LogicalSwitch1RemoveResults.taskState | Should -Be Completed

        }

        It "Remove Logical Switch2 using pipeline: $LogicalSwitch2Name" {

            { $Script:LogicalSwitch2RemoveResults = Get-HPOVLogicalSwitch -Name $LogicalSwitch2Name -ErrorAction Stop | Remove-HPOVLogicalSwitch -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw

            if ("Completed", "Warning" -notcontains $LogicalSwitch2RemoveResults.taskState) {

                DisplayTaskError $LogicalSwitch2RemoveResults

            }

            "Completed", "Warning" -contains $LogicalSwitch2RemoveResults.taskState | Should -Be True

        }

        It "Remove Logical Switch Group1 using parameter: $LogicalSwitchGroup1Name" {

            $CreatedLogicalSwitchGroup1 = Get-HPOVLogicalSwitchGroup -Name $LogicalSwitchGroup1Name -ErrorAction Stop

            { $Script:LogicalSwitchGroup1RemoveResults = Remove-HPOVLogicalSwitchGroup -InputObject $CreatedLogicalSwitchGroup1 -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($LogicalSwitchGroup1RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $LogicalSwitchGroup1RemoveResults

            }

            $LogicalSwitchGroup1RemoveResults.taskState | Should -Be Completed

        }

        It "Remove Logical Switch Group2 using pipeline: $LogicalSwitchGroup2Name" {

            { $Script:LogicalSwitchGroup2RemoveResults = Get-HPOVLogicalSwitchGroup -Name $LogicalSwitchGroup2Name -ErrorAction Stop | Remove-HPOVLogicalSwitchGroup -Confirm:$false | Wait-HPOVTaskComplete } | Should -Not -Throw
            
            if ($LogicalSwitchGroup2RemoveResults.taskState -ne "Completed") {

                DisplayTaskError $LogicalSwitchGroup2RemoveResults

            }

            $LogicalSwitchGroup2RemoveResults.taskState | Should -Be Completed

        }

    }

}

Describe "Clean up any left over resources found on appliances" -Tag $Alltags {

    Context "Clean up $Appliance1" {

        BeforeAll {

            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1)) {

                { Connect-HPOVMgmt -Hostname $Appliance1 -Credential $AppliancePSCredential } | Should -Not -Throw

            }

            #Check if multiple connections and if '$Appliance1' is not Default
            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance1).Default)
            {

                ($ConnectedSessions | Where-Object Name -eq $Appliance1) | Set-HPOVApplianceDefaultConnection

            }

        }

        AfterAll {

            { Disconnect-HPOVMgmt ($ConnectedSessions | Where-Object Name -eq $Appliance1) -ErrorAction Stop } | Should -Not -Throw

        }

        { $Script:FoundResources = Send-HPOVRequest -Uri $CleanupIndexUri } | Should -Not -Throw

        if ($FoundResources.Count = 0) {

            Microsoft.PowerShell.Utility\write-host "Appliance $Appliance1 is clean." -ForegroundColor Yellow 

        }

        ForEach ($_member in $FoundResources.members) {

            $_ItText = "Will clean up resource: {0} [{1}]" -f $_member.name, $_member.category

            It $_ItText {

                { Send-HPOVRequest -Uri $_member.uri -Method DELETE } | Should -Not -Throw

            }           

        }        

    }

    Context "Clean up $Appliance2" {

        BeforeAll {

            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance2)) {

                { Connect-HPOVMgmt -Hostname $Appliance2 -Credential $AppliancePSCredential } | Should -Not -Throw

            }

            #Check if multiple connections and if '$Appliance2' is not Default
            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance2).Default)
            {

                ($ConnectedSessions | Where-Object Name -eq $Appliance2) | Set-HPOVApplianceDefaultConnection

            }

        }

        AfterAll {

            { Disconnect-HPOVMgmt ($ConnectedSessions | Where-Object Name -eq $Appliance2) -ErrorAction Stop } | Should -Not -Throw

        }

        if ($FoundResources.Count = 0) {

            Microsoft.PowerShell.Utility\write-host "Appliance $Appliance2 is clean." -ForegroundColor Yellow 

        }

        ForEach ($_member in $FoundResources.members) {

            $_ItText = "Will clean up resource: {0} [{1}]" -f $_member.name, $_member.category

            It $_ItText {

                { Send-HPOVRequest -Uri $_member.uri -Method DELETE } | Should -Not -Throw

            }           

        }    

    }

    Context "Clean up $Appliance3" {

        BeforeAll {

            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance3)) {

                { Connect-HPOVMgmt -Hostname $Appliance3 -Credential $AppliancePSCredential } | Should -Not -Throw

            }

            #Check if multiple connections and if '$Appliance2' is not Default
            if (-not ($ConnectedSessions | Where-Object Name -eq $Appliance3).Default)
            {

                ($ConnectedSessions | Where-Object Name -eq $Appliance3) | Set-HPOVApplianceDefaultConnection

            }

        }

        AfterAll {

            { Disconnect-HPOVMgmt ($ConnectedSessions | Where-Object Name -eq $Appliance3) -ErrorAction Stop } | Should -Not -Throw

        }

        { $Script:FoundResources = Send-HPOVRequest -Uri $CleanupIndexUri } | Should -Not -Throw

        ForEach ($_member in $FoundResources.members) {

            Microsoft.PowerShell.Utility\write-host ('Cleaning up resource: {0} [{1}]' -f $_member.name, $_member.category) -ForegroundColor Yellow 

            { Send-HPOVRequest -Uri $_member.uri -Method DELETE } | Should -Not -Throw

        }  

    }

    Context "Clean up $FexAppliance" {

        BeforeAll {

            if (-not ($ConnectedSessions | Where-Object Name -eq $FexAppliance)) {

                { Connect-HPOVMgmt -Hostname $FexAppliance -Credential $AppliancePSCredential } | Should -Not -Throw

            }

            #Check if multiple connections and if '$FexAppliance' is not Default
            if (-not ($ConnectedSessions | Where-Object Name -eq $FexAppliance).Default)
            {

                ($ConnectedSessions | Where-Object Name -eq $FexAppliance) | Set-HPOVApplianceDefaultConnection

            }

        }

        AfterAll {

            { Disconnect-HPOVMgmt ($ConnectedSessions | Where-Object Name -eq $FexAppliance) -ErrorAction Stop } | Should -Not -Throw

        }

        { $Script:FoundResources = Send-HPOVRequest -Uri $CleanupIndexUri } | Should -Not -Throw

        ForEach ($_member in $FoundResources.members) {

            Microsoft.PowerShell.Utility\write-host ('Cleaning up resource: {0} [{1}]' -f $_member.name, $_member.category) -ForegroundColor Yellow 

            { Send-HPOVRequest -Uri $_member.uri -Method DELETE } | Should -Not -Throw

        }  

    }

}

Describe "Tear down left over connections" -Tags $Alltags {

    $PSDefaultParameterValues = @{ 'It:Skip' = ($ConnectedSessions.Count -eq 0) }

    It 'Disconnect from remaining Appliances' {

        { Disconnect-HPOVMgmt $ConnectedSessions -ErrorAction Stop } | Should -Not -Throw

    }

}

Describe "Remove $LibraryModuleName Module from runtime and validate" -Tags $Alltags {

    It "Execute 'Remove-Module $LibraryModuleName'" {

        { Remove-Module $LibraryModuleName } | Should -Not -Throw

    }
    
    It "Validate Global parameters 'ConnectedSessions' and 'CallStack' module creates do not -Exist" {

        { Get-Variable -Name ConnectedSessions -ea stop } | Should -Throw "Cannot find a variable"
        { Get-Variable -Name CallStack -ea stop } | Should -Throw "Cannot find a variable"

    }

}