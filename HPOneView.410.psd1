##############################################################################9
## (C) Copyright 2013-2018 Hewlett Packard Enterprise Development LP 
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

@{
    
    # Script module or binary module file associated with this manifest
    RootModule = 'HPOneView.410.psm1'
    
    # Version number of this module.
    ModuleVersion = '4.10.1865.3905'
    
    # ID used to uniquely identify this module
    GUID = '2c99a71e-361b-4ec0-b168-060eac70561d'
    
    # Author of this module
    Author = 'Hewlett-Packard Enterprise'
    
    # Company or vendor of this module
    CompanyName = 'Hewlett-Packard Enterprise'
    
    # Copyright statement for this module
    Copyright = '(C) Copyright 2013-2018 Hewlett-Packard Development Company, L.P.'
    
    # Description of the functionality provided by this module
    Description = 'HPE OneView PowerShell Library'
    
    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '4.0'

    # Minimum version of the .NET Framework required by this module
	DotNetFrameworkVersion = '4.0'
    
    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = '4.0'
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(@{ModuleName = 'FormatPX'; ModuleVersion = '1.1.3.15'},
					    @{ModuleName = 'SnippetPX'; ModuleVersion = '1.0.5.18'})
    
    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @(
						  'lib\HPOneView_Classes.410.dll',
						  'lib\SysadminsLV.Asn1Parser.dll'
						  )
    
    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @(
						'Appliance.format.ps1xml',
						'Cluster.format.ps1xml',
						'Networking.format.ps1xml',
						'Server.format.ps1xml',
						'Storage.format.ps1xml'
						)

    
    # List of all modules packaged with this module
    # ModuleList = @('HPOneView.410.psm1')
    
    # List of all files packaged with this module
    FileList = @(
				'HPOneView.410.psd1',
				'HPOneView.410.psm1',
				'Appliance.format.ps1xml',
				'Cluster.format.ps1xml',
				'Networking.format.ps1xml',
				'Server.format.ps1xml',
				'Storage.format.ps1xml',
				'HPOneView.410_2c99a71e-361b-4ec0-b168-060eac70561d_HelpInfo.xml',
				'HPOneView.410_2c99a71e-361b-4ec0-b168-060eac70561d_ModuleInfo.xml',
				'en-US\about_Appliance_Connections.help.txt',
				'en-US\about_Appliance_Connection_Permissions.help.txt',
				'en-US\about_Two_Factor_Authentication.help.txt',
				'en-US\about_HPOneView.410.help.txt',
				'en-US\HPOneView.410.psm1-help.xml',
				'lib\HPOneView_Classes.410.dll',
				'lib\SysadminsLV.Asn1Parser.dll',
				'Samples\AddServers_Monitored_Sample.ps1',
				'Samples\AddStorageSystem_Sample.ps1',
				'Samples\Alerts_Sample.ps1',
				'Samples\ApplianceConfig_Sample.ps1',
				'Samples\Appliance_Backup_Sample.ps1',
				'Samples\CreateEnclosureGroup_Sample.ps1',
				'Samples\Configure_IIS_WebDav_ExternalRepo_Sample.ps1',
				'Samples\ConfigureRemoteSupport_Sample.ps1',
				'Samples\DefineLogicalInterconnectGroup_AA_VC_Sample.ps1',
				'Samples\DefineLogicalInterconnectGroup_Sample.ps1',
				'Samples\DefineNetworks_AA_VC_Sample.ps1',
				'Samples\DefineNetworks_Sample.ps1',
				'Samples\ImportEnclosure_Sample.ps1',
				'Samples\Server_Multiconnection_AA_VC_Sample.ps1',
				'Samples\Server_Multiconnection_Sample.ps1',
				'Samples\Server_Multiconnection_SAN_Storage_Sample.ps1',
				'Samples\Server_Profile_Template_Multiconnection_Sample.ps1',
				'Samples\Wipe_Appliance.ps1'
				)

    # HelpInfo URI of this module
    HelpInfoURI = 'http://hewlettpackard.github.io/POSH-HPOneView/UpdateHelp'
    
	PrivateData = @{
		PSData = @{
			Tags = 'Hewlett', 'Packard', 'Enterprise', 'HPE', 'HPOneView', 'HPEOneView', 'HPESynergy';
			LicenseUri = 'https://github.com/HewlettPackard/POSH-HPOneView/blob/master/LICENSE';
			ProjectUri = 'http://hewlettpackard.github.io/POSH-HPOneView';
			IconUri = '';
            ReleaseNotes = 'Release 4.10.1865.3905

* Updated New-HPOVServerProfile and New-HPOVServerProfileTemplate with -PassThru parameter, which will return the object back to the caller to modify it before creating it with Save-HPOVServerProfile or Save-HPOVServerProfileTemplate Cmdlets.
* [#372] Updated HostOSType parameters for New-HPOVServerProfile, New-HPOVServerProfileTemplate, and New-HPOVServerProfileAttachVolume Cmdlets.
* [#373] Fixed New-HPOVServerProfile where certain parameters were not mapped to the "SPT" ParameterSet.
* [#374] Fixed Show-HPOVFirmwareReport for server hardware where baseline firmware compliance was not being used correctly.
* [#375] Fixed incorrect call to generate error for unsupported remote support server hardware.
* [#361] Fixed Invoke-HPOVVcmMigration parameter regression that was supposed to be fixed in 4.10.1821.1567.
* Fixed Show-HPOVFirmwareReport where SAS interconnects were not reported.
* Fixed Get-HPOVInterconnect where SAS Interconnects were not part of the API call to index.
* Fixed Copy-HPOVServerProfile where server hardware validation was incorrectly being handled.
* Fixed New-HPOVServerProfile where server hardware validation was incorrectly being handled.
* Fixed New-HPOVServerProfileConnection where -VirtualFunctions parameter was not being honored correctly.
* Fixed New-HPOVSnmpConfiguration which was missing SNMPv3 configuration parameters.
* [#382] Fixed New-HPOVServerProfileTemplate where -BootMode $false would not set the appropriate values to unmanage settings.
* Updated New-HPOVServerProfile to make -AssignmentType a non-mandatory parameter, which now defaults to "Server".
* Added Cmdlets to get and set HPE Synergy Reserved VLAN Range; Get-HPOVReservedVlanRange, Set-HPOVReservedVlanRange'

		}

	}

}


