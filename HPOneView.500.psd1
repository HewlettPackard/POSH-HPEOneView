##############################################################################9
## (C) Copyright 2013-2020 Hewlett Packard Enterprise Development LP
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
    RootModule = 'HPOneView.500.psm1'

    # Version number of this module.
    ModuleVersion = '5.0.2368.2592'

    # ID used to uniquely identify this module
    GUID = '39a18995-ec04-422b-a972-1c4b3f8cebe7'

    # Author of this module
    Author = 'Hewlett-Packard Enterprise'

    # Company or vendor of this module
    CompanyName = 'Hewlett-Packard Enterprise'

    # Copyright statement for this module
    Copyright = '(C) Copyright 2013-2020 Hewlett-Packard Development Company, L.P.'

    # Description of the functionality provided by this module
    Description = 'HPE OneView PowerShell Library'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Minimum version of the .NET Framework required by this module
    DotNetFrameworkVersion = '4.7.2'

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = '4.0.30319.42000'

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @(@{ModuleName = 'FormatPX'; ModuleVersion = '1.1.3.15'},
    #                     @{ModuleName = 'SnippetPX'; ModuleVersion = '1.0.5.18'})

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @(
                          'lib\HPOneView_Classes.dll'
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
    # ModuleList = @('HPOneView.500.psm1')

    # List of all files packaged with this module
    FileList = @(
                'HPOneView.500.psd1',
                'HPOneView.500.psm1',
                'Appliance.format.ps1xml',
                'Cluster.format.ps1xml',
                'Networking.format.ps1xml',
                'Server.format.ps1xml',
                'Storage.format.ps1xml',
                'HPOneView.500_39a18995-ec04-422b-a972-1c4b3f8cebe7_HelpInfo.xml',
                'HPOneView.500_39a18995-ec04-422b-a972-1c4b3f8cebe7_ModuleInfo.xml',
                'en-US\about_Appliance_Connections.help.txt',
                'en-US\about_Appliance_Connection_Permissions.help.txt',
                'en-US\about_Two_Factor_Authentication.help.txt',
                'en-US\about_HPOneView.500.help.txt',
                'en-US\HPOneView.500.psm1-help.xml',
                'lib\HPOneView_Classes.dll',
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
            ReleaseNotes = "Release 5.00.2368.2592

* [#411] Fixed regression in Connect-HPOVMgmt where login message wasn't being displayed or honored.
* [#449] Fixed ConvertTo-HPOVPowerShellScript mishandling of OS Deployment custom attributes with Password.
* [#450] Enhanced ConvertTo-HPOVPowerShellScript to handle Ethernet and Fibre Channel networks, and Network Sets for OS Custom Attributes, instead of setting a Uri value that might not be valid for another appliance the script may be executed against.
* [#452] Enhanced New-HPOVNetworkSet and Set-HPOVNetworkSet to support Large VLAN type.
* [#460] Fixed incorrect handling of exception message within New-HPOVsnmpV3user.
* [#461] Fixed issue with -LockProvisionMode in New-HPOVStorageVolumeTemplate Cmdlet where provision mode was not locking.
* [#463] Changed how the library was handling the decryption of password SecureString values for MacOS and PowerShellCore 7.
* [#464] Fixed Get-HPOVDriveEnclosureInventory mishandling -Avilable parameter where all drives were returned, regardless if drive was allocated to a Logical JBOD or not.
* [#465] Fixed Update-HPOVLogicalEnclosureFirmware handling of a supplied Baseline.  Object type is now stongly typed to HPOneView.Appliance.Baseline class object from Get-HPOVBaseline.
* [#466] Fixed New-HPOVUplinkSet regression where uplink set trunking property is not set correctly for non-capable Virtual Connect fabric modules.
* [#467] Fixed -LocalStorageConsistencyChecking parameter within New-HPOVServerProfileTemplate Cmdlet not supporting 'Minimum' value.
* Online user documentation has been moved from the GitHub project Wiki site to Gitbook.io.  Offline user documentation has been updated to point to the new site."

        }

    }

}
