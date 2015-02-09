##############################################################################
# HP OneView PowerShell Library
##############################################################################
##############################################################################
## (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
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

<#
 Note: This library requires the following installed:
 Microsoft .NET Framework 4.0: http://go.microsoft.com/fwlink/?LinkID=212547 
 Windows PowerShell 3: http://www.microsoft.com/en-us/download/details.aspx?id=34595
#>

#Revision History
#------------------------------------------
<#
1.10.1193
     |  - Branch to HP OneView 1.10 Release.  NOTE:  This library version does not support older appliance versions.
     |  - Fixed New-HPOVProfile to check for Firmware and BIOS management for supported platforms.  Would erroneously error when neither -firmware or -bios were passed.
     |  - Fixed Remove-HPOV* cmdlets which did not handle -force switch parameter correctly.
     |  - Fixed New-HPOVUplinkSet and New-HPOVNetwork.
     |  - Fixed Download-File where HTTP stream compression was not handled, resulting in incorrectly written/downloaded files (backup, support dump and audit logs).
     |  - Fixed New-HPOVProfileConnection and the query to the Index when a Network Resource Name was provided.
     |  - Fixed Send-HPOVRequest where if the request was to bulk create resources (e.g. '?multiResource=true'), the cmdlet would endlessly loop and generate an 'Invalid JSON Primitive' error.
     |  - Updated throwing errors to provide a more consistent experience.
	 |  - Updated Send-HPOVRequest to allow for additional headers to be passed in order to support storage volume removal.
     |  - Updated New-HPOVProfile to attach Storage Volumes.
	 |  - Updated resource type revisions to support 1.10 (i.e. EnclosureGroupV2, etc.).
	 |  - Updated New-HPOVStorageSystem, added ports and domain processing.
     |  - Updated Get-HPOVUser to return user account objects, and included a Report switch to display account in a tabular format.
     |  - Updated Get-HPOVProfileConnectionList to display Network Name, and ordered by Connection ID instead of Physical Function (aka FlexNIC).
     |  - Updated Show-HPOVAppliance to return PSCustomObject instead of System.Array.
     |  - Updated Update-HPOVLogicalInterconnect to support Reapply LI configuration.
     |  - Added New-ErrorRecord to create a custom $PSCmd.ThrowTerminatingError() or $PSCmd.WriteError() process.
	 |  - Added Set-HPOVUser to update/modify user accounts with a native cmdlet.
     |  - Added Get/New/Update/Remove-HPOVStorageSystem.
	 |  - Added Get/New/Remove-HPOVStoragePool.
	 |  - Added Get/New/Remove-HPOVStorageVolumeTemplate.
	 |  - Added Get/Set-HPOVStorageVolumeTemplatePolicy.
	 |  - Added Get/New/Remove-HPOVStorageVolume.
     |  - Added Update-HPOVEnclosure.
     |  - Added New-HPOVProfileAttachVolume.
	 |  - Added support for tunneled/untagged networks to New-HPOVNetwork and New-HPOVUplinkSet.
     |  - Added Update-HPOVLogicalInterconnectFirmware.
     |  - Added Get-HPOVStorageVolumeTemplatePolicy and Set-HPOVStorageVolumeTemplatePolicy.
     |  - Added Stop-HPOVAppliance and Restart-HPOVAppliance.
     |  - Removed redundant returns from New-HPOVProfile.
     |  - Removed private Verify-Auth cmdlet from library.
	 |  - Removed calls to verify-auth as it no longer exists.
     |  - Renamed Set-HPOVAlertCleared to Clear-HPOVAlert.
------------------------------------------
1.10.1314
     |  - Fixed Send-HPOVRequest Pagination issue where Send-HPOVRequest would not continue to the nextPageUri value.
     |  - Fixed New-HPOVProfileAttachVolume where Manual LUN ID was not being added to the PsCustomObject resource.
     |  - Fixed Get-HPOVEnclosure where Server Profile name wasn't being displayed if -Report switch was used.
     |  - Fixed Set-HPOVApplianceNetworkConfig to support changed API properties, and added ipv6OverrideDhcpDns option.
     |  - Updated New-HPOVEnclosureGroup to support adding OA Configuration Script.
     |  - Updated Get-HPOVProfile to use the API to filter for resource name.
     |  - Updated Get-HPOVSpp to include SPP Name in search and to display the results in list format.
     |  - Updated New-HPOVNetwork to allow bulk network creation via HP OneView REST API.
     |  - Added updatable offline help system. This module now supports 'Update-Help -module HPOneView.110'.
     |  - Added detection of an existing HP OneView library loaded, and generate terminating error, preventing the library from loading.
     |  - Added Show-HPOVUserSession to display list of logged in users to the appliance.
------------------------------------------
1.10.1339
     |  - Fixed New-HPOVEnclosure where the logicalInterconnectGroupUri parameter was replaced with logicalInterconnectGroup, but no alias was added for backwards compatibility.
     |  - Fixed Set-HPOVInitialPassword where it would inadvertantly check for a valid user session to the API.
     |  - Fixed New-HPOVStorageSystem where after the initial connection task completed, a report would be generated showing the system details, including ports, and displaying the ports would cause a connection issue.
     |  - Fixed New-HPOVStorageSystem where if no ports were specified, identified "Actual Networks" were not being used to automatically place the Expected Network value, causing the storage system to be added with no Storage System Host Ports.
     |  - Fixed Upload-File internal function where the API compresses the response stream and the function wasn't handling it correctly.
     |  - Fixed Send-HPOVRequest where a "Method invocation failure because [System.Object[]] does not contain a method named 'op_Subtraction'" error when New-HPOVStoragePool would attempt to add multiple pools.
     |  - Fixed Installer where "What's New" was generating a "ShellExecuteEx failed: code 2" error when installing for All Users.
     |  - Fixed Get-HPOVTask where count woudl not return the specified number of tasks.
     |  - Fixed Remove-HPOVStoragePool if the storage system name was provided, an incorrect call to Get-HPOVStorageSystem was made causing a PowerShell parameter error.
     |  - Updated Unmanaged Pools list when executing Get-HPOVStorageSystem -Report.
     |  - Updated Get-HPOVTask to display non-hidden tasks only.
     |  - Updated Get-HPOVTask to display a list of tasks.
     |  - Added custom Exceptions to generate terminating errors for the library.
     |  - Added Show-HPOVLogicalInterconnectMacTable to display the MAC Table of Logical Interconnect resources.
------------------------------------------
1.10.1378
     |  - Fixed Remove-HPOVStorageVolume where it should have supported Confirm and WhatIf parameter options when attempting to delete a storage volume resource.
     |  - Fixed Upload-File internal function headers and how responses are returned once the file has been uploaded.
     |  - Fixed Install-HPOVUpdate where the appliance firmware update would not stage properly.
     |  - Fixed Copy-HPOVProfile where the wrong Exception class was being used to generate a terminating error during task validation.
     |  - Fixed New-HPOVNetworkSet UntaggedNetwork parameter, where if a PSCustomObject was provided, the URI value was casted as [System.Array] instead of [System.String].
     |  - Fixed Set-HPOVUser where the new password wasn't being set properly as part of the user resource.
     |  - Fixed and Renamed Set-HPOVRole (to Set-HPOVUserRole, cmdlet alias set to Set-HPOVRole) where roles were not being processed correctly.
     |  - Fixed Add-HPOVEnclosure where the caller would not be prompted if the enclosure was already managed by another manager (HP OneView or Virtual Connect Manager).
     |  - Fixed New-HPOVStorageVolume where if a Volume Template was provided, the volume would fail to create.
     |  - Updated Send-HPOVRequest to handle GZip decompression automatically via System.Net.HttpWebRequest.AutomaticDecompression property.
     |  - Updated Set-HPOVNetwork and Set-HPOVNetworkSet to provide more native features to update networks and network sets.
     |  - Added ConvertFrom-HTML internal helper function to convert HTML to text, which can then be displayed in the PowerShell console without using a Web Browser to display the HTML page (i.e. Appliance Update Release Notes.)
     |  - Added Wildcard Name support to Get-HPOVNetwork.
     |  - Added Wildcard Name support to Get-HPOVNetworkSet.
     |  - Added Wildcard Name support to Get-HPOVProfile.
     |  - Added Wildcard Name support to Get-HPOVServer.
     |  - Added Wildcard Name support to Get-HPOVStorageSystem.
     |  - Added Wildcard Name support to Get-HPOVStoragePool.
     |  - Added Wildcard Name support to Get-HPOVStorageVolume.
     |  - Added the ability to filter for unassigned Server Profiles in Get-HPOVProfile.
     |  - Added the ability to filter for Server Hardware without Server Profiles in Get-HPOVServer.
     |  - Added support for Server Profile alerts in Get-HPOVAlert.
     |  - Added Set-HPOVUserPassword to allow the current user to update/change their password.
     |  - Added Set-HPOVLdapGroup to modify the roles assigned to the directory group.
     |  - Renamed the following CMDLETs, and provided CMDLET alias to the original name: New-HPOVEnclosure -> Add-HPOVEnclosure, New-HPOVServer -> Add-HPOVServer, New-HPOVPowerDevice -> Add-HPOVPowerDevice, New-HPOVStorageSystem -> Add-HPOVStorageSystem, New-HPOVStoragePool -> Add-HPOVStoragePool, and New-HPOVSanManager -> Add-HPOVSanManager.
------------------------------------------
1.10.1415
     |  - Moved project repository to GitHub (https://github.com/HewlettPackard/POSH-HPOneView).
     |  - Fixed internal Download-File function where ContentLength wasn't being detected correctly.
     |  - Fixed Get-HPOVServer where wildcard search wasn't correct.
     |  - Fixed New-HPOVProfile where -ServerHardwareType parameter wasn't being handled correctly.
     |  - Fixed Get-HPOVNetwork where specifying a FC network name would return zero results, even though the network existed.
     |  - Fixed Wait-HPOVApplianceStart where the appliance web services needed an additional few seconds to finish their init.
     |  - Fixed Add-HPOVEnclosure where if the enclosure is already managed by another external manager, the method to resolve the IP Address to FQDN could fail if a valid DNS name is not returned.
	 |  - Added Detailed switch to display detailed BIOS and Connection detail to Get-HPOVProfile.
------------------------------------------
1.10.1432
     |  - Fixed New-HPOVProfile where attempting to attach SAN Storage would fail due to API lookup error.
     |  - Fixed New-HPOVProfile where firmware baseline URI was printed to the screen causing the callers variable to store the task object to become a System.Array type.
     |  - Fixed New-HPOVLogicalInterconnectGroup to add -EnablePauseFloodProtection parameter.
     |  - Fixed New-HPOVBackup where backup file would not download.
     |  - Updated New-HPOVStorageVolume to allow the Storage Pool to be passed via pipeline instead of Storage Volume Template.
     |  - Added new parameters to Get-HPOVVersion; -CheckOnline and -ReleaseNotes. CheckOnline will check for newer library version on GitHub, and ReleaseNotes will display the found update's Release Notes.
     |  - Added Add-HPOVStorageVolume cmdlet to help import an existing volume from a managed storage system.
------------------------------------------
1.10.1447.1
     |  - Fixed New-HPOVUplinkSet where FibreChannel Uplink Set objects were not being created with uplink ports (logicalPortConfigInfos).
     |  - Fixed Connect-HPOVMgmt to trap HTTP 401 Unauthorized request to get appliance roles after successfully connecting to appliance when user has insufficient privileges.
     |  - Fixed Remove-HPOVNetwork pipeline input.
     |  - Fixed New-HPOVNetwork where ManagedSAN object wasn't included in the createFC Fabric Attach network request.
     |  - Updated New-HPOVBackup to increase the timeout waiting for the create backup file async task to complete.
     |  - Updated Send-HPOVRequest to generate terminating error for HTTP 401 Insufficient Privileges and not just for invalid session.
------------------------------------------
1.10.1476
     |  - Fixed Install-HPOVUpdate where it wasn't checking for a pending update when the -Update switch was used.
     |  - Fixed Install-HPOVUpdate where Write-Progress was causing an error, even though the update would complete.
     |  - Fixed Upload-File error handling from appliance generated 40x/50x status code.
     |  - Updated Add-HPOVPowerDevice to provide a native CMDLET Should Process/Continue prompt and use the -confirm/-whatif common parameters.
     |  - Updated Get-HPOVEnclosure, Get-HPOVNetwork, Get-HPOVPowerDevice, and Get-HPOVRole to return consistent results when -Name parameter is provided and no results were found which generates a terminating error.
#>

#Set HPOneView POSH Library Version
#Increment 3rd string by taking todays day (e.g. 23) and hour in 24hr format (e.g. 14), and adding to the prior value.
$script:scriptVersion = "1.10.1476"

#Check to see if another module is loaded in the console, but allow Import-Module to process normally if user specifies the same module name
if ($(get-module -name HPOneView*) -and (-not $(get-module -name HPOneView* | % { $_.name -eq "HPOneView.110"}))) { 

    write-Host "CRITICAL:  Another HP OneView module is already loaded:  "  -ForegroundColor Yellow -BackgroundColor Black 
    Write-Host "  |"  -ForegroundColor Yellow -BackgroundColor Black 
    get-module -name HPOneView* | % { write-host "  |--> $($_.name) ($($_.Version))"  -ForegroundColor Yellow -BackgroundColor Black }
    write-host ""

    [System.String]$Exception = 'InvalidOperationException'
    [System.String]$ErrorId = 'CannotLoadMultipleLibraries'
    [System.Object]$TargetObject = 'Import-Module HPOneView.110'
    [System.Management.Automation.ErrorCategory]$ErrorCategory = 'ResourceExists'
    [System.String]$Message = 'Another HP OneView module is already loaded.  The HP OneView PowerShell library does not support loading multiple versions of libraries within the same console.'
    
    $_exception = New-Object $Exception $Message
    $errorRecord = New-Object Management.Automation.ErrorRecord $_exception, $ErrorID, $ErrorCategory, $TargetObject
    throw $errorRecord

}

#If the PKI.HPOneView.SslCertificate Class is not currently loaded, load it
#This is to fix a limitation in the .Net CLR, where PowerShell maintains a single AppDomain context. Custom Classes loaded cannot be unloaded without
#terminating the existing PowerShell console session.
if (! ("HPOneView.PKI.SslCertificate" -as [type])) {

    add-type @"
    using System;
    using System.Collections;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;


    // Namespace PKI.HPOneView used for SSL Certificate handling
    namespace HPOneView 
	{
	    namespace PKI 
		{
		    public class SslCertificate 
			{
			    public Uri OriginalURi;
			    public Uri ReturnedURi;
			    public X509Certificate2 Certificate;
			    public string Issuer;
			    public string Subject;
			    public string[] SubjectAlternativeNames;
			    public bool CertificateIsValid;
			    public string[] ErrorInformation;
			    public HttpWebResponse Response;
		    }
	    }

        namespace Library
        {

            public class UpdateConnectionError : Exception
            {

                public UpdateConnectionError() : base() { }
                public UpdateConnectionError(string message) : base(message) { }
                public UpdateConnectionError(string message, Exception e) : base(message, e) { }


                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
            }

            public class TooNew : Exception
            {

                public TooNew() : base() { }
                public TooNew(string message) : base(message) { }
                public TooNew(string message, Exception e) : base(message, e) { }


                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
            }


        }
		
        namespace Appliance 
        {

            public class NetworkConnectionException : Exception
            {

                public NetworkConnectionException() : base() { }
                public NetworkConnectionException(string message) : base(message) { }
                public NetworkConnectionException(string message, Exception e) : base(message, e) { }


                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
            }

            public class NetworkConfigurationException : Exception
            {

                public NetworkConfigurationException() : base() { }
                public NetworkConfigurationException(string message) : base(message) { }
                public NetworkConfigurationException(string message, Exception e) : base(message, e) { }


                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
            }

            public class FirmwareUpdateException : Exception
            {

                public FirmwareUpdateException() : base() { }
                public FirmwareUpdateException(string message) : base(message) { }
                public FirmwareUpdateException(string message, Exception e) : base(message, e) { }

                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }

            }

            public class TaskValidationError : Exception
	        {

                public TaskValidationError() : base() { }
                public TaskValidationError(string message) : base(message) { }
                public TaskValidationError(string message, Exception e) : base(message, e) { }

                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
    
	        }
		
	        public class AuthSessionException : Exception
	        {

                public AuthSessionException() : base() { }
                public AuthSessionException(string message) : base(message) { }
                public AuthSessionException(string message, Exception e) : base(message, e) { }

                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
    
	        }

	        public class AuthPrivilegeException : Exception
	        {

                public AuthPrivilegeException() : base() { }
                public AuthPrivilegeException(string message) : base(message) { }
                public AuthPrivilegeException(string message, Exception e) : base(message, e) { }

                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
    
	        }
		
	        public class PasswordMismatch : Exception
	        {

                public PasswordMismatch() : base() { }
                public PasswordMismatch(string message) : base(message) { }
                public PasswordMismatch(string message, Exception e) : base(message, e) { }

                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
    
	        }

            public class UserResourceException : Exception
	        {

                public UserResourceException() : base() { }
                public UserResourceException(string message) : base(message) { }
                public UserResourceException(string message, Exception e) : base(message, e) { }

                private string strExtraInfo;
                public string ExtraErrorInfo
                {
                    get
                    {
                        return strExtraInfo;
                    }

                    set
                    {
                        strExtraInfo = value;
                    }
                }
    
	        }


        }      

        public class EnclosureResourceException : Exception
        {

            public EnclosureResourceException() : base() { }
            public EnclosureResourceException(string message) : base(message) { }
            public EnclosureResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }

        public class EnclosureGroupResourceException : Exception
        {

            public EnclosureGroupResourceException() : base() { }
            public EnclosureGroupResourceException(string message) : base(message) { }
            public EnclosureGroupResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }

        public class BaselineResourceException : Exception
        {

            public BaselineResourceException() : base() { }
            public BaselineResourceException(string message) : base(message) { }
            public BaselineResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }
	
        public class NetworkResourceException : Exception
        {

            public NetworkResourceException() : base() { }
            public NetworkResourceException(string message) : base(message) { }
            public NetworkResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }

        public class LogicalInterconnectGroupResourceException : Exception
        {

            public LogicalInterconnectGroupResourceException() : base() { }
            public LogicalInterconnectGroupResourceException(string message) : base(message) { }
            public LogicalInterconnectGroupResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }

        public class UplinkSetResourceException : Exception
        {

            public UplinkSetResourceException() : base() { }
            public UplinkSetResourceException(string message) : base(message) { }
            public UplinkSetResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }

        public class ServerHardwareResourceException : Exception
        {

            public ServerHardwareResourceException() : base() { }
            public ServerHardwareResourceException(string message) : base(message) { }
            public ServerHardwareResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }

	    public class StorageSystemResourceException : Exception
        {

            public StorageSystemResourceException() : base() { }
            public StorageSystemResourceException(string message) : base(message) { }
            public StorageSystemResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }
	
	    public class ServerProfileResourceException : Exception
        {

            public ServerProfileResourceException() : base() { }
            public ServerProfileResourceException(string message) : base(message) { }
            public ServerProfileResourceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }
        
	    public class ServerProfileConnectionException : Exception
        {

            public ServerProfileConnectionException() : base() { }
            public ServerProfileConnectionException(string message) : base(message) { }
            public ServerProfileConnectionException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }
        
        public class PowerDeliveryDeviceException : Exception
        {

            public PowerDeliveryDeviceException() : base() { }
            public PowerDeliveryDeviceException(string message) : base(message) { }
            public PowerDeliveryDeviceException(string message, Exception e) : base(message, e) { }

            private string strExtraInfo;
            public string ExtraErrorInfo
            {
                get
                {
                    return strExtraInfo;
                }

                set
                {
                    strExtraInfo = value;
                }
            }
        }        	

        //Define the [System.Net.ServicePointManager]::CertificatePolicy for the library
        public class HPOneViewIgnoreCertPolicy : ICertificatePolicy {
            public HPOneViewIgnoreCertPolicy() {}
            public bool CheckValidationResult(
	            ServicePoint sPoint, X509Certificate cert,
	            WebRequest wRequest, int certProb) 
                {
		            return true;
	            }
        }

    }


"@
}

$debugMode = $False

#Note: Set $debugPreference to control debug logging
If ($debugmode) {
    $debugPreference = "Continue"         # Display requests and responses
    $VerbosePreference = "Continue" 
}
#Else{ $debugPreference = "SilentlyContinue" } # Hide debug messages

$script:HPOneViewAppliance = $null
$global:cimgmtSessionId = $null
$script:lastWebResponse = $null
$script:defaultTimeout = New-TimeSpan -Minutes 20
[MidpointRounding]$script:mathMode = 'AwayFromZero' 
$script:MaxXAPIVersion = "101"
$script:applMinVersion = "100"
$script:applianceConnectedTo = @{User = "None"; Appliance = "Not connected"}
$script:repository = "https://api.github.com/repos/HewlettPackard/POSH-HPOneView/releases"

# Default handle self-signed certs
$script:SSLCheckFlag = $False

#------------------------------------
# Appliance Configuration
#------------------------------------
$script:applEulaStatus = "/rest/appliance/eula/status"
$script:applEulaSave = "/rest/appliance/eula/save"
$script:applConfigUri = "/rest/appliance/network-interfaces"
$script:applGlobalSettingsUri = "/rest/global-settings"
$script:applXApiVersion = "/rest/version"
$script:applMacAddresses = "/rest/appliance/network-interfaces/mac-addresses"
$script:applBackup = "/rest/backups"
$script:applRestoreFile = "/rest/backups/archive"
$script:applRestore = "/rest/restore"
$script:applVersion = "/rest/appliance/version"
$script:applSupportDump = "/rest/appliance/support-dumps"
$script:applHealthStatus = "/rest/appliance/health-status"
$script:applRabbitmqUri = "/rest/certificates/client/rabbitmq"
$script:applKeypairUri = "/rest/certificates/client/rabbitmq/keypair/default"
$script:applCaUri = "/rest/certificates/ca"
$script:applUpdate = "/rest/appliance/firmware/image"
$script:applUpdatePending = "/rest/appliance/firmware/pending"
$script:applUpdateNotification = "/rest/appliance/firmware/notification"
$script:applUpdateMonitor = "/cgi-bin/status/update-status.cgi"
$script:applSnmpReadCommunity = "/rest/appliance/device-read-community-string"
$script:applianceRebootUri = '/rest/appliance/shutdown?type=REBOOT'
$script:applianceShutDownUri = '/rest/appliance/shutdown?type=HALT'
$script:applianceDebugLogSetting = '/logs/rest/debug'
#------------------------------------
# Physical Resource Management
#------------------------------------
$script:serversUri = "/rest/server-hardware"
$script:serverListUri = "/rest/server-hardware?start=0&count=-1"
$script:serverHardwareTypesUri = "/rest/server-hardware-types"
$script:storageSystemUri = "/rest/storage-systems"
$script:storageVolumeUri = "/rest/storage-volumes"
$script:attachableVolumesUri = '/rest/storage-volumes/attachable-volumes'
$script:storageVolumeTemplateUri = "/rest/storage-volume-templates"
$script:storagePoolUri = "/rest/storage-pools"
$script:fcSanManagerProvidersUri = "/rest/fc-sans/providers"  #list available SAN Manager plugins, and create SAN Manager
$script:fcSanManagersUri = "/rest/fc-sans/device-managers" #created SAN Managers
$script:fcManagedSansUri = "/rest/fc-sans/managed-sans" #Discovered managed SAN(s) that the added SAN Manager will manage
$script:enclosuresUri = "/rest/enclosures"
$script:enclosureGroupsUri = "/rest/enclosure-groups"
$script:enclosurePreviewUri = "/rest/enclosure-preview"
$script:fwUploadUri = "/rest/firmware-bundles"
$script:fwDriversUri = "/rest/firmware-drivers"
$script:powerDevicesUri = "/rest/power-devices"
$script:powerDevicesDiscoveryUri = "/rest/power-devices/discover"
$script:unmanagedDevicesUri = "/rest/unmanaged-devices"
$script:mpModelTable = [pscustomobject]@{ilo2 = "RI7";ilo3 = "RI9";ilo4 = "RI10"}
#------------------------------------
# Network Resource Management
#------------------------------------
$script:networkSetsUri = "/rest/network-sets"
$script:ethNetworksUri = "/rest/ethernet-networks"
$script:fcNetworksUri = "/rest/fc-networks"
$script:connectionTemplatesUri = "/rest/connection-templates"
$script:logicalInterconnectGroupsUri = "/rest/logical-interconnect-groups"
$script:logicalInterconnectsUri = "/rest/logical-interconnects"
$script:interconnectsUri = "/rest/interconnects"
$script:interconnectTypesUri = "/rest/interconnect-types"
$script:interconnectListUri = "/rest/interconnects?start=0&count=-1"
$script:uplinkSetsUri = "/rest/uplink-sets"
$script:logicalDownlinksUri = "/rest/logical-downlinks"
$script:applVmacPoolsUri = "/rest/id-pools/vmac"
$script:applVmacPoolRangesUri = "/rest/id-pools/vmac/ranges"
$script:applVwwnPoolsUri = "/rest/id-pools/vwwn"
$script:applVwwnPoolRangesUri = "/rest/id-pools/vwwn/ranges"
$script:applVsnPoolsUri = "/rest/id-pools/vsn"
$script:applVsnPoolRangesUri = "/rest/id-pools/vsn/ranges"
$script:applVmacGenerateUri = "/rest/id-pools/vmac/generate"
$script:applVwwnGenerateUri = "/rest/id-pools/vwwn/generate"
$script:applVsnPoolGenerateUri = "/rest/id-pools/vsn/generate"
$script:macAddressPattern = @('^([0-9a-f]{2}:){5}([0-9a-f]{2})$')
$script:wwnAddressPattern = @('^([0-9a-f]{2}:){7}([0-9a-f]{2})$')
[regex]$script:ip4regex="\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
[Hashtable]$script:getUplinkSetPortSpeeds = @{
    Speed_0M = "0";
    Speed_100M = "100Mb";
    Speed_10G = "10Gb";
    Speed_10M = "10Mb";
    Speed_1G = "1Gb";
    Speed_1M = "1Mb";
    Speed_20G = "20Gb";
    Speed_2G = "2Gb";
    Speed_2_5G = "2.5Gb";
    Speed_40G = "40Gb";
    Speed_4G = "4Gb";
    Speed_8G = "8Gb";
    Auto = "Auto"
}

[Hashtable]$script:SetUplinkSetPortSpeeds = @{
    '0' = "Speed_0M";
    '100M' = "Speed_100M";
    '10G' = "Speed_10G";
    '10M' = "Speed_10M";
    '1G' = "Speed_1G";
    '1M' = "Speed_1M";
    '20G' = "Speed_20G";
    '2G' = "Speed_2G";
    '2' = "Speed_2G";
    '2.5G' = "Speed_2_5G";
    '40G' = "Speed_40G";
    '4G' ="Speed_4G";
    '8G' = "Speed_8G";
    '4' ="Speed_4G";
    '8' = "Speed_8G";
    'Auto' = "Auto"
}
#------------------------------------
#  Profile Management
#------------------------------------
$script:profilesUri = "/rest/server-profiles"
$script:profileListUri = "/rest/server-profiles?start=0&count=250"
$script:profileIndexListUri = "/rest/index/resources?sort=name:asc&category=server-profiles"
$script:profileAvailStorageSystemsUri = '/rest/server-profiles/available-storage-systems'
[pscustomobject]$script:profileSanManageOSType = @{
    CitrixXen = "Citrix Xen Server 5.x/6.x";
    AIX = "AIX";
    IBMVIO = "IBM VIO Server";
    RHEL4= "RHE Linux (Pre RHEL 5)";
    RHEL3= "RHE Linux (Pre RHEL 5)";
    RHEL = "RHE Linux (5.x, 6.x)";
    RHEV = "RHE Virtualization (5.x, 6.x)";
    VMware = "ESX 4.x/5.x";
    Win2k3 = "Windows 2003";
    Win2k8 = "Windows 2008/2008 R2";
    Win2k12 = "Windows 2012 / WS2012 R2";
    OpenVMS = "OpenVMS";
    Egenera = "Egenera";
    Exanet = "Exanet";
    Solaris9 = "Solaris 9/10";
    Solaris10="Solaris 9/10";
    Solaris11 = "Solaris 11";
    ONTAP = "NetApp/ONTAP";
    OEL = "OE Linux UEK (5.x, 6.x)";
    HPUX11iv1 = "HP-UX (11i v1, 11i v2)"
    HPUX11iv2 = "HP-UX (11i v1, 11i v2)";
    HPUX11iv3 = "HP-UX (11i v3)";
    SUSE ="SuSE (10.x, 11.x)";
    SUSE9 = "SuSE Linux (Pre SLES 10)";
    Inform = "InForm"
}
#------------------------------------
#  Index Search
#------------------------------------
$script:indexUri = "/rest/index/resources" 
$script:associationsUri = "/rest/index/associations"
$script:associationTreesUri = "/rest/index/trees"
#------------------------------------
#  Tasks
#------------------------------------
$script:allNonHiddenTaskUri = "/rest/tasks?filter=hidden=$false"
$script:taskUri = "/rest/tasks"
#------------------------------------
#  Alerts and Events
#------------------------------------
$script:alertsUri = "/rest/alerts"
$script:eventsUri = "/rest/events"
#------------------------------------
#  Licenses
#------------------------------------
$script:licensesUri = "/rest/licenses"
#------------------------------------
#  Security
#------------------------------------
$script:loginSessionsUri = "/rest/login-sessions"
$script:activeUserSessionsUri = '/rest/active-user-sessions'
$script:usersUri = "/rest/users"
$script:userRoleUri = "/rest/users/role"
$script:authnProvidersUri = "/rest/logindomains"
$script:authnProviderValidator = "/rest/logindomains/validator"
$script:authnSettingsUri = "/rest/logindomains/global-settings"
$script:authnDirectoryGroups = "/rest/logindomains/groups"
$script:authnEgroupRoleMappingUri = "/rest/logindomains/grouptorolemapping"
$script:applAuditLog = "/rest/audit-logs/download"

#######################################################
# Basic Support Functions
#

function New-ErrorRecord {

    <#  
    .Synopsis
    Creates an custom ErrorRecord that can be used to report a terminating or non-terminating error.  
    
    .Description
    Creates an custom ErrorRecord that can be used to report a terminating or non-terminating error.  
    
    .Parameter Exception      
    The Exception that will be associated with the ErrorRecord. 
     
    .Parameter ErrorID      
    A scripter-defined identifier of the error. This identifier must be a non-localized string for a specific error type.  
    
    .Parameter ErrorCategory      
    An ErrorCategory enumeration that defines the category of the error.  The supported Category Members are (from: http://msdn.microsoft.com/en-us/library/system.management.automation.errorcategory(v=vs.85).aspx) :
        
        • AuthenticationError - An error that occurs when the user cannot be authenticated by the service. This could mean that the credentials are invalid or that the authentication system is not functioning properly. 
        • CloseError - An error that occurs during closing. 
        • ConnectionError - An error that occurs when a network connection that the operation depends on cannot be established or maintained. 
        • DeadlockDetected - An error that occurs when a deadlock is detected. 
        • DeviceError - An error that occurs when a device reports an error. 
        • FromStdErr - An error that occurs when a non-Windows PowerShell command reports an error to its STDERR pipe. 
        • InvalidArgument - An error that occurs when an argument that is not valid is specified. 
        • InvalidData - An error that occurs when data that is not valid is specified. 
        • InvalidOperation - An error that occurs when an operation that is not valid is requested. 
        • InvalidResult - An error that occurs when a result that is not valid is returned. 
        • InvalidType - An error that occurs when a .NET Framework type that is not valid is specified. 
        • LimitsExceeded - An error that occurs when internal limits prevent the operation from being executed. 
        • MetadataError - An error that occurs when metadata contains an error.  
        • NotEnabled - An error that occurs when the operation attempts to use functionality that is currently disabled. 
        • NotImplemented - An error that occurs when a referenced application programming interface (API) is not implemented. 
        • NotInstalled - An error that occurs when an item is not installed. 
        • NotSpecified - An unspecified error. Use only when not enough is known about the error to assign it to another error category. Avoid using this category if you have any information about the error, even if that information is incomplete. 
        • ObjectNotFound - An error that occurs when an object cannot be found. 
        • OpenError - An error that occurs during opening. 
        • OperationStopped - An error that occurs when an operation has stopped. For example, the user interrupts the operation. 
        • OperationTimeout - An error that occurs when an operation has exceeded its timeout limit. 
        • ParserError - An error that occurs when a parser encounters an error. 
        • PermissionDenied - An error that occurs when an operation is not permitted. 
        • ProtocolError An error that occurs when the contract of a protocol is not being followed. This error should not happen with well-behaved components. 
        • QuotaExceeded An error that occurs when controls on the use of traffic or resources prevent the operation from being executed. 
        • ReadError An error that occurs during reading. 
        • ResourceBusy An error that occurs when a resource is busy. 
        • ResourceExists An error that occurs when a resource already exists. 
        • ResourceUnavailable An error that occurs when a resource is unavailable. 
        • SecurityError An error that occurs when a security violation occurs. This field is introduced in Windows PowerShell 2.0. 
        • SyntaxError An error that occurs when a command is syntactically incorrect. 
        • WriteError An error that occurs during writing. 
    
    .Parameter TargetObject      
    The object that was being processed when the error took place.  
    
    .Parameter Message      
    Describes the Exception to the user.  
    
    .Parameter InnerException      
    The Exception instance that caused the Exception association with the ErrorRecord.  
    
    .Example     
     #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$Exception,

        [Parameter(Mandatory = $true, Position = 1)]
        [Alias('ID')]
        [System.String]$ErrorId,

        [Parameter(Mandatory = $true, Position = 2)]
        [Alias('Category')]
        [ValidateSet('AuthenticationError','NotSpecified', 'OpenError', 'CloseError', 'DeviceError',
            'DeadlockDetected', 'InvalidArgument', 'InvalidData', 'InvalidOperation',
                'InvalidResult', 'InvalidType', 'MetadataError', 'NotImplemented',
                    'NotInstalled', 'ObjectNotFound', 'OperationStopped', 'OperationTimeout',
                        'SyntaxError', 'ParserError', 'PermissionDenied', 'ResourceBusy',
                            'ResourceExists', 'ResourceUnavailable', 'ReadError', 'WriteError',
                                'FromStdErr', 'SecurityError')]
        [System.Management.Automation.ErrorCategory]$ErrorCategory,

        [Parameter(Mandatory = $true, Position = 3)]
        [System.Object]$TargetObject,

        [Parameter()]
        [System.String]$Message,

        [Parameter()]
        [System.Exception]$InnerException
    )

    process {

        # ...build and save the new Exception depending on present arguments, if it...
        $_exception = if ($Message -and $InnerException) {
            # ...includes a custom message and an inner exception
            New-Object $Exception $Message, $InnerException
        } elseif ($Message) {
            # ...includes a custom message only
            New-Object $Exception $Message
        } else {
            # ...is just the exception full name
            New-Object $Exception
        }
        # now build and output the new ErrorRecord
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Building ErrorRecord object"
        New-Object Management.Automation.ErrorRecord $_exception, $ErrorID,$ErrorCategory, $TargetObject

    }

}

function Set-HPOVPrompt {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (

        [parameter(Mandatory = $true, ParameterSetName = 'Enable')]
        [Switch]$Enable,

        [parameter(Mandatory = $true, ParameterSetName = 'Disable')]
        [Switch]$Disable,

        [parameter(Mandatory = $false, ParameterSetName = 'Enable')]
        [parameter(Mandatory = $false, ParameterSetName = 'Disable')]
        [Switch]$Global

    )

    
    Process {

        if ($Enable) {
            
            $Value = "Enabled"

        }

        if ($Disable) { 
        
            $Value = "Disabled"

        }

        if ($global) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting Global Prompt setting."

            #Get Library Global Prompt Setting
            $regkey = "HKLM:\Software\Hewlett-Packard\HPOneView" 
            $regValueName = "Prompt"

        }

        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting Per User Prompt setting."

            #Get Library Per User Prompt Setting
            $regkey = "HKCU:\Software\Hewlett-Packard\HPOneView" 
            $regValueName = "Prompt"

        }

        $RegQueryPrompt = Get-ItemProperty $regkey $regValueName -ErrorAction SilentlyContinue

        #Create if it doesn't exist
        if (! $RegQueryPrompt) {

           Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Prompt (REG_SZ) at $regkey does not exist.  Creating, and setting to default 'Enabled'."

            #If Global, need to check for UAC and elevate the call to Net-ItemProperty
            #Need to elevate users prviledges due to UAC policy
            if ($global) {
                if ($pscmdlet.ShouldProcess("Setting Global Prompt Policy",'Are you sure?')) {
                    If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

                       Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requesting to elevate user access due to UAC."

                        $arguments = "`"if (! (test-path $regkey)) { Md $regkey }; New-ItemProperty $regkey -Name $regValueName -Value Enabled -PropertyType String`""

                        Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments -WindowStyle Hidden

                    }

                    #Else, UAC not enabled for HKLM write access, or per user setting
                    else {

                        if (! (test-path $regkey)) { Md $regkey }

                        New-ItemProperty $regkey -Name $regValueName -Value $value -PropertyType "String"

                    }
                }
            }

            else {

                if (! (test-path $regkey)) { Md $regkey }

                New-ItemProperty $regkey -Name $regValueName -Value $value -PropertyType "String"

            }

        }

        else {

           Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Prompt (REG_SZ) at $regkey does exists.  Setting to $($Value)."

            Set-ItemProperty $regkey -Name $regValueName -Value $Value

        }

        $RegQueryPrompt = Get-ItemProperty $regkey $regvalue -ErrorAction SilentlyContinue

        #Control how the Prompt function will behave
        $script:HPOneViewLibraryPrompt = ($RegQueryPrompt).Prompt

        switch ($script:HPOneViewLibraryPrompt) {

            "Enabled" { Prompt }

            "Disabled" { Invoke-Expression $Global:prompt_old }

        }

    }

}

function RestClient {

<#

    .SYNOPSIS 
    Internal Private Class for building a RestClient using [System.Net.HttpWebRequest]

    .DESCRIPTION 
    This is a private, internal class/function to create a new [System.Net.HttpWebRequest] object with pre-defined properties of the HttpWebReqeuest connection.  This class will set the following attributes, which the caller can overload the values with their own after the resource has been created:

        Timeout = 10000
        ContentType = "application/json"
        Accept = "application/json"
	    Headers.Item("X-API-Version") = $script:MaxXAPIVersion
        Headers.Item("accept-language") = "en_US"
        Headers.Item("accept-encoding") = "gzip, deflate"
        Headers.Item("auth") = $global:cimgmtSessionId.sessionID  NOTE: Only if the sessionID exists.
        AutomaticDecompression = "GZip,Deflate,None"

    The URI of the HttpWebRequest object will automatically include the connected (or requested if the first call is Connect-HPOVMgmt) appliance address or name ($script:HPOneViewAppliance).  This value can be overloaded, but the Auth token that may be included as an HTTP header item could be invalid.

    .INPUTS
    None.

    .OUTPUTS
    New [System.Net.HttpWebRequest] object.

    .PARAMETER URI
    The URI of the request.  Do not include the appaliance hostname or IP Address, only the cononical URI value (i.e. /rest/server-hardware).

    .PARAMETER Method
    Optional.  Provide the HTTP method for the request.  The default value is 'GET'.  Only the following values are allowed:

        GET
        PUT
        POST
        DELETE
        PATCH (to be supported in a future release)

    .PARAMETER Appliance
    Optional.  Provide the appliance hostname or FQDN.  The default is the value of '$script:HPOneViewAppliance'
#>

    [CmdletBinding()]
    Param (

        [parameter(Mandatory = $False, Position = 0)]
        [ValidateScript({if ("GET","POST","DELETE","PATCH","PUT" -match $_) {$true} else { Throw "'$_' is not a valid Method.  Only GET, POST, DELETE, PATCH, or PUT are allowed." }})]
        [string]$method = "GET",

        [parameter(Mandatory = $true, Position = 1, HelpMessage = "Enter the resource URI (ex. /rest/enclosures)")]
        [ValidateScript({if ($_.startswith('/')) {$true} else {throw "-URI must being with a '/' (eg. /rest/server-hardware) in its value. Please correct the value and try again."}})]
        [string]$uri,

        [parameter(Mandatory = $False, Position = 2)]
        [ValidateNotNullorEmpty()]
        [string]$Appliance = $script:HPOneViewAppliance

    )

    Begin {

         Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bound PS Parameters: $($PSBoundParameters | out-string)"

        $url = $Appliance + $uri
        Write-Verbose "[RESTCLIENT] Building new [System.Net.HttpWebRequest] object for $method https://$url"

    }


    Process {

        [System.Net.httpWebRequest]$restClient = [System.Net.httpWebRequest]::Create("https://$url")
        $restClient.Method = $method
        $restClient.Timeout = 10000
        $restClient.ContentType = "application/json"
        $restClient.Accept = "application/json"
	    $restClient.Headers.Item("X-API-Version") = $script:MaxXAPIVersion
        $restClient.Headers.Item("accept-language") = "en_US"
        $restClient.Headers.Item("accept-encoding") = "gzip, deflate"

        #Add Auth Session token if it exists
        if ($global:cimgmtSessionId) { $restClient.Headers.Item("auth") = $global:cimgmtSessionId.sessionID }

        $restClient.AutomaticDecompression = "GZip,Deflate,None"

    }

    End {

        Return $restClient

    }


}

function Send-HPOVRequest {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (
         [parameter(Mandatory = $true,HelpMessage = "Enter the resource URI (ex. /rest/enclosures)")]
         [ValidateScript({if ($_.startswith('/')) { $true } else { throw "-URI must being with a '/' (eg. /rest/server-hardware) in its value. Please correct the value and try again. Provided value: '$_'"}})]
         [string]$uri,

         [parameter(Mandatory = $false)]
         [string]$method="GET",
         
         [parameter(Mandatory = $false)]
         [object]$body=$null,

         [parameter(Mandatory = $false)]
         [int]$start=0,

         [parameter(Mandatory = $false)]
         [int]$count=0,

         [parameter(Mandatory = $false)]
         [hashtable]$addHeader
    )

    Begin { 

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] BEGIN"

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bound PS Parameters: $($PSBoundParameters | out-string)"

        #BROKEN? Check to see if System.Net.Webrequest is still "active"
        if ($req) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] System.Net.Webrequest was not closed properly. Fixing..."
            $req = $Null
            $script:lastWebResponse.close()
            
        }
        
        #Check how to handle SSL Certificates
        if (! $script:SSLCheckFlag) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SSL Certificate has not been checked."

            #Out-Host is IMPORTANT, otherwise, the Certificate Details will NOT display when called from Connect-HPOVMgmt, or any other cmdlet for that matter.
            Try { Show-HPOVSSLCertificate | Out-Host }
            catch [System.Net.WebException] { 
            
                if ($_.FullyQualifiedErrorId -match "ApplianceNotResponding") {

                    $errorRecord = New-ErrorRecord HPOneView.Appliance.NetworkConnectionException ApplianceNotResponding ResourceUnavailable 'Send-HPOVRequest' -Message "Unable to connect to '$Appliance' due to timeout." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
            
                }
            
            }
            
            #If cert is untrusted, set ServicePointManager to ignore cert checking
            if ($global:certTrusted -eq $False) { [System.Net.ServicePointManager]::CertificatePolicy = new-object HPOneView.HPOneViewIgnoreCertPolicy }

            $script:SSLCheckFlag = $True
        }
    
        #Need to check for authenticated session when the URI passed is not value of $script:loginSessionsUri
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requested URI: $($uri)"
        If ((!$global:cimgmtSessionId ) -and ($uri -ine $script:loginSessionsUri)) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] We have reached the URI Whitelist condition block"

            #URI Whitelist
            if ($uri -eq $script:applUpdateMonitor) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Unauth request allowed." } #Allow the unauthenticated request 
            elseif ($uri -eq $script:applXApiVersion) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Unauth request allowed." } #Allow the unauthenticated request 
            elseif ($uri -eq "/ui-js/pages/") { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Unauth request allowed." } #Allow the unauthenticated request 
            elseif ($uri -eq $applEulaStatus) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Unauth request allowed." } #Allow the unauthenticated request 
            elseif ($uri -eq $applEulaSave) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Unauth request allowed." } #Allow the unauthenticated request 
            elseif ($uri -eq ($usersUri + "/changePassword")) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Unauth request allowed." } #Allow the unauthenticated request 
            elseif ($uri -eq "/startstop/rest/component?fields=status") { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Unauth request allowed." } #Allow the unauthenticated request 
            
            #Else, require authentication
            else {
                $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Send-HPOVRequest' -Message "No valid session ID found.  The call to '$uri' requires authentication.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }
    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] PROCESS"
    
        #Pagination handling:
        [PSCustomObject]$allMembers = @();

        #See if the caller specified a count, either in the URI or as a param
        #(if so, we will let them handle pagination manually)
        [bool]$manualPaging=$false

        if ($uri.ToLower().Contains("count=") -or $uri.ToLower().Contains("count =")) {

            $manualPaging=$true

        }
        elseif ($count -gt 0) {

            $manualPaging=$true

            #add start & count params to the URI
            if (-not ($uri -contains "?")) {

                $uri += "?"    

            }

            $uri += ("start=" + $start + "&")

            $uri += ("count=" + $count)
        }
        elseif ($start -gt 0) {

            #start specified, but no count -- just set the start param & auto-page from there on:
            $manualPaging = $false

            if (-not ($uri -contains "?")) {

                $uri += "?"   
             
            }

            $uri += ("start=" + $start)
        }

        do {

            #Used to keep track of async task response
            $taskRecieved = $False
            
            [System.Net.httpWebRequest]$req = RestClient $method $uri

            #Increase timeout for synchronous call for Support Dumps to be generated as they are not an Async task.
            if ($uri -match "support-dump") { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Increase HttpWebRequest timeout to 120s, as a Support Dump is being requested."
                $req.Timeout = 120000 
                
            }

            #Handle additional headers being passed in for updated API (storage volume removal)
            #Variable defined as a hashtable in case other API pass more than one additional header
            if($addHeader){
                $addHeader.GetEnumerator() | ForEach-Object { $req.Headers.Item($_.key) = $_.value }
            }

            #Send the request with a messege
            if ($body) {
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Body object found. Converting to JSON."

                if ($method -eq "PUT") {

                    #Handle eTags from connection manager
                    $req.Headers.Item("If-match") = $body.etag

                }
            
                #Create a new stream writer to write the json to the request stream.
                $js = ConvertTo-Json -inputobject $body -Depth 99 -Compress

		        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request Body: $($js)"

                #Send the messege
		        $stream = New-Object IO.StreamWriter $req.GetRequestStream()
		        $stream.AutoFlush = $True
		        $stream.WriteLine($js)
		        $stream.Close()
            }

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request: $($method) https://$($script:HPOneViewAppliance)$($uri)"
   
            #Write Verbose the headers if needed
            $i = 0
            foreach ($h in $req.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request Header $($i+1): $($h) = $($req.Headers[$i])"; $i++ }

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] [System.Net.HttpWebRequest] object details: $($req | select * -ExcludeProperty headers | out-string)"

            try {

                #just to be sure this is cleared, if an exception is thrown
                $script:lastWebResponse = $null 

                #Get response from appliance
                $script:lastWebResponse = $req.GetResponse()

                #Display the response status if verbose output is requested
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Status: $([int]$script:lastWebResponse.StatusCode) $($script:lastWebResponse.StatusDescription)"

                $i = 0
                foreach ($h in $script:lastWebResponse.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Header $($i+1): $($h) = $($script:lastWebResponse.Headers[$i])"; $i++ }
                
                $rs = $script:lastWebResponse.GetResponseStream()

                #Read the response
                $reader = New-Object System.IO.StreamReader($rs)
                $responseJson = $reader.ReadToEnd()
                $rs.Close()
                $reader.Close()

                $resp = ConvertFrom-json $responseJson

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response: $($resp | fl * -force | out-string)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Manual Pagination: $($manualPaging)"

                #Handle multi-page result sets
                if ($resp.members -and ($resp.nextPageUri -or $resp.prevPageUri) -and -not ($manualPaging) -and -not ($resp -is [System.Array])) {

                    $allMembers += $resp.members
                    write-verbose "total stored '$($allmembers.count)'"
                    write-verbose "nextPageURI: '$($resp.nextPageUri)'"

                    if ($resp.nextPageUri) { 

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Pagination has ocurred. Recieved $($resp.count) resources of $($resp.total)"

                        $uri = $resp.nextPageUri

                    }
                    else { 

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Reached end of pagination. Building allResults"

                        $allResults = [PsCustomObject]@{members = $allMembers; count = $allMembers.Count; category = $resp.category; eTag = $resp.eTag }
                        
                    }

                }

                #If asynchronous (HTTP status=202), make sure we return a Task object:
                if ([int]$script:lastWebResponse.StatusCode -eq 202) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Async Task recieved"

                    #Asynchronous operation -- in some cases we get the Task object returned in the body.
                    #In other cases, we only get the Task URI in the Location header.
                    #In either case, return a Task object with as much information as we know
                    if ($script:lastWebResponse.Headers.Item('Location')) {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Async Task Location found: $($script:lastWebResponse.Headers.Item('Location'))"

                        #Return custom task resource if response does not contain actual task resource
                        if (-not $resp.type -and -not $resp.category -eq "TaskResourceV2" -and -not $uri.startswith("/rest/storage-pools")) {

                            #Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] building custom async resouce to be returned to caller."
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Task Resource Object to return to caller."

                            #Only have the Task URI - generate a Task object to be returned:
                            [string]$taskUri = $script:lastWebResponse.Headers.Item('Location')

                            #First, make sure the task URI is relative:
                            $pos = $taskUri.IndexOf("/rest/")

                            if ($pos -gt 0) {

                                $taskUri = $taskUri.Substring($pos)

                            }

                            $resp = Send-HPOVRequest $taskUri

                            if ([int]$script:lastWebResponse.statusCode -eq 200) {
                                
                                #Change the statusCode from 200 to 202, as wewant to reply to the caller with HTTP 202 as Async Task status.
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating HTTP statusCode property to 202"
                                $resp | select * -ExcludeProperty statusCode | Add-Member -NotePropertyName statusCode -NotePropertyValue 202

                            }

                        }

                        $taskRecieved = $true
                        Return

                    }
                    elseif (!$resp) {

                        $errorRecord = New-ErrorRecord InvalidOperationException RestAPIError InvalidResult 'Send-HPOVRequest' -Message 'SEND-HPOVREQUEST: REST API ERROR: The operation is asynchronous, but neither a Task resource or URI was returned!' #-verbose
                        throw $errorRecord
                    
                    }
                    
                    #We have recieved an async task, and need to break out of the Do/While loop
                    $taskRecieved = $true
                    return

                }

            } 
       
            catch [System.Net.WebException] { 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Net.WebException Error caught"
                
                if ($_.Exception.InnerException -match "System.Net.WebException: Unable to connect to the remote server") { 
                
                    $errorRecord = New-ErrorRecord HPOneView.Appliance.NetworkConnectionException ApplianceNotResponding ResourceUnavailable 'Connect-HPOVMgmt' -Message "Unable to connect to '$Appliance' due to timeout." #-verbose
                    Throw $errorRecord

                }

                if ($_.Exception.InnerException) {

                    if ($_.Exception.InnerException.Response) {

                        $script:lastWebResponse = $_.Exception.InnerException.Response

                    }

                    else {

                        Write-Error $_.Exception.InnerException.Message

                    }

                } 
            
                else {

                    if ($_.Exception.Response) {

                        $script:lastWebResponse = $_.Exception.Response

                    }

                    else {

                        Write-Error $_.Exception.Message

                    }
                }

                if ($script:lastWebResponse) {

                    $rs = $script:lastWebResponse.GetResponseStream()

                    $reader = New-Object System.IO.StreamReader($rs)
                    $responseJson = $reader.ReadToEnd()
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ERROR RESPONSE: $($responseJson | ConvertFrom-Json | out-string)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Status: HTTP_$([int]$script:lastWebResponse.StatusCode) $($script:lastWebResponse.StatusDescription)"
                    foreach ($h in $script:lastWebResponse.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Header: $($h) = $($script:lastWebResponse.Headers[$i])"; $i++ }
                
                    $resp = $responseJson | ConvertFrom-Json
                    
                    #Handle HTTP 404 Errors with no response messege.
                    if ($resp) { $resp | Add-Member -MemberType NoteProperty -Name statusCode -Value ([int]$script:lastWebResponse.StatusCode) -Force }
                    else { $resp = [PsCustomObject]@{statusCode = ([int]$script:lastWebResponse.StatusCode); statusMessage = $($script:lastWebResponse.StatusDescription); lastCall = $uri } }

                    switch ([int]$script:lastWebResponse.StatusCode) {
                    
                        #Handle HTTP 400 Errors
                        400 {
                            
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] HTTP 400 error caught."

                            #Hande initial authentication errors
                            if ($resp.errorCode -eq "AUTHN_AUTH_DIR_FAIL") {

                                $errorRecord = New-ErrorRecord HPOneView.Appliance.AuthSessionException InvalidUsernameOrPassword AuthenticationError 'Send-HPOVRequest' -Message "$($resp.message)  $($resp.recommendedActions)"
                                $pscmdlet.ThrowTerminatingError($errorRecord)

                            }
                            else {
                                if ($resp.errorSource) { $source = $resp.errorSource }
                                else { $source = 'Send-HPOVRequest' }

                                $errorRecord = New-ErrorRecord InvalidOperationException InvalidOperation InvalidOperation $source -Message "$($resp.message) $($resp.details)"
                                $pscmdlet.ThrowTerminatingError($errorRecord)
                            }

                        }

                        #User is unauthorized
                        401 { 

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] HTTP 401 error caught."
                            
                            if ( $resp.details -cmatch "User not authorized for this operation" ) {

                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] $($resp.message) Request was '$method' at '$uri'."

                                $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthPrivilegeException InsufficientPrivilege AuthenticationError 'Send-HPOVRequest' -Message "[Send-HPOVRequest]: $($resp.message).  Request was '$method' at '$uri'. " #-verbose
                                Throw $errorRecord

                            }
                            else {
                            
                                $script:HPOneViewAppliance = $null
                                $Script:PromptApplianceHostname = "Not Connected"
                                $Appliance = $null
                                $global:cimgmtSessionId = $null
                                $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException InvalidOrTimedoutSession AuthenticationError 'Send-HPOVRequest' -Message "[Send-HPOVRequest]: Your session has timed out or is not valid. Please use Connect-HPOVMgmt to authenticate to your appliance." #-verbose
                                Throw $errorRecord

                            }

                        }
                    
                        #
                        405 {
                    
                            $errorRecord = New-ErrorRecord InvalidOperationException $resp.errorCode AuthenticationError 'Send-HPOVRequest' -Message ("[Send-HPOVRequest]: The requested HTTP method is not valid/supported.  " + $resp.details + " URI: $uri")
                            Throw $errorRecord

                        }

                        #Wait for appliance startup here by calling Wait-HPOVApplianceStart
                        { @(503, 0) -contains $_ } {
                            
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] HTTP $([int]$script:lastWebResponse.StatusCode) error caught."
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Calling Wait-HPOVApplianceStart"

                            Wait-HPOVApplianceStart

                            #appliance startup should have finished.
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Returning caller back to: $($method.ToUpper()) $uri"
                            if ($addHeader) { return (Send-HPOVRequest $uri $method $body $addHeader) }
                            else { return (Send-HPOVRequest $uri $method $body) }

                        }
                        
                        #0 {
                        #    
                        #    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] HTTP $([int]$script:lastWebResponse.StatusCode) error caught."
                        #    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Calling Wait-HPOVApplianceStart"
                        #
                        #    Wait-HPOVApplianceStart
                        #
                        #    #appliance startup should have finished.
                        #    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Returning caller back to: $($method.ToUpper()) $uri"
                        #    if ($addHeader) { return (Send-HPOVRequest $uri $method $body $addHeader) }
                        #    else { return (Send-HPOVRequest $uri $method $body) }
                        #
                        #}

                        501 {

                            $errorRecord = New-ErrorRecord InvalidOperationException $resp.errorCode SyntaxError 'Send-HPOVRequest' -Message ("[Send-HPOVRequest]: " + $resp.message + " " + $resp.recommendedActions) -InnerException $resp.details #-verbose
                            Throw $errorRecord

                        }
                        
                    } 

                }

                else {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Returning Null"
                    return $null

                }
            }

        } until ($manualPaging -or -not $resp.nextPageUri)

    }

    End {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] END"

        $taskRecieved = $False
        if ($allResults) { return $allResults }
        elseif ($resp) { return $resp }

    }

}

function Wait-HPOVApplianceStart {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdletBinding()]
    Param (
         [parameter(Position = 0, Mandatory = $false, HelpMessage = "Provide the Appliance IP Address or Host Name to monitor.")]
         [ValidateNotNullOrEmpty()]
         [string]$Appliance = $script:HPOneViewAppliance
    )

    Begin { 
    
        if (! $Appliance) {

            $errorRecord = New-ErrorRecord ArgumentNullException ParametersNotSpecified InvalidArgument 'Set-HPOVSanManager' -Message "No parameter values" #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        $flag = $false <# Used to control displaying either output messages #> 

        #Check to see if SSL Certificate trust has been validated
        if (! $script:SSLCheckFlag) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SSL Certificate has not been checked before."

            #Out-Host is IMPORTANT, otherwise, the Certificate Details will NOT display when called from Connect-HPOVMgmt, or any other cmdlet for that matter.
            Show-HPOVSSLCertificate -Appliance $Appliance | Out-Host

            #If cert is untrusted, set ServicePointManager to ignore cert checking
            if ($global:certTrusted -eq $False) { [System.Net.ServicePointManager]::CertificatePolicy = new-object HPOneView.HPOneViewIgnoreCertPolicy }

            $script:SSLCheckFlag = $True
        }
        
    }

    Process {

        do {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Services not started. Monitoring startup progress"
            
            $waitRequest= $Null
            $waitResponse = $Null
            [System.Net.httpWebRequest]$waitRequest = RestClient -uri "/rest/appliance/progress" -appliance $Appliance #$appliance 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] REQUEST: GET https://$($Appliance)/rest/appliance/progress"
            $i = 0
            foreach ($h in $waitRequest.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request Header $($i+1): $($h) = $($waitRequest.Headers[$i])"; $i++ }

            try {

                #Get response from appliance
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting response..."
                $waitResponse = $waitRequest.GetResponse()

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved HTTP\$([int]$waitResponse.StatusCode) status."

                #This will trigger when the GetResponse() does not generate an HTTP Error Code and get trapped by the Catch clause below
                If ($flag) {

                    write-host "]"

                    #Reset flag so we don't display the ending brace
                    $flag = $False
                }

                #Read the response
                $reader = New-Object System.IO.StreamReader($waitResponse.GetResponseStream())
                $responseJson = $reader.ReadToEnd()
                $reader.Close()

                $resp = ConvertFrom-json $responseJson
                
                #Handle the call from -Verbose so Write-Progress does not get borked on display.
                if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { 
                    
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Skipping Write-Progress display."
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Percent Complete: $([Math]::Round(($resp.complete / $resp.total) * 100,$mathMode))"
                    start-sleep -s 2

                }
                  
                else {

                    #Display progress-bar
                    $percentComplete = [Math]::Round(($resp.complete / $resp.total) * 100,$mathMode)
                    Write-Progress -activity "Appliance services starting" -Status "$percentComplete%" -percentComplete $percentComplete
                    start-sleep -s 2

                }

            }

            #Catch if we haven't received HTTP 200, as we should display a nice message stating services are still beginning to start
            catch [Net.WebException] {

                if ($waitResponse) {

                    $rs = $waitResponse.GetResponseStream()

                    $reader = New-Object System.IO.StreamReader($rs)
                    $responseJson = $reader.ReadToEnd()

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ERROR RESPONSE: $($responseJson | ConvertFrom-Json | out-string)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Status: HTTP_$([int]$waitResponse.StatusCode) $($waitResponse.StatusDescription)"
                    foreach ($h in $waitResponse.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Header: $($h) = $($waitResponse.Headers[$i])"; $i++ }

                }

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] EXCEPTION CAUGHT! HTTP Status Code: $($waitResponse)"
                write-verbose "$($waitResponse| Out-string)"

                #Only want to display this message once.
                if (-not $flag) {
                    Write-host "Waiting for services to begin starting [" -nonewline
                }

                if (-not ([int]$waitResponse.StatusCode -eq 200)) {

                    Write-host "*" -nonewline -ForegroundColor Green
                    $flag = $true
                    start-sleep -s 5
                }

                $waitRequest = $null
            }

        } until ($resp.complete -eq $resp.total -and [int]$waitResponse.StatusCode -eq 200)

    }

    end {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Web Services have started successfully"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Pausing 5 seconds to let web services finish their final startup"

        start-sleep -s 5

        $script:lastWebResponse = $waitResponse

    }
}

function Connect-HPOVMgmt {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param(
         [parameter(Mandatory = $true, HelpMessage = "Enter the appliance DNS name or IP",Position=0)]
         [ValidateNotNullOrEmpty()]
         [string] $appliance,

         [parameter(Mandatory = $false, HelpMessage = "Enter the authentication domain",Position=3)]
         [ValidateNotNullOrEmpty()]
         [string] $authProvider="LOCAL",

         [parameter(Mandatory = $true, HelpMessage = "Enter the user name",Position=1)]
         [ValidateNotNullOrEmpty()]
         [alias("u")]
         [string]$User,

         [parameter(Mandatory = $false, HelpMessage = "Enter the password:",Position=2)]
         [alias("p")]
         [ValidateNotNullOrEmpty()]
         [String]$password
    )

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bound PS Parameters: $($PSBoundParameters | out-string)"
        
        #Check to see if the user is already connected
        if ($global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException ResourceExists AuthenticationError $script:HPOneViewAppliance -Message "You are already logged into $Appliance. Please use Disconnect-HPOVMgmt to end your existing session, and then call Connect-HPOVMgmt again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        else {

            if (!$password){

                [SecureString]$password = read-host -AsSecureString "Password"
                $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
            
            }

            else {
                $decryptPassword = $password
            }

            #Handle connecting to other appliances where SSL Cert validation has not ocurred yet.
            if ($Appliance -ne $script:HPOneViewAppliance -and -not $script:HPOneViewAppliance -eq $Null) { 
                
                Disconnect-HPOVMgmt
            
            }

            $script:HPOneViewAppliance = $Appliance

            #Check to make sure the appliance X-API-Version is at least the supported minimum
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Checking X-API Version"
            
            try {
            
                $applianceVersion = (Send-HPOVRequest $script:applXApiVersion).currentVersion

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Appliance returned: $($applianceVersion | out-string)"

                if ($applianceVersion -and $applianceVersion -lt $script:applMinVersion ) {

                    #Display terminating error
                    $errorRecord = New-ErrorRecord HPOneView.Library.TooNew LibraryTooNew OperationStopped $script:HPOneViewAppliance -Message "The appliance you are connecting to supports an older version of this library.  Please visit https://hponeview.codeplex.com for a supported version of the library." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }

            }
            catch [HPOneView.Appliance.NetworkConnectionException] {

                    $errorRecord = New-ErrorRecord HPOneView.Appliance.NetworkConnectionException ApplianceNotResponding ResourceUnavailable 'Connect-HPOVMgmt' -Message "Unable to connect to '$Appliance' due to timeout." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            catch {

                write-error $_ -TargetObject "Connect-HPOVMgmt" -ErrorAction Stop 

            }

        }
    
    }

    Process {

        $authinfo = @{userName=$user; password=$decryptPassword; authLoginDomain=$authProvider}

        try {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending auth request"
            
            $resp = Send-HPOVRequest $script:loginSessionsUri POST $authinfo

        }

        catch [HPOneView.Appliance.AuthSessionException] {

            $errorRecord = New-ErrorRecord HPOneView.Appliance.AuthSessionException InvalidUsernameOrPassword AuthenticationError 'Connect-HPOVMgmt' -Message $_.Exception.Message 
            Throw $errorRecord

        }
    
        catch [Net.WebException] {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response: $($resp)"
            
            #Clear connected appliance variables
            $tmpAppliance = $script:HPOneViewAppliance
            $global:cimgmtSessionId = $Null
            $script:userName = $Null
            $script:HPOneViewAppliance = $Null
            $Script:PromptApplianceHostname = "[Not Connected]"

            $errorRecord = New-ErrorRecord System.Net.WebException ApplianceNotResponding OperationStopped $tmpAppliance -Message "The appliance at $Appliance is not responding on the network.  Check for firewalls or ACL's prohibiting access to the appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    end {

        $global:er = $resp
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] RESP: $($resp)"
        #If a sessionID is returned, then the user has authenticated
        if ($resp.sessionID) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Session token received: $($resp.sessionID)"
                
            #Change the prompt to display the hostname value, which will replace the string "Not Connected"
            $Script:PromptApplianceHostname = $Appliance
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting PromptApplianceHostname to: $($Appliance)"

            #Store the entire auth request for later deletion when issuing Disconnect-HPOVmgmt
            $global:cimgmtSessionId = $resp
                
            #Add the Appliance Name to the cimgmtSessionId PsCustomObject
            $global:cimgmtSessionId | add-member -MemberType NoteProperty -name Appliance -value $script:HPOneViewAppliance -force
            $global:cimgmtSessionId | add-member -NotePropertyName Username -NotePropertyValue $User -force
                
            #Used for the custom display prompt
			$script:userName = $User

            #used for the Show-HPOVAppliance CMDLET
            $script:applianceConnectedTo = [pscustomobject]@{User = $User; Domain = $authProvider; Appliance = $Appliance}

            #Get list of supported Roles from the appliance
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of supported roles from appliance."

            try { $script:applSecurityRoles = (Send-HPOVRequest /rest/roles).members.roleName }

            catch [HPOneview.Appliance.AuthPrivilegeException] { $script:applSecurityRoles = $Null }

        }

        else { 
            
            
            #Need to generate error when auth fails due to invalid username or password
            if ([int]$resp.statusCode -eq 400) {

                $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException InvalidUsernameOrPassword AuthenticationError $script:HPOneViewAppliance -Message "You entered an invalid username or password. Please check your credentials and try again." -InnerException "$($resp.errorCode) $($resp.statusCode) $($resp.details)" #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            else {
                    
                return $resp 
            }

        }

    }

}

function Show-HPOVAppliance {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param()

    Begin {
    
    
    }

    Process {

        $script:applianceConnectedTo
    
    }

    End {


    }

}

function Disconnect-HPOVMgmt {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdletBinding()]
    Param()

    Begin {

        If (!$global:cimgmtSessionId) { 

            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession ResourceUnavailable 'Disconnect-HPOVMgmt' -Message "No valid logon session available.  Please use Connect-HPOVMgmt to connecto to an appliance, and then use Disconnect-HPOVmgmt to terminate your session." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)
            
        }
    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending Delete Session ID request"
        Send-HPOVRequest $loginSessionsUri DELETE $global:cimgmtSessionId
    
        if ([int]$script:lastWebResponse.StatusCode -eq 204) {
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Successfully logged off"
            
            Reset-LibraryVariables

        }
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logoff request failed. Response code: $([int]$script:lastWebResponse.StatusCode)"
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException UnableToLogoff InvalidResult 'Disconnect-HPOVMgmt' -Message "You entered an invalid username or password. Please check your credentials and try again." -InnerException "$($resp.errorCode) $($resp.statusCode) $($resp.details)" #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
    }
}

function Reset-LibraryVariables {


    $script:SSLCheckFlag = $False
    $script:HPOneViewAppliance = $null
    $Script:PromptApplianceHostname = "Not Connected"
    $Appliance = $null
    $User = $Null
    $authProvider = $Null
    $global:cimgmtSessionId = $null

    #Clear the System.Net.ServicePointManager Certificate Policy
    if ([System.Net.ServicePointManager]::CertificatePolicy) {

        #Restore System.Net.ServicePointManager
        [System.Net.ServicePointManager]::CertificatePolicy = $Null

    }

    #used for the Show-HPOVAppliance CMDLET
    $script:applianceConnectedTo = [pscustomobject]@{User = $User; Domain = $authProvider; Appliance = $Appliance}

}

function New-HPOVResource {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param
        (
         [parameter(Position = 0, Mandatory = $true, HelpMessage = "Enter the URI string of the resource type to be created")]
         [ValidateNotNullOrEmpty()]
         [string] $uri,

         [parameter(Position = 1, Mandatory = $true, HelpMessage = "Enter the resource object definition")]
         [ValidateNotNullOrEmpty()]
         [object] $resource
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVResource" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        Send-HPOVRequest $uri POST $resource

    }
}

function Set-HPOVResource {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (
         [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Enter the resource object that has been modifed")]
         [ValidateNotNullOrEmpty()]
         [ValidateScript({$_.Uri})]
         [object]$resource,

         [parameter(Mandatory = $false)]
         [string]$force = $false
    )
    
    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError $script:HPOneViewAppliance -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $uri = $resource.uri
        if ($force -eq $true) { $uri += "?force=true" }
        Send-HPOVRequest $uri PUT $resource

    }
}    

function Remove-HPOVResource {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml
     
    [CmdletBinding(DefaultParameterSetName = "nameOrUri")]
    Param (
          [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "resource", HelpMessage = "Enter the PowerShell variable name of the resource object.")]
          [ValidateScript({$_.uri})]
          [Alias("ro")]
          [object] $resource,

          [parameter(Position = 0, Mandatory = $true, ParameterSetName = "nameOrUri", HelpMessage = "Enter the URI of the resource.")]
          [ValidateNotNullOrEmpty()]
          [Alias("uri","name")]
          [string] $nameOruri,

          [parameter(Mandatory = $false)]
          [switch] $force
        )

    Begin {
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Called from: $($pscmdlet.CommandOrigin)"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError $script:HPOneViewAppliance -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {
         
        $deleteUri = $null
        switch ($PsCmdlet.ParameterSetName) { 

            "resource"  { 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource object passed."
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Name: $($resource.name)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] URI: $($resource.uri)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Category: $($resource.category)"
                $deleteUri = $resource.uri 
                
            }
         
            "nameOrUri"  {
                
                #nameOrUri value is a URI
                if($nameOrUri.StartsWith("/rest")){
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource URI passed: $($nameOrUri)"
                    $deleteUri = $nameOrUri

                }

                #It's a string value
                else {
                    
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource name provided: $($nameOrUri)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Querying appliance index for resource."
                    #Use Index filtering to locate object
                    $resources = Send-HPOVRequest ($indexUri + "?filter=name='$nameOrUri'")

                    #$resources = $resources.members #| ? {$_.name -eq $nameOrUri}

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found $($resources.count) resources."

                    if($resources.members){

                        #Error should only be displayed if a Name was provided, and it wasn't globally unique on the appliance (i.e. Server Profile and Ethernet Network with the same name, which is completely valid.)
                        #if($resources -is [Array]){
                        if($resources.count -gt 1){
                            
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resources found: $($resources.members | % { $_.name + " of type " + $_.category })"
                            $errorRecord = New-ErrorRecord InvalidOperationException ResourceNotUnique LimitsExceeded 'Remove-HPOVResource' -Message "'$nameOrUri' is not unique.  Located $($resources.count) resources with the same value." #-verbose
                            $pscmdlet.ThrowTerminatingError($errorRecord)
                            #Write-Error "'$nameOrUri' is not unique.  Located $($resources.count) objects with the same value." -Category LimitsExceeded -CategoryTargetName "Remove-HPOVResource"
                            #Break
                        }

                        else { 
                        
                            #If $resources.members is an Array, get the first item which should be the only item in the array
                            if ($resources.members -is [array]) { $deleteUri = $resources.members[0].uri }

                            #Else, return the URI of the hashtable member
                            else { $deleteUri = $resources.members.uri }
                        }
                    }

                    else { 
                        $errorRecord = New-ErrorRecord InvalidOperationException ResourceNotFound ObjectNotFound 'Remove-HPOVResource' -Message "Resource '$nameOrUri' not found. Please check the resource value provided and try the call again." #-verbose
                        $pscmdlet.ThrowTerminatingError($errorRecord)
                        #Write-Error "Resource '$nameOrUri' not found" -Category ObjectNotFound -CategoryTargetName "Remove-HPOVResource"
                        #Break    
                    }
                }
            }     
        }
    
        if ($deleteUri) {
            if ([bool]$force) { $deleteUri += "?force=true" }
            Send-HPOVRequest $deleteUri DELETE
        }
    }
}

function Set-DefaultDisplay ($resources, [string[]]$defProps) {
<#
     .DESCRIPTION 
     Handy internal utility function to set default display properties
#>
    $defDisplayProps = New-Object -TypeName System.Management.Automation.PSPropertySet -ArgumentList DefaultDisplayPropertySet, $defProps
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]$defDisplayProps 

    ForEach ($resource in $resources) {
        Add-Member -InputObject $resource -MemberType MemberSet -Name PSStandardMembers -Value $PSStandardMembers -Force
    }
}

function ConvertFrom-HTML {

    [CmdletBinding()]
    param(

        [Parameter(Position = 0, ValueFromPipeline = $True, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.String] $html,

        [switch]$NoClobber
        
    )

    Begin { }

    Process {
        
        # remove line breaks, replace with spaces
        if (-not ($NoClobber.ispresent)) { $html = $html -replace "(`r|`n|`t)", " " }
        
        # remove invisible content
        @('head', 'style', 'script', 'object', 'embed', 'applet', 'noframes', 'noscript', 'noembed') | % {$html = $html -replace "<$_[^>]*?>.*?</$_>", "" }
        
        # Condense extra whitespace
        $html = $html -replace "( )+", " "
        
        # Add line breaks
        @('div','p','blockquote','h[1-9]') | % { $html = $html -replace "</?$_[^>]*?>.*?</$_>", ("`n" + '$0' )} 

        # Add line breaks for self-closing tags
        @('div','p','blockquote','h[1-9]','br') | % { $html = $html -replace "<$_[^>]*?/>", ('$0' + "`n")} 
        
        #strip tags 
        $html = $html -replace "<[^>]*?>", ""
         
        # replace common entities
        @(
            @("&amp;bull;", " * "),
            @("&amp;lsaquo;", "<"),
            @("&amp;rsaquo;", ">"),
            @("&amp;(rsquo|lsquo);", "'"),
            @("&amp;(quot|ldquo|rdquo);", '"'),
            @("&amp;trade;", "(tm)"),
            @("&amp;frasl;", "/"),
            @("&amp;(quot|#34|#034|#x22);", '"'),
            @('&amp;(amp|#38|#038|#x26);', "&amp;"),
            @("&amp;(lt|#60|#060|#x3c);", "<"),
            @("&amp;(gt|#62|#062|#x3e);", ">"),
            @('&amp;(copy|#169);', "(c)"),
            @("&amp;(reg|#174);", "(r)"),
            @("&amp;nbsp;", " "),
            @("&amp;(.{2,6});", ""),
            @("&nbsp;", " ")
        ) | % { $html = $html -replace $_[0], $_[1] }
    }

    End {
    
        return $html

    }

}


#######################################################
# Appliance Configuration: 
#

function Install-HPOVUpdate {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = 'Update',SupportsShouldProcess = $True, ConfirmImpact = 'High')]
	Param (
		[parameter(Mandatory = $true, ParameterSetName = 'Update')]
        [parameter(Mandatory = $true, ParameterSetName = 'Stage')]
        [Alias('f')]
        [ValidateScript({Test-Path $_})]
        [string]$File,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Update')]
        [parameter(Mandatory = $false, ParameterSetName = 'StageInstall')]
        [string]$Eula,

        [Parameter(Mandatory = $false, ParameterSetName = 'Update')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Stage')]
        [Parameter(Mandatory = $false, ParameterSetName = 'List')]
        [switch]$DisplayReleaseNotes,

        [parameter(Mandatory = $true, ParameterSetName = 'Stage')]
        [switch]$Stage,

        [parameter(Mandatory = $true, ParameterSetName = 'StageInstall')]
        [switch]$InstallNow,
        
        [parameter(Mandatory = $true, ParameterSetName = 'List')]
        [Alias('list')]
        [switch]$ListPending

	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Install-HPOVUpdate' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            Throw $errorRecord

        }

    }

    Process {

        Switch ($PsCmdlet.ParameterSetName) {

            #Stage Update
            "Stage" {
                
                #Check to see if ane existing update is present.  Report to user if it is, and tell them to use -InstallNow
                $pendingUpdate = Send-HPOVRequest $script:applUpdatePending

                if (-not ($pendingUpdate)) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Stage Only"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - UPLOAD FILE: $($File)"

                    Try {
                    
                        #Upload update
                        $FileName = Get-Item $File
                        $upload = Upload-File $script:applUpdate $File
                    
                    }
                    Catch {
                        
                        $errorRecord = New-ErrorRecord InvalidOperationException UploadUpdateFailed InvalidResult 'Install-HPOVUpdate' -Message $upload #-verbose
                        $pscmdlet.ThrowTerminatingError($errorRecord)

                    }

                    If ($DisplayReleaseNotes) {
                        
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Displaying Release Notes"

                        #Display Release Notes
                        Send-HPOVRequest "/rest/appliance/firmware/document-content/$($upload.fileName)/release" | ConvertFrom-HTML
                        write-host "Done. Displayed update release notes."
                    }

                    Return
                }
                else {
                    
                    $errorRecord = New-ErrorRecord HPOneView.Appliance.FirmwareUpdateException PendingUpdateConflict ResourceExists 'Install-HPOVUpdate' -Message "An existing appliance update has been staged. Version: $($pendingUpdate.version) Filename: $($pendingUpdate.fileName)  Please use the -InstallUpdate parameter to proceed with the update, or use Remove-HPOVPendingUpdate cmdlet to remove the staged update." #-verbose
                    Throw $errorRecord

                }
            }

            #List a
            "List" {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Checking if pending update exists"

                #Verify a pending update exists
                $resp = Send-HPOVRequest $script:applUpdatePending

                $updateVersion = $resp.version
                $updateFileName = $resp.fileName
                $estUpgradeTime = $resp.estimatedUpgradeTime


                #If the request is to install a staged update, we need to handle no response.  If request is Update, then no pending update will exist yet.
                If (!$resp) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - No pending update found. Return is Null"
                    $errorRecord = New-ErrorRecord InvalidOperationException StorageSystemResourceNotFound ObjectNotFound 'Install-HPOVUpdate' -Message "No pending update found. Please first upload update and try again."
                    $pscmdlet.ThrowTerminatingError($errorRecord)

                }

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Update found $($updateFileName), $($updateVersion)"

                $u = @{Expression={$_.version};Label="Version"},
                     @{Expression={if ($_.rebootRequired) { "Yes" } else { "No" }};Label="Reboot Required"},
                     @{Expression={"$($_.estimatedUpgradeTime) minutes"};Label="Estimated Upgrade Time"},
                     @{Expression={$_.fileName};Label="Update File Name"}

                $resp | format-table $u -AutoSize
                
                If ($DisplayReleaseNotes) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Displaying Release Notes"

                    #Display Release Notes of Update
                    Send-HPOVRequest "/rest/appliance/firmware/document-content/$updateFileName/release" | ConvertFrom-HTML
                    write-host "Done. Displayed update release notes."

                }
                
                Return
            }
        
            #Upload update then install update below.
            "Update" {
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - UPLOAD FILE: $($File)"

                Try {
				
					#Verify if an existing update is present
					$resp = Send-HPOVRequest $script:applUpdatePending
					
					if ($resp) {
					
						$updateVersion = $resp.version
						$updateFileName = $resp.fileName
						$estUpgradeTime = $resp.estimatedUpgradeTime

						Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - A pending update was found.  File name: $updateFileName; Update Version: $updateVersion"
						$errorRecord = New-ErrorRecord InvalidOperationException PendingUpdateFound ResourceExists 'Install-HPOVUpdate' -Message "A pending update was found.  File name: $updateFileName; Update Version: $updateVersion. Please remove the update before continuing and try again."
						$pscmdlet.ThrowTerminatingError($errorRecord)
					
					}

                    #Upload update
                    $FileName = Get-Item $File
                    $upload = Upload-File $script:applUpdate $File
                
                }
                Catch {

                    $errorRecord = New-ErrorRecord InvalidOperationException UploadUpdateFailed InvalidResult 'Install-HPOVUpdate' -Message $upload #-verbose
                    $pscmdlet.ThrowTerminatingError($errorRecord)

                }
				
            }
			
        }
        
        #Process pending update
        if (($PsCmdlet.ParameterSetName -eq "StageInstall") -or ($PsCmdlet.ParameterSetName -eq "Update" )) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Install Now"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Verifying pending update exists"

            #Verify a pending update exists
            $resp = Send-HPOVRequest $script:applUpdatePending

            #If the request is to install a staged update, we need to handle no response.  If request is Update, then no pending update will exist yet.
            If ((!$resp) -and ($PsCmdlet.ParameterSetName -eq "StageInstall")) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - No pending update found. Return is Null"
                
                $errorRecord = New-ErrorRecord InvalidOperationException StorageSystemResourceNotFound ObjectNotFound 'Install-HPOVUpdate' -Message "No pending update found. Please first upload update and try again."
                $pscmdlet.ThrowTerminatingError($errorRecord)

            }

            $updateVersion = $resp.version
            $updateFileName = $resp.fileName
            $estUpgradeTime = $resp.estimatedUpgradeTime

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Update found $($updateFileName), $($updateVersion)"

            $u = @{Expression={$_.version};Label="Version"},
                 @{Expression={if ($_.rebootRequired) { "Yes" } else { "No" }};Label="Reboot Required"},
                 @{Expression={"$($_.estimatedUpgradeTime) minutes"};Label="Estimated Upgrade Time"},
                 @{Expression={$_.fileName};Label="Update File Name"}

            $resp | format-table $u -AutoSize

            If ($Eula -ne "accept") {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - EULA NOT Accepted"
                
                #Display eula of update
                
                (New-Object System.Net.WebClient).DownloadString("https://$script:HPOneViewAppliance/ui-js/pages/upgrade/eula_content.html") | ConvertFrom-HTML -NoClobber

                Do { $acceptEula = Read-Host "Accept EULA (Must type ACCEPT)" } Until ($acceptEula -eq "Accept")
            }
                
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - EULA Accepted"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Beginning update $($updateFileName)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Estimated Upgrade Time $($estUpgradeTime) minutes"

            #Check to see if the update requires an appliance reboot.
            if ($resp.rebootRequired) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Appliance reboot required $($resp.rebootRequired)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Prompting for confirmation"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Is confirmation overridden $($confirm)"

                #If it does require a reboot, then we need to prompt for confirmation. Overriden by -confirm:$false
                if ($pscmdlet.ShouldProcess($script:HPOneViewAppliance,"Reboot required!  Upgrade appliance using $($resp.fileName)")) {

                    send-hpovrequest ("$script:applUpdatePending"+"?file=$updateFileName") PUT

                    $sw = [System.Diagnostics.Stopwatch]::StartNew()

                    #Loop to display progress-bar
                    Do {

                        #Connect to update monitor web process
                        $monitorUpdate = Send-HPOVRequest $script:applUpdateMonitor
                        
                        #Remove % from value in order to get INT
                        if ($monitorUpdate.percentageCompletion) { $percentComplete = $monitorUpdate.percentageCompletion.replace("%","") }
                        else { $percentComplete = 0 }
                        
                        #Remove " State = " to get proper status
                        if ($monitorUpdate.status) { $updateStatus = $monitorUpdate.status.replace(" State = ","") }
                        else { $updateStatus = "Starting" }

                        #Handle the call from -Verbose so Write-Progress does not get borked on display.
                        if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Skipping Write-Progress display."  }
                          
                        else { Write-Progress -activity "Installing appliance update $updateVersion " -status "$updateStatus $percentComplete% [$($sw.elapsed.minutes)min $($sw.elapsed.seconds)sec]" -percentComplete $percentComplete }

                    } Until ([int]$percentComplete -eq 100)

                    $sw.Stop()

                    #Retrieve final update status
                    $resp = Send-HPOVRequest $script:applUpdateNotification

                    If ($resp) { $updateStatus = "Completed" }
                    ElseIf (!$resp) { $updateStatus = "FAILED" }
                    Write-Progress -activity "Installing appliance update $updateVersion " -status $updateStatus -percentComplete $percentComplete
                }
                if ($updateStatus -ne "FAILED") { Write-Warning "Appliance will begin reboot now." }
            }

            else { 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Appliance reboot NOT required"
                
                $updateTask = send-hpovrequest ("$script:applUpdatePending"+"?file=$updateFileName") PUT

                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                
                #Loop to display progress-bar
                Do {

                    #Connect to update monitor web process
                    $monitorUpdate = Send-HPOVRequest $script:applUpdateMonitor
                        
                    #Remove % from value in order to get INT
                    $percentComplete = $monitorUpdate.percentageCompletion.replace("%","")
                        
                    #Remove " State = " to get proper status
                    $updateStatus = $monitorUpdate.status.replace(" State = ","")

                    #Handle the call from -Verbose so Write-Progress does not get borked on display.
                    if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Skipping Write-Progress display."  }
                      
                    else { Write-Progress -activity "Installing appliance update $updateVersion " -status "$updateStatus $percentComplete% [$($sw.elapsed.minutes)min $($sw.elapsed.seconds)sec]" -percentComplete $percentComplete }

                } Until ([int]$percentComplete -eq 100)
                
                $sw.Stop()

                #Retrieve final update status
                $resp = Send-HPOVRequest $script:applUpdateNotification

                If ($resp) { $updateStatus = "Completed" }
                ElseIf (!$resp) { $updateStatus = "FAILED" }
                Write-Progress -activity "Installing appliance update $updateVersion " -status $updateStatus -percentComplete $percentComplete
            }
        }
    }
}

function Remove-HPOVPendingUpdate {

    
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = 'Update',SupportsShouldProcess = $True, ConfirmImpact = 'High')]
	Param ()

    Begin {
    
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError $script:HPOneViewAppliance -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }    
    
    }

    Process { 
    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Checking for an existing update."
        $pendingUpdate = Send-HPOVRequest $script:applUpdatePending

    }

    End { 
    
        if ($pendingUpdate) {

            $u = @{Expression={$_.version};Label="Version"},
                     @{Expression={if ($_.rebootRequired) { "Yes" } else { "No" }};Label="Reboot Required"},
                     @{Expression={"$($_.estimatedUpgradeTime) minutes"};Label="Upgrade Time"},
                     @{Expression={$_.fileName};Label="Update File Name"}

            $pendingUpdate | format-table $u -AutoSize

            Write-Host "Done. Pending appliance update found."

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Pending update found: $($pendingUpdate | out-string)"
            if ($pscmdlet.ShouldProcess($pendingUpdate.fileName,'Remove pending update from appliance?')) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Removing pending update from applinace."
                Send-HPOVRequest $script:applUpdatePending DELETE

            }

        }
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No pending update found"
            write-host "No pending update found."
            return $Null

        }
    
    }

}

function Get-HPOVVersion {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = "Default")]
	Param
	(
		[parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Alias('Appliance')]
        [switch]$ApplianceVer,

        [parameter(Mandatory = $false, ParameterSetName = "OnlineCheck")]
        [switch]$CheckOnline,

        [parameter(Mandatory = $false, ParameterSetName = "OnlineCheck")]
        [switch]$ReleaseNotes
	)
	
	Begin {

    }
    
    Process {

        $versionInfo = [HashTable]@{ "OneViewPowerShellLibrary" = $script:scriptVersion }
     
        #If the user provided the -Appliance switch, display the appliance and X-API versions
        If ($ApplianceVer){

            if ($script:HPOneViewAppliance) {

                $applVersionInfo = Send-HPOVRequest $script:applVersion

                $versionInfo += @{ "applVersionInfo" = $applVersionInfo.softwareVersion; 
                                   "applMajorVersion" = $applVersionInfo.major;
                                   "applMinorVersion" = $applVersionInfo.minor;
                                   "applXApiVersion" = (Get-HPOVXApiVersion).currentVersion }

            }

            else {

                $versionInfo += @{ "applVersionInfo" = "NOT CONNECTED" }

            }

        }

        [collections.sortedlist] $versionInfo

        if ($CheckOnline.isPresent) {

            try { 
                
                $resp = Invoke-RestMethod -Method GET -Uri $repository

                $versionMajorMinor = "$(([version]$versionInfo["OneViewPowerShellLibrary"]).major).$(([version]$versionInfo["OneViewPowerShellLibrary"]).minor)"

                #filter for versions that match Major and Minor release, and exclude the HP VCM to OneView Migration Tool
                $matchedVersions = $resp | ? { $_.tag_name -like "*$versionMajorMinor*" -and -not ($_.tag_name.startswith('HPVCtoOV'))} 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found versions online: $($matchedVersions.tag_name | % { "$_,"})"

                $newerVersion = $Null

                #Compare the releases
                $matchedVersions | % { 
    
                    if ($newerVersion) { write-verbose "Found previous version to compare: $newerVersion" }

                    [version]$version = $_.tag_name -replace "v","" 

                    write-verbose "Comparing $version to $([version]$versionInfo["OneViewPowerShellLibrary"])" 
        
                    #Compare found version with library
                    if (-not ($newerVersion) -and $version.build -gt ([version]$versionInfo["OneViewPowerShellLibrary"]).build) {
            
                        [version]$newerVersion = $version
                        $newerVersionObj = $_

                    }
                    elseif ($newerVersion.Build -lt $version.Build -and $version.build -gt ([version]$versionInfo["OneViewPowerShellLibrary"]).build) {

                        [version]$newerVersion = $version
                        $newerVersionObj = $_

                    }
    
                }

                if ($newerVersion) { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found $([string]$version)"

                    if ($ReleaseNotes) { $newerVersionObj.body -replace "## ","" -replace "\*","  • " }

                    $caption = "Please Confirm";
                    $message = "You currently have v$($versionInfo["OneViewPowerShellLibrary"]) installed.  The HP OneView PowerShell Library v$([string]$newerVersion) was found that is newer.  Do you want to download the current version of the HP OneView POSH Library (will open your web browser for you to download)?";
                    $yes = new-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Open your browser to download latest HP OneView POSH Library version.";
                    $no = new-Object System.Management.Automation.Host.ChoiceDescription "&No","No, you will do this later.";
                    $choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes,$no);
                    $answer = $host.ui.PromptForChoice($caption,$message,$choices,0) 

                    switch ($answer){

                        0 {

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Launching users browser to 'https://github.com/HewlettPackard/POSH-HPOneView/releases/latest'"
                            start "https://github.com/HewlettPackard/POSH-HPOneView/releases/latest"
                            break
        
                        }

                    }     
    
                }
                else { 
                
                    Write-Host ""
                    Write-Host "Library is already up-to-date." 
                    
                }

            }
            catch {

                $errorMessage = "$($_[0].exception.message). $($_[0].exception.InnerException.message)"
                $errorRecord = New-ErrorRecord HPOneView.Library.UpdateConnectionError $_[0].exception.status ConnectionError 'Get-HPOVVersion' -Message "$($_[0].exception.message). $($_[0].exception.InnerException.message)" #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

        }

    }

}

function Get-HPOVHealthStatus {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param()
	
    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVHealthStatus' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process{

        $healthStatus = Send-HPOVRequest $script:applHealthStatus
    
    }

    end {

        
        $a = @{Expression={$_.resourceType};label="Resource Type"},
             @{Expression={$_.available};label="Available"},
             @{Expression={$_.capacity};label="Capacity"},
             @{Expression={if ($_.statusMessage -match "insufficient"){"CRITICAL"} elseif ($_.statusMessage -match "sufficient"){"Good"} };label="Status"}

        return $healthstatus.members | Format-Table $a -AutoSize | Out-String | ColorPattern -pattern "critical|good" -color @{Good="green";critical="red"}

    }

}

function Get-HPOVXApiVersion {
	
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param (
		[parameter(Position = 0, Mandatory = $false)]
		[string]$appliance
	)

    Begin { }

    Process {

	    if ($global:cimgmtSessionId) {
		    Send-HPOVRequest $applXApiVersion
        }

	    Else {

		    if (!$appliance) {

                $errorRecord = New-ErrorRecord System.InvalidOperationException NoAuthSession ConnectionError $script:HPOneViewAppliance -Message "No existing session established. Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

			    #Write-Error "No existing session established. Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." -Category ConnectionError -RecommendedAction "Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." -CategoryTargetName Get-HPOVXApiVersion
		    }

		    else {
                $script:HPOneViewAppliance = $appliance
                write-warning $script:HPOneViewAppliance
			    $applVersion = Send-HPOVRequest $applXApiVersion
                $script:HPOneViewAppliance = $Null
                return $applVersion
		    }
        }

    }

    End { }
}

function Get-HPOVEulaStatus {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param
    (
        [parameter(Position = 0, Mandatory = $false)]
        [string]$appliance=$null
    )

    Begin { }

    Process {

        if ($global:cimgmtSessionId) {
	        Send-HPOVRequest $applEulaStatus
        }

        Else {

		    if (!$appliance) {

                $errorRecord = New-ErrorRecord System.InvalidOperationException NoAuthSession ConnectionError $script:HPOneViewAppliance -Message "No existing session established. Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

			    #Write-Error "No existing session established. Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." -Category ConnectionError -RecommendedAction "Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." -CategoryTargetName Get-HPOVXApiVersion
		    }

	        else {
		    
                $script:HPOneViewAppliance = $appliance
			    $eulaStatus = Send-HPOVRequest $applEulaStatus
                $script:HPOneViewAppliance = $Null
                return $eulaStatus

            }
	    }

        }

    End { }
}

function Set-HPOVEulaStatus {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory = $true,
        HelpMessage = "Set to 'yes' to allow HP support access to the appliance, otherwise set to 'no'.")]
        [ValidateNotNullOrEmpty()]
        [string]$supportAccess,

        [parameter(Mandatory = $false)]
        [string]$appliance=$null
    )

    $body = [pscustomobject]@{supportAccess=$supportAccess}

    if ($global:cimgmtSessionId) {
	    Send-HPOVRequest $applEulaSave POST $body
    }

    Else {
		if (!$appliance) {

            $errorRecord = New-ErrorRecord System.InvalidOperationException NoAuthSession ConnectionError $script:HPOneViewAppliance -Message "No existing session established. Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

			#Write-Error "No existing session established. Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." -Category ConnectionError -RecommendedAction "Appliance name or existing connection is required.  Either specify the appliance hostname or IP Address, or use Connect-HPOVMgmt." -CategoryTargetName Get-HPOVXApiVersion
		}

	    else {
		    		    
            $script:HPOneViewAppliance = $appliance
			$eulaStatus = Send-HPOVRequest $applEulaSave POST $body
            $script:HPOneViewAppliance = $Null
            return $eulaStatus
        }
    }
}

function Get-HPOVApplianceNetworkConfig {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdLetBinding()]
    Param (
        [parameter(Mandatory = $false)]
        [alias("x", "export")]
        [ValidateScript({split-path $_ | Test-Path})]
        [String] $exportFile
    )

    If ($exportFile) {

        try { $netConfig = Send-HPOVRequest $applConfigUri }

        catch [System.IO.DirectoryNotFoundException] {
            $noDir = split-path $exportFile
            #Write-Error "Path $noDir not found!  Please verify the location where to save the configuration file to and try your request again."  -Category ObjectNotFound -CategoryTargetName Get-HPOVApplianceNetworkConfig -RecommendedAction "Please verify the location where to save the configuration file to and try your request again."
            $errorRecord = New-ErrorRecord InvalidOperationException LocationNotFound ObjectNotFound 'Get-HPOVApplianceNetworkConfig' -Message "Path $noDir not found!  Please verify the location where to save the configuration file to and try your request again." #-verbose
            $pscmdlet.throwterminatingerror($errorRecord)
        }

        ForEach ($nic in $netConfig.applianceNetworks) {

            if ($nic.ipv4Type -eq "DHCP") {

                $nic.app1Ipv4Addr=$null
            }

            if ($nic.ipv6Type -eq "DHCP") {
                $nic.app1Ipv6Addr=$null
            }
        }

        $netConfig | convertto-json  > $exportFile
    }
    Else {
        Send-HPOVRequest $applConfigUri
    }
}

function Set-HPOVApplianceNetworkConfig {

    # .ExternalHelp HPOneView.110.psm1-help.xml
       
    [CmdletBinding(DefaultParameterSetName = "primary")]
	Param (
        
		[parameter(Position = 0, Mandatory = $true, ParameterSetName="secondary")]
        [ValidateScript({$_ -ne "eth0"})]
		[string]$device,

        [parameter(Position = 1, Mandatory = $true, ParameterSetName="secondary")]
        [ValidateSet("Management", "Deployment")]
		[string]$interfaceName,

		[parameter(Position = 0,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 2,Mandatory = $true, ParameterSetName="secondary")]
		[string]$hostname = $null,

		[parameter(Position = 1,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 3,Mandatory = $false, ParameterSetName="secondary")]
		[string]$ipv4Type = $null,

		[parameter(Position = 2,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 4,Mandatory = $false, ParameterSetName="secondary")]
		[string]$ipv4Addr = $null,

		[parameter(Position = 3,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 5,Mandatory = $false, ParameterSetName="secondary")]
		[string]$ipv4Subnet = $null,

		[parameter(Position = 4,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 6,Mandatory = $false, ParameterSetName="secondary")]
		[string]$ipv4Gateway = $null,

		[parameter(Position = 5,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 7,Mandatory = $false, ParameterSetName="secondary")]
		[string]$ipv6Type = $null,

		[parameter(Position = 6,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 8,Mandatory = $false, ParameterSetName="secondary")]
		[string]$ipv6Addr = $null,

		[parameter(Position = 7,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 9,Mandatory = $false, ParameterSetName="secondary")]
		[string]$ipv6Subnet = $null,

		[parameter(Position = 8,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 10,Mandatory = $false, ParameterSetName="secondary")]
		[string]$ipv6Gateway = $null,

		[parameter(Mandatory = $false, ParameterSetName="primary")]
        [parameter(Mandatory = $false, ParameterSetName="secondary")]
        [alias('overrideDhcpDns')]
		[switch]$overrideIpv4DhcpDns,

		[parameter(Mandatory = $false, ParameterSetName="primary")]
        [parameter(Mandatory = $false, ParameterSetName="secondary")]
		[switch]$overrideIpv6DhcpDns,

		[parameter(Position = 9,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 11,Mandatory = $false, ParameterSetName="secondary")]
		[string]$domainName = $null,

		[parameter(Position = 10,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 12,Mandatory = $false, ParameterSetName="secondary")]
		[array]$searchDomains = @(),

		[parameter(Position = 11,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 13,Mandatory = $false, ParameterSetName="secondary")]
        [alias('nameServers')]
		[array]$ipV4nameServers = @(),

		[parameter(Position = 12,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 14,Mandatory = $false, ParameterSetName="secondary")]
		[array]$ipV6nameServers = @(),

		[parameter(Position = 13,Mandatory = $false, ParameterSetName="primary")]
        [parameter(Position = 15,Mandatory = $false, ParameterSetName="secondary")]
        [array]$ntpServers = @(),

        [parameter(Mandatory = $true, ParameterSetName="importFile", HelpMessage = "Enter the full path and file name for the input file.")]
        [alias("i", "import")]
        [ValidateScript({Test-Path $_})]
        $importFile
    ) 

    Begin { }
    
    Process { 

        # Get the current config (to get ETag & ensure we don't overwrite anything):
        $currentConfig = Get-HPOVApplianceNetworkConfig
    
        if ($currentConfig.etag)  {$etag = $currentConfig.etag }
    
        Switch ($PsCmdlet.ParameterSetName) {
    
            "secondary" {
            [int]$i=0
            $deviceIndex = $NULL
            $configured = $false
            #If($currentConfig.applianceNetworks.Count -gt 1){
                For($i -eq 0; $i -le ($currentConfig.applianceNetworks.Count - 1); $i++)
                    {
                     if($currentConfig.applianceNetworks[$i].device -eq $device){
                        $deviceIndex = $i; $configured=$true; break
                        }
                    }
                #}
            
            if(!$configured){
                $freeMacs = Send-HPOVRequest $script:applMacAddresses
                if($freeMacs.members | ? {$_.device -eq $device}){
                    $macAddr = ($freeMacs.members | ? {$_.device -eq $device}).macAddress
                    # Update any non-null values that were passed-in:
                    $secondaryNet = New-Object System.Object
                    $secondaryNet | Add-Member -NotePropertyName device -NotePropertyValue $device
                    $secondaryNet | Add-Member -NotePropertyName macAddress -NotePropertyValue $macAddr
                    if ($hostname)     { $secondaryNet | Add-Member -NotePropertyName hostname -NotePropertyValue $hostname }
                    if ($ipv4Type)     { $secondaryNet | Add-Member -NotePropertyName ipv4Type -NotePropertyValue $ipv4Type.ToUpper()
                                         # If setting DHCP, clear any existing IP address:
                                         if ($ipv4Type -ieq "DHCP") {$secondaryNet | Add-Member -NotePropertyName app1Ipv4Addr -NotePropertyValue $null }
                                       }
                    if ($ipv4Addr)     { $secondaryNet | Add-Member -NotePropertyName app1Ipv4Addr -NotePropertyValue $ipv4Addr }
                    if ($ipv4Subnet)   { $secondaryNet | Add-Member -NotePropertyName ipv4Subnet -NotePropertyValue $ipv4Subnet }
                    if ($ipv4Gateway)  { $secondaryNet | Add-Member -NotePropertyName ipv4Gateway -NotePropertyValue $ipv4Gateway }
                    if ($ipv6Type)     { $secondaryNet | Add-Member -NotePropertyName ipv6Type -NotePropertyValue $ipv6Type.ToUpper() 
                                         # If setting DHCP, clear any existing IP address:
                                         if ($ipv6Type -ieq "DHCP") { $secondaryNet | Add-Member -NotePropertyName app1Ipv6Addr = $null }
                                       }
                    if ($ipv6Addr)     { $secondaryNet | Add-Member -NotePropertyName app1Ipv6Addr -NotePropertyValue $ipv6Addr }
                    if ($ipv6Subnet)   { $secondaryNet | Add-Member -NotePropertyName ipv6Subnet -NotePropertyValue $ipv6Subnet }
                    if ($ipv6Gateway)  { $secondaryNet | Add-Member -NotePropertyName ipv6Gateway -NotePropertyValue $ipv6Gateway }
                    if ($overrideDhcpDns){ $secondaryNet | Add-Member -NotePropertyName overrideDhcpDnsServers -NotePropertyValue $overrideDhcpDns }
                    if ($domainName)   { $secondaryNet | Add-Member -NotePropertyName domainName -NotePropertyValue $domainName }
                    if ($searchDomains){ $secondaryNet | Add-Member -NotePropertyName searchDomains -NotePropertyValue $searchDomains }
                    if ($nameServers)  { $secondaryNet | Add-Member -NotePropertyName nameServers -NotePropertyValue $nameServers }

                    if ($ntpServers) { $currentConfig.time.ntpServers = $ntpServers }

                    # Hard code the following settings, for now:
                    $secondaryNet | Add-Member -NotePropertyName allowTransientValidationErrors -NotePropertyValue "false" # "true" or "false"
                    $secondaryNet | Add-Member -NotePropertyName confOneNode -NotePropertyValue "true"  # Always "true", for now
                    $secondaryNet | Add-Member -NotePropertyName activeNode -NotePropertyValue "1"      # Always "1", for now
                    $currentConfig.applianceNetworks += $secondaryNet                    
                    }
                else{
                    #$errMessage = $device + " does not exist on the appliance."
                    #Throw $errMessage
                    $errorRecord = New-ErrorRecord InvalidOperationException UnknownNetworkInterface ObjectNotFound 'Set-HPOVApplianceNetworkConfig' -Message $device + " does not exist on the appliance." #-verbose
                    $pscmdlet.ThrowTerminatingError($errorRecord)
                    
                    }
                }

            }
    
            "primary" {
                [int]$i=0
                $deviceIndex = $NULL
                For($i -eq 0; $i -le ($currentConfig.applianceNetworks.Count - 1); $i++)
                    {
                     if($currentConfig.applianceNetworks[$i].interfaceName -eq "Appliance"){
                        
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found interface: $($currentConfig.applianceNetworks[$i].interfaceName)"
                        $deviceIndex = $i
                        $configured=$true
                        
                        #break out of for loop
                        break
                        }
                    }
                }
            "importFile" {
                try {
                    $importConfig = [string]::Join("", (gc $importfile -ErrorAction Stop))
                    $importConfig = $importConfig -replace "\s","" | convertfrom-json -ErrorAction Stop
                    $freeMacs = Send-HPOVRequest $script:applMacAddresses
    
                    [int]$i=0
                    For($i -eq 0; $i -le ($importConfig.applianceNetworks.Count - 1); $i++)
                        {
                        if ($importConfig.applianceNetworks[$i].ipv4Gateway -eq "127.0.0.1"){
                            $importConfig.applianceNetworks[$i].ipv4Gateway = ""
                            }
                        if ($importConfig.applianceNetworks[$i].nameServers -is "String"){
                            $importConfig.applianceNetworks[$i].nameServers = @()
                            }
                        if ($importConfig.applianceNetworks[$i].searchDomains -is "String"){
                            $importConfig.applianceNetworks[$i].searchDomains = @()
                            }
                        if (!$importConfig.applianceNetworks[$i].macAddress){
                            $macAddr = ($currentConfig.applianceNetworks | ? {$_.device -eq $importConfig.applianceNetworks[$i].device}).macAddress
                            if(!$macAddr){
                                $macAddr = ($freeMacs.members | ? {$_.device -eq $importConfig.applianceNetworks[$i].device}).macAddress
                                }
                            if(!$macAddr){
                                $errorRecord = New-ErrorRecord InvalidOperationException ApplianceNICResourceNotFound ObjectNotFound 'Get-HPOVStorageSystem' -Message ($importConfig.applianceNetworks[$i].device + "does not exist on the appliance.") #-verbose
                                #$errMessage = $importConfig.applianceNetworks[$i].device + "does not exist on the appliance."
                                #Throw $errMessage
                                $PsCmdlet.ThrowTerminatingError($errorRecord)
                                }
                            $importConfig.applianceNetworks[$i] | Add-Member -NotePropertyName macAddress -NotePropertyValue $macAddr
    
                            }
                        }
                    #zero the $currentConfig.applianceNetworks array so we can send it all new values
                    $currentConfig.applianceNetworks = @()
                    $currentConfig.applianceNetworks = $importConfig.applianceNetworks
                    }
                catch [System.Management.Automation.ItemNotFoundException] {
    
                    $errorRecord = New-ErrorRecord System.Management.Automation.ItemNotFoundException ImportFileNotFound ObjectNotFound 'Set-HPOVApplianceNetworkConfig' -Message "$importFile not found!" #-verbose
                    $pscmdlet.ThrowTerminatingError($errorRecord)
    
                }
    
                catch [System.ArgumentException] {
    
                    $errorRecord = New-ErrorRecord System.ArgumentException InvalidJSON ParseErrror 'Set-HPOVApplianceNetworkConfig' -Message "Input JSON format incorrect!" #-verbose
                    $pscmdlet.ThrowTerminatingError($errorRecord)    

                }

            }

        }

        if($configured){
                # Update any non-null values that were passed-in:
                
                if ($hostname)        { $currentConfig.applianceNetworks[$deviceIndex].hostname =     $hostname }
                if ($ipv4Type)        { $currentConfig.applianceNetworks[$deviceIndex].ipv4Type =     $ipv4Type.ToUpper()
                    
                    # If setting DHCP, clear any existing IP address:
                    if ($ipv4Type -ieq "DHCP") { $currentConfig.applianceNetworks[$deviceIndex].app1Ipv4Addr = $null }

                }
                if ($ipv4Addr)        { $currentConfig.applianceNetworks[$deviceIndex].app1Ipv4Addr = $ipv4Addr }
                if ($ipv4Subnet)      { $currentConfig.applianceNetworks[$deviceIndex].ipv4Subnet =   $ipv4Subnet }
                if ($ipv4Gateway)     { $currentConfig.applianceNetworks[$deviceIndex].ipv4Gateway =  $ipv4Gateway }
                if ($ipv6Type)        { $currentConfig.applianceNetworks[$deviceIndex].ipv6Type =     $ipv6Type.ToUpper() 
                                          
                    # If setting DHCP, clear any existing IP address:
                    if ($ipv6Type -ieq "DHCP") { $currentConfig.applianceNetworks[$deviceIndex].app1Ipv6Addr = $null }

                }
                if ($ipv6Addr)        { $currentConfig.applianceNetworks[$deviceIndex].app1Ipv6Addr = $ipv6Addr }
                if ($ipv6Subnet)      { $currentConfig.applianceNetworks[$deviceIndex].ipv6Subnet =   $ipv6Subnet }
                if ($ipv6Gateway)     { $currentConfig.applianceNetworks[$deviceIndex].ipv6Gateway =  $ipv6Gateway }
                if ($overrideIpv4DhcpDns) { $currentConfig.applianceNetworks[$deviceIndex].overrideIpv4DhcpDnsServers = [bool]$overrideIpv4DhcpDns }
                if ($overrideIpv6DhcpDns) { $currentConfig.applianceNetworks[$deviceIndex].overrideIpv6DhcpDnsServers = [bool]$overrideIpv6DhcpDns }
                if ($domainName)      { $currentConfig.applianceNetworks[$deviceIndex].domainName =   $domainName }
                if ($searchDomains)   { $currentConfig.applianceNetworks[$deviceIndex].searchDomains =$searchDomains }
                if ($ipV4nameServers)     { $currentConfig.applianceNetworks[$deviceIndex].ipv4NameServers =  $ipV4nameServers }
                if ($ipV6nameServers)     { $currentConfig.applianceNetworks[$deviceIndex].ipv6NameServers =  $ipV6nameServers }
    
                if ($ntpServers) { $currentConfig.time.ntpServers = $ntpServers }
    
                # Hard code the following settings, for now:
                $currentConfig.applianceNetworks[$deviceIndex].confOneNode = "true"  # Always "true", for now
                $currentConfig.applianceNetworks[$deviceIndex].activeNode = "1"      # Always "1", for now
            }
        
        if ($etag) { $currentConfig | Add-Member -type NoteProperty -name etag -value $etag }

    }

    end {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Configuration to be applied: $($currentConfig | out-string)"

        #Remove MAC Address value or DHCP setting will break
        if ($currentConfig.macAddress) { $currentConfig.macAddress = $Null }

        # This is an asynchronous method, so get the returned Task object
        $task = Send-HPOVRequest $applConfigUri POST $currentConfig

        #Take a peak at the task before moving on
        try { $taskStatus = Send-HPOVRequest $task.uri }
        catch [HPOneView.Appliance.NetworkConnectionException]{
        
            #The appliance is no longer reachable.
			$Script:PromptApplianceHostname = $Null
            $script:HPOneViewAppliance = $Null
            $global:cimgmtSessionId.appliance = $Null
            $script:applianceConnectedTo.appliance = $Null
			$errorRecord = New-ErrorRecord HPOneView.Appliance.NetworkConfigurationException ApplianceUnreachable ConnectionError 'Set-HPOVApplianceNetworkConfig' -Message "The appliance is unreachable." #-verbose
            $PsCmdlet.ThrowTerminatingError($errorRecord)

        }
        
        #validate status code 200, even though it should be HTTP/202
        if ([int]$script:lastWebResponse.StatusCode -eq 200 -and $taskStatus.type -eq "TaskResourceV2" -and $taskStatus.taskState -eq "Running") {
        
            #Start a new stopwatch object
            $sw = [diagnostics.stopwatch]::StartNew()
                
            Do {

                $percentComplete = [Math]::Round(($sw.Elapsed.Seconds / 40) * 100,$mathMode)
                
                if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { 
                    
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Skipping Write-Progress display."
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Percent Complete: $percentComplete"
                    Start-Sleep -s 1

                }
                  
                else {

                    #Display progress-bar
                    Write-Progress -activity "Update Appliance Network Configuration" -Status "Processing $percentComplete%" -percentComplete $percentComplete -SecondsRemaining (40 - $sw.Elapsed.Seconds)

                }

            } While ($sw.Elapsed.Seconds -le 40)

            #Stop the stopwatch
            $sw.stop()
            
            Write-Progress -activity "Update Appliance Network Configuration" -Completed
        
        }

        #task failed validation
        elseif ($taskStatus.taskState -eq "Error") {

            if ($taskStatus.taskErrors -is [Array] -and $taskStatus.taskErrors.count -gt 1 ) {

                for ($e = 0; $e -gt $taskStatus.taskErrors.count; $e++) {

                    if ($e -ne $taskStatus.taskErrors.length) {
                        
                        $errorRecord = New-ErrorRecord HPOneView.Appliance.NetworkConfigurationException NoAuthSession AuthenticationError 'Set-HPOVApplianceNetworkConfig' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
                        $PsCmdlet.WriteError($errorRecord)    

                    }
                    else {

                        $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Set-HPOVApplianceNetworkConfig' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
                        $PsCmdlet.ThrowTerminatingError($errorRecord)    

                    }
                }

            }

        }

        if ($ipv4Type -eq "static") {
            
            #Check to make sure we connect to a OneView appliance
            $resp = Invoke-WebRequest -uri "http://$ipv4Addr"

            #If successful, update current POSH session
            if ($resp.Content -match "OneView") { 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating session appliance variables with new appliance address: $ipv4Addr"
                $Script:PromptApplianceHostname = $ipv4Addr
                $script:HPOneViewAppliance = $ipv4Addr
                $global:cimgmtSessionId.appliance = $ipv4Addr
                $script:applianceConnectedTo.appliance = $ipv4Addr

                #Check to see if we can get the final status of the task resource
                Send-HPOVRequest $task.uri

            }
            else {

                #Unable to connect to new appliance address or connection failed.  Need to generate error here.
				$Script:PromptApplianceHostname = $Null
				$script:HPOneViewAppliance = $Null
				$global:cimgmtSessionId.appliance = $Null
				$script:applianceConnectedTo.appliance = $Null
				$errorRecord = New-ErrorRecord HPOneView.Appliance.NetworkConfigurationException ApplianceUnreachable ConnectionError 'Set-HPOVApplianceNetworkConfig' -Message "The appliance is unreachable." #-verbose
				$PsCmdlet.ThrowTerminatingError($errorRecord)

            }
        }
        #Should wait ~40 seconds after task has been validated.
        # Wait for the asynch task to complete before returning:
        #Wait-HPOVTaskComplete $task

    }

}

function Get-HPOVSnmpReadCommunity {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml
    
	[CmdletBinding()]
	Param ()

    Begin {
        
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVSnmpReadCommunity' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
        $applSnmpReadCommunityStr = Send-HPOVRequest $script:applSnmpReadCommunity
        return $applSnmpReadCommunityStr | select-object -property * -excludeproperty uri
    
    }
}

function Set-HPOVSnmpReadCommunity {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
	Param (
		[parameter(Position= 0, Mandatory = $True)]
		[string]$name = $null
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Set-HPOVSnmpReadCommunity' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New SNMP Read Community Value: $($name)"

        $applSnmpReadCommunityStr = [PsCustomObject]@{ "communityString" = $name }
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
        $rspNewApplSnmpReadCommunity = Send-HPOVRequest $script:applSnmpReadCommunity PUT $applSnmpReadCommunityStr

        return $rspNewApplSnmpReadCommunity
    
    }

}

function Get-HPOVApplianceGlobalSetting {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param (
		[parameter(Position = 0, Mandatory = $false)]
		[string]$name=$null
	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVSnmpReadCommunity' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $settings = Send-HPOVRequest $applGlobalSettingsUri
        Set-DefaultDisplay $settings.members -defProps 'name', 'value', 'description', 'uri'

        if ($name) { $settings.members | Where-Object {$_.name -eq $name} }
        else { $settings.members }

    }

}

function Set-HPOVApplianceGlobalSetting {

   # .ExternalHelp HPOneView.110.psm1-help.xml
      
    [CmdletBinding()]
	Param
	(
		[parameter(Position = 0, Mandatory = $true, HelpMessage = "Enter the name of the global parameter")]
		[string]$name,

        [parameter(Position = 1, Mandatory = $true, HelpMessage = "Enter the new value for the global parameter")]
        [string]$value
	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Set-HPOVApplianceGlobalSetting' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $setting = Get-HPOVApplianceGlobalSetting($name)

        if ($setting.uri) {

            $setting.value = $value

            # This should really be a PUT to the setting's URI. Will be fixed in a future release
            #Send-HPOVRequest $applGlobalSettingsUri POST $setting
            Send-HPOVRequest $applGlobalSettingsUri PUT $setting

        }

    }

}

function Get-HPOVSppFile {

    # .ExternalHelp HPOneView.110.psm1-help.xml

   	[CmdletBinding(DefaultParameterSetName = "ISOFileName" )]
	Param (
		[parameter(Position = 0, Mandatory = $false,ParameterSetName = "ISOFileName")]
        [ValidateNotNullOrEmpty()]
        [Alias('filename')]
		[string]$isoFileName,

		[parameter(position = 0, Mandatory = $false,ParameterSetName = "SppName")]
		[Alias('name')]
        [string]$SppName,

		[parameter(Position = 1, Mandatory = $false,ParameterSetName = "SppName")]
        [ValidateNotNullOrEmpty()]
		[string]$version,
        
        [parameter(Mandatory = $false)]
        [Alias('report')]
        [switch]$List
	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVSppFile" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bound PS Parameters: $($PSBoundParameters | out-string)"

        $baselines = (Send-HPOVRequest $fwDriversUri).members

    }

    end {

        switch ($PSCmdlet.ParameterSetName) {
            
            "SppName" {
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SppName parameter provided: $($SppName)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Version parameter provided: $($version)"

                #API Filtering for the SPP is broken in 1.10
                #$uri = $fwDriversUri + "?filter=name='$SppName'"

                if ($version) { $baseline = $baselines | ? { $_.version -eq $version } }
                else { $baseline = $baselines | ? { $_.name -eq $SppName } }

                if (-not $baseline -and $SppName) {

                    $errorRecord = New-ErrorRecord HPOneView.BaselineResourceException BaselineResourceNotFound ObjectNotFound 'Get-HPOVSspFile' -Message "The Baseline name '$SppName' was not found." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }
                elseif (-not $baseline -and $version) {

                    $errorRecord = New-ErrorRecord HPOneView.BaselineResourceException BaselineResourceNotFound ObjectNotFound 'Get-HPOVSspFile' -Message "The Baseline name '$SppName' with version $version was not found." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }
        
            }
        
            "ISOFileName" {

                if ($isoFileName) { $baseline = $baselines | ? { $_.isoFileName -eq $isoFileName } }
                else { $baseline = $baselines }

            }
        
            default {
        
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No parameter provided. Looking for all SPP Baselines."
                $baseline = $baselines
        
            }
        
        }

        #$spp = (Send-HPOVRequest $uri).members
        
        if (-not $baseline) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No SPP's found." }
        
        if($list) {

            $b = @{Expression={$_.name};Label="Name"},
            @{Expression={$_.version};Label="Version"},
            @{Expression={$_.isoFileName};Label="ISO File Name"},
            @{Expression={$_.xmlKeyName};Label="XML Key Name"}, 
            @{Expression={
                $value = '{0:N2}' -f ($_.bundleSize / 1GB)
                $value + "GB"            
            };Label="Size"}

            $baseline | sort-object -Property name,Version | Format-Table $b -AutoSize -wrap

        }
        else { $baseline }

        if ($baseline -and $baseline -is [PSCustomObject]) { "Done. 1 spp baseline resource(s) found." | out-host }
        else { "Done. {0} spp baseline resource(s) found."-f $baseline.count | out-host }
    }

}

function Add-HPOVSppFile {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param (
		[parameter(Position = 0, Mandatory = $true, HelpMessage = "Enter the path and file name to the SPP iso file.")]
        [ValidateScript({Test-Path $_})]
		[string]$sppFile
	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Add-HPOVSppFile" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        #Start upload file
        Upload-File $fwUploadUri $sppFile

    }
}

function New-HPOVSupportDump {

	# .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "values")]
    Param (
        [parameter(Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "values", HelpMessage = "Specify the folder location to save the Support Dump.",Position=0)]
		[parameter(Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "Object", HelpMessage = "Specify the folder location to save the Support Dump.",Position=0)]
        [Alias("save")]
        [string]$Location = $null,

        [parameter(Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "values", HelpMessage = "Specify the Type of Support Dump (appliance | li) you wish to generate.", Position=1)]
        [parameter(Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "Object", HelpMessage = "Specify the Type of Support Dump (appliance | li) you wish to generate.", Position=1)]
        [ValidateSet("Appliance","LI")]
        [string]$Type = $null,

        #[parameter(Mandatory = $false,ValueFromPipeline=$false, ParameterSetName = "values", HelpMessage = "Specify the Logical Interconnect Name the Support Dump will be generated for.", Position=2)]
        #[ValidateNotNullOrEmpty()]
        #[object]$Name = $null,
			
		[parameter(Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "Object", HelpMessage = "Specify the Logical Interconnect URI the Support Dump will be generated for.", Position = 3)]
        [Alias('liobject','li','name')]
        [object]$LogicalInterconnect

    )

    Begin {

        if (-not ($global:cimgmtSessionId) -and -not ($type -eq "LI")) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVSupportDump" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if (-not ($PSBoundParameters["LogicalInterconnect"])) { $PipelineInput = $true }
		

		#Validate the path exists.  If not, create it.
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Validating $($Location) exists"
		if (!(Test-Path $Location)) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] $($Location) Directory does not exist.  Creating directory..."; New-Item -ItemType directory -path $Location }

    }

    Process{

        if($PipelineInput -and $LogicalInterconnect){
			Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Pipeline object: $($LogicalInterconnect.name)"
            $request = @{errorCode = $LogicalInterconnect.name}
			$targetURI = $LogicalInterconnect.uri + "/support-dumps"
			Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved information from pipeline"
			Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request : $($request | out-string) "
			Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] URI: $($targetURI)"
			
        }
        else {

			try {
				
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Support Dump Type: $($type)"
				switch ($Type){
				        
				    "appliance" {

						#Build the request and specify the target URI. Do not change errorCode value.
						Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requesting Appliance Support Dump..."
				        $request = @{errorCode = "CI";encrypt = $false}
				        $targetURI = $script:applSupportDump
							
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request : $($request | out-string) "
			            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] URI: $($targetURI)"

					}
							
				    "li" { 

						Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requesting $LogicalInterconnect Support Dump..."
							
						#Check to see if /rest is in the variable
						if($LogicalInterconnect -is [String] -and $LogicalInterconnect.StartsWith($script:LogicalInterconnectURIs)){

							Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] A valid URI was passed $($LogicalInterconnect)"
                            $request = @{errorCode = $LogicalInterconnect.Substring($LogicalInterconnect.length - 10,10)}
							$targetURI = $LogicalInterconnect + "/support-dumps"
						
                        }
							
						#Assume the name of the LI is being passed and get its URI
						elseif ($LogicalInterconnect -is [String]) {

							#Return LI URI
							$resp = Get-HPOVLogicalInterconnect $LogicalInterconnect
							$request = @{errorCode = $resp.name.Substring(0,10)}
					        $targetURI = $resp.uri + "/support-dumps"
							Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($resp.name) Logical Interconnect"

						}
                        elseif ($LogicalInterconnect -is [PSCustomObject]) {
                            
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect Object provided."
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($LogicalInterconnect.name) Logical Interconnect"
                            $request = @{errorCode = $LogicalInterconnect.name.Substring(0,10)}
                            $targetUri = $LogicalInterconnect.uri

                        }
				    }

					default {
							
						#If the SDMP type is not a value we understand, we need to report that.
						#write-error "'$Type' is not a proper Support Dump type. Valid types are 'appliance' or 'li'." -Category InvalidArgument -CategoryTargetName "New-HPOVSupportDump"
						#Break
                        $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'New-HPOVSupportDump' -Message "'$Type' is not a proper Support Dump type. Valid types are 'appliance' or 'li'.  Please verify your call and try again." #-verbose
                        $pscmdlet.ThrowTerminatingError($errorRecord)
					}

				} 
					
			} 

            catch {
                $errorRecord = New-ErrorRecord InvalidOperationException UnknownErrorOrException NotSpecified 'New-HPOVSupportDump' -Message "An unknown error ocurred during handling of the Support Dump type." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)
			}
		}
	}
	End {
		
		#If there were any errors, let's catch that.
		if($err){write-error $err ;break}
		
		#Send the request
		Write-Host "Please wait while the Support Dump is generated.  This can take a few minutes..."
		$resp = Send-HPOVRequest $targetUri POST $Request
		
		#Now that the Support Dump has been requested, download the file
		Download-File $resp.uri $Location
	}
}

Function New-HPOVBackup {
	
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default")]
    Param (
        [parameter(Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "default",HelpMessage = "Specify the folder location to save the appliance backup file.",Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("save")]
        [string]$Location = (get-location).Path
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVBackup" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }


    Process {
        
        #Validate the path exists.  If not, create it.
		if (!(Test-Path $Location)){ 
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Directory does not exist.  Creating directory..."
            New-Item $Location -itemtype directory
        }
			
		#Send the request
		Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Please wait while the appliance backup is generated.  This can take a few minutes..."
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending Request..."
		$resp = Send-HPOVRequest $script:applBackup POST
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response: $($resp | out-string)"

        #Wait for task to complete, and set timeout to 45 minutes.
        $taskStatus = Wait-HPOVTaskComplete $resp.uri -timeout (New-Timespan -minutes 45)

        if ($taskStatus.taskState -eq "Completed") {
            
            #check for Appliance 1.00 API behavior
            If ($resp.downloadUri) {
                $backupFileUri = $resp.downloadUri
            }

            #Appliance 1.01+ Backup API behavior
            else {
                #Get backup file from completed task
                $backupUri = (Send-HPOVRequest $resp.uri).associatedResource.resourceUri
                $backupFileUri = (Send-HPOVRequest $backupUri).downloadUri
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Backup File URI $($backupFileUri)"
            }
		    
		    #Now that the Support Dump has been requested, download the file
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Downloading $($backupFileUri) to $($Location)"
		    Download-File $backupFileUri $Location
        }

        else {

            $errorRecord = New-ErrorRecord InvalidOperationException BackupFileCreateError InvalidResult 'New-HPOVBackup' -Message "Create Backup File task '$($taskStatus.taskState)':  $($taskStatus.taskErrors)" #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)

        }
    }
}

Function New-HPOVRestore {
	
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
            [parameter(Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "default",
            HelpMessage = "Specify the file to restore.",
            Position=0)]
            [ValidateNotNullOrEmpty()]
            [Alias("File")]
            [string]$FileName = $null

    )
    
    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVRestore" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        if ($pscmdlet.ShouldProcess($script:HPOneViewAppliance,'Restore backup to appliance')){    
     
			
		    #Send the request
		    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Please wait while the appliance backup is uploaded.  This can take a few minutes..."
		    $resp = Upload-File $script:applRestoreFile $FileName

            if ($resp.id){
		    
                Write-warning "Appliance restore in progress.  All users are now logged off."
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to restore appliance"
                $task = Send-HPOVRequest $resp.ID 
                Wait-HPOVTaskComplete $task.uri
            }
        }
    }
}

function Download-File {
	<#
        .DESCRIPTION
        Helper function to download Support Dump or backup from appliance.  
                
        .PARAMETER uri
        The location where the Support Dump or backup will be downloaded from
        
        .PARAMETER saveLocation
        The full path to where the Support Dump or backup will be saved to.  This path will not be validated in this helper function
        
        .INPUTS
        None.  You cannot pipe objects to this cmdlet.
                
        .OUTPUTS
        Downloads the requested file using net.WebRequest
	
		.LINK
		https://hponeview.codeplex.com/wikipage?title=Download-File

        .EXAMPLE
        PS C:\> Download-File /rest/appliance/support-dumps/ci5401AB76-CI-2013_09_04-04_52_00.014786.sdmp c:\temp
			
    #>

    [CmdLetBinding()]
    Param (
            [parameter(Mandatory = $true, HelpMessage = "Specify the URI of the object to download.", Position=0)]
            [ValidateNotNullOrEmpty()]
            [string]$uri,

            [parameter(Mandatory = $true, HelpMessage = "Specify the location where to save the file to.", Position=1)]
            [Alias("save")]
            [ValidateNotNullOrEmpty()]
            [string]$saveLocation
    )

    Begin {
        
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Download-File" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    
    Process{	
    
        $fsCreate = [System.IO.FileAccess]::Create
        $fsWrite = [System.IO.FileAccess]::Write

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Download URI: $uri"
  
        [System.Net.httpWebRequest]$fileDownload = RestClient GET $uri
	    $fileDownload.accept = "application/zip,application/octet-stream,*/*"
		$fileDownload.Headers.Item("auth") = $global:cimgmtSessionId.sessionID

        $i=0
        foreach ($h in $fileDownload.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request Header $($i): $($h) = $($fileDownload.Headers[$i])"; $i++}
		    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request: GET $($fileDownload | out-string)"
        
        #Get response
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting response"
        [Net.httpWebResponse]$rs = $fileDownload.GetResponse()

        #Display the response status if verbose output is requested
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Status: $([int]$rs.StatusCode) $($rs.StatusDescription)"
        $i=0
        foreach ($h in $rs.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Header $($i): $($h) = $($rs.Headers[$i])"; $i++ }

        #Request is a redirect to download file contained in the response headers
        if (($rs.headers["Content-Disposition"]) -and ($rs.headers["Content-Disposition"].StartsWith("attachment; filename="))) {
        
            $fileName = ($rs.headers["Content-Disposition"].Substring(21)) -replace "`"",""
        
        }
                		
        #Detect if the download is a Support Dump or Appliance Backup
        elseif ($uri.Contains("/rest/backups/archive")){
            #Need to get the Appliance file name
	        $fileName = $uri.split("/")
            $fileName = $fileName[-1] + ".bkp"
        }

        else {
		    #Need to get the Support Dump file name
	        $fileName = $uri.split("/")
            $fileName = $fileName[-1]
        }

		if ($rs.headers['Content-Length']) { $fileSize = $rs.headers['Content-Length'] }
		elseif ($rs.ContentLength -and $rs.ContentLength -gt 0) { $fileSize = $rs.ContentLength }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filename: $($fileName)"
	    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filesize:  $($fileSize)"

	    #Read from response and write to file
		$stream = $rs.GetResponseStream() 
	        
	    #Define buffer and buffer size
		[int] $bufferSize = (4096*1024)
	    [byte[]]$buffer = New-Object byte[] (4096*1024)
	    [int] $bytesRead = 0

		#This is used to keep track of the file upload progress.
	    $totalBytesToRead = $fileSize
	    $numBytesRead = 0
		$numBytesWrote = 0
	 
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Saving to $($saveLocation)\$($fileName)"
        $fs = New-Object IO.FileStream ($saveLocation + "\" + $fileName),'Create','Write','Read'

	    while (($bytesRead = $stream.Read($buffer, 0, $bufferSize)) -ne 0) {

	        #Write from buffer to file
			$byteCount = $fs.Write($buffer, 0, $bytesRead);
			
			#Keep track of bytes written for progress meter
			$numBytesWrote += $bytesRead

	        #Use the Write-Progress cmd-let to show the progress of uploading the file.
	        [int]$percent = (($numBytesWrote / $totalBytesToRead)  * 100)
	        if ($percent -gt 100) { $percent = 100 }
	        $status = "(" + $numBytesWrote + " of " + $totalBytesToRead + ") Completed " + $percent + "%"

            #Handle the call from -Verbose so Write-Progress does not get borked on display.
            if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Skipping Write-Progress display."
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Downloading file $fileName, status: $status, percentComplete: $percent"
                
            }
              
            else { Write-Progress -activity "Downloading file $fileName" -status $status -percentComplete $percent }

	    } #end while

	    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] File saved to $($saveLocation)"

	    #Clean up our work
	    $stream.Close()
	    $rs.Close()
	    $fs.Close()
    }

 }

 function Upload-File {

    <#
        .SYNOPSIS
        Upload a file to the appliance.

        .DESCRIPTION
        This cmdlet will upload a file to the appliance that can accepts file uploads (SPP firmware bundle, Appliance Restore, and Appliance Updates.)

        .PARAMETER URI
        Location where to upload file to.

        .PARAMETER File
        Full path to the file to be uploaded.

        .INPUTS
        None.  You cannot pipe objects to this cmdlet.

        .OUTPUTS
        Write-Progress
        The progress of uploading the file to the appliance.

        .LINK
        Add-HPOVSppFile

        .LINK
        New-HPOVRestore
	
		.LINK
		https://hponeview.codeplex.com/wikipage?title=Upload-File

        .EXAMPLE
        PS C:\> Upload-File "/rest/firmware-bundles" "C:\Users\me\Documents\SPP2012060B.2012_0525.1.iso"
        Upload a new SPP into the appliance.

        .EXAMPLE
        PS C:\> Upload-File "/rest/restores" "C:\Users\me\Documents\appliance.bak"
        Upload a backup file to restore in the appliance.
    #>

	[CmdletBinding()]

	Param (

        [parameter(Mandatory = $true, HelpMessage = "Specify the upload URI.", Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('u')]
        [string]$uri,

		[parameter(Mandatory = $true, HelpMessage = "Enter the path and file name to upload.", Position = 1)]
        [Alias('f')]
        [ValidateScript({Test-Path $_})]
		[string]$File

	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Upload-File" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }
    
    Process {

        $authinfo = $global:cimgmtSessionId.sessionID

        $fsmode = [System.IO.FileMode]::Open
        $fsread = [System.IO.FileAccess]::Read

        $fileObj = Get-Item -path $File

        [string]$filename = $fileObj.name

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Uploading $($filename) file to appliance, this may take a few minutes..."

        try {

            [System.Net.httpWebRequest]$uploadRequest = RestClient POST $uri
            $uploadRequest.Timeout = 1200000
            
            $boundary = "--" + (-join(48..57+65..90+97..122 | ForEach-Object {[char]$_} | Get-Random -Count 20)) #--------------------------bac8d687982e"
            $uploadRequest.ContentType = "multipart/form-data; boundary=$boundary"
            $uploadRequest.Headers.Item("auth") = $authinfo
            $uploadRequest.Headers.Item("uploadfilename") = $filename
            $uploadRequest.AllowWriteStreamBuffering = $false
            $uploadRequest.SendChunked = $true

            $fs = New-Object IO.FileStream ($fileObj,$fsmode, $fsread)
            $uploadRequest.ContentLength = $fs.length

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request: POST $($uri )"

            $i=0
            foreach ($h in $uploadRequest.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request Header {$i} $($h) : $($uploadRequest.Headers[$i])"; $i++}

            $rs = $uploadRequest.getRequestStream()
            $disposition = 'Content-Disposition: form-data; name="file"; filename="' + $fileObj.Name + '"'
            $conType = "Content-Type: application/octet-stream"

            [byte[]]$readbuffer = New-Object byte[] 1048576

            [byte[]]$BoundaryBytes = [System.Text.Encoding]::UTF8.GetBytes("--" + $boundary + "`r`n");
            $rs.write($BoundaryBytes,0,$BoundaryBytes.Length);

            [byte[]]$contentDisp = [System.Text.Encoding]::UTF8.GetBytes($disposition + "`r`n");
            $rs.write($contentDisp,0,$contentDisp.Length);

            [byte[]]$contentType = [System.Text.Encoding]::UTF8.GetBytes($conType + "`r`n`r`n");
            $rs.write($contentType,0,$contentType.Length);

            #This is used to keep track of the file upload progress.
            $numBytesToRead = $fs.Length    
            $numBytesRead = 0

            if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Skipping Write-Progress display." }

            do {
		        $byteCount = $fs.Read($readbuffer,0,1048576)
		        $rs.write($readbuffer,0,$byteCount)
	        
		        #Keep track of where we are at clearduring the read operation
		        $numBytesRead += $bytecount

		        #Use the Write-Progress cmd-let to show the progress of uploading the file.
                [int]$percent = (($numBytesRead / $fs.Length) * 100)
                if ($percent -gt 100) { $percent = 100 }
                $status = "(" + $numBytesRead + " of " + $numBytesToRead + ") Completed " + $percent + "%"

                #Handle the call from -Verbose so Write-Progress does not get borked on display.
                if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Uploading file $fileName, status: $status, percentComplete: $percent"
                    
                }
                  
                else { Write-Progress -activity "Upload File" -CurrentOperation "Uploading $Filename " -status $status -percentComplete $percent }

            } while ($bytecount -gt 0)

            $fs.close()

            [byte[]]$endBoundaryBytes = [System.Text.Encoding]::UTF8.GetBytes("`n`r`n--" + $boundary + "--`r`n");
            $rs.write($endBoundaryBytes,0,$endBoundaryBytes.Length);
            $rs.close()
        }

        catch [System.Exception] {

            #$uploadRequest = $Null
			
            #dispose if still exist
			if ($rs) { $rs.close() }
            if ($fs) { $fs.close() }

            Write-Error $_.Exception.Message -Category ConnectionError -ErrorAction Stop

        }

        try {
		
            [net.httpWebResponse]$script:lastWebResponse = $uploadRequest.getResponse()
			
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Status: ($([int]$script:lastWebResponse.StatusCode)) $($script:lastWebResponse.StatusDescription)"
			
            $uploadResponseStream = $script:lastWebResponse.GetResponseStream()

            #Read the response & convert to JSON
            $reader = New-Object System.IO.StreamReader($uploadResponseStream)
            $responseJson = $reader.ReadToEnd()
            $uploadResponseStream.Close()
            $reader.Close()
            $uploadResponse = $responseJson | convertFrom-Json

            #need to parse the output to know when the upload is truly complete
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response: $($uploadResponse | out-string)"

            Write-Progress -activity "Upload File" -CurrentOperation "Completed" -Completed
            $uploadRequest = $Null
            
			#dispose if still exist
			if ($rs) { $rs.close() }
            if ($fs) { $fs.close() }

        }

        catch [Net.WebException] {
            
            $errorResponse = $_.Exception.Response.getResponseStream()

            $sr = New-Object IO.StreamReader ($errorResponse)
            
            $rawErrorStream = $sr.readtoend()
            #$error[0].Exception.InnerException.Response.close()
            $errorObject = $rawErrorStream | convertFrom-Json
            
            Write-Host $errorObject.errorcode $errorObject.message $errorObject.resolution
			
			#dispose if still exist
            #if ($rs) { $rs.close() }
            #if ($fs) { $fs.close() }
			$errorResponse.close()
			$sr.close()

            Write-Error "$([int]$script:lastWebResponse.StatusCode)) $($script:lastWebResponse.StatusDescription)" -ErrorAction Stop
            
        }

    }

    end {

        #Handle file uploads that generate task resource (i.e. Upload SPP Baseline)
        if ([int]$script:lastWebResponse.StatusCode -eq 202 -or $uploadResponse.uri) {
                  
	        $task = Wait-HPOVTaskComplete $uploadResponse.uri -timeout (New-TimeSpan -Minutes 4)
            Write-Progress -activity "Upload File" -CurrentOperation "Uploading $Filename " -Completed
            
            return $task
        }
        else {

            $uploadResponse

        }

    }
}

function Get-HPOVScmbCertificates {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param(
        [parameter(Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "default", HelpMessage = "Specify the folder location to save the SSL certificates.", Position=0)]
	    [parameter(Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "convert", HelpMessage = "Specify the folder location to save the SSL certificates.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("save")]
        [string]$Location = $null,

        [parameter(Mandatory = $false, ParameterSetName = "convert", HelpMessage = "Convert rabbitmq_readonly client certificate to PFX format.")]
        [ValidateNotNullOrEmpty()]
        [Alias("pfx")]
        [switch]$ConvertToPFx,
	    
		[parameter(Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "convert", HelpMessage = "Password for PFX file")]
        [ValidateNotNullOrEmpty()]
		[SecureString]$Password
    )
	
    Begin {
        
        #Check to see if the user has authenticated to the appliance
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVScmbCertificates" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
        
        #Validate the path exists.  If not, create it.
		if (!(Test-Path $Location)){ 
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Directory does not exist.  Creating directory..."
            New-Item -path $Location -ItemType Directory
        }
    }

    Process{
		
		if ($Password){
			$decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
		}

        #Appliance CA
        $caFile = $Location + "\" + "ca.pem"
        
        #Appliance Public Key
        $publicKeyFile = $Location + "\" + "cert.pem"
        
        #Rabbit Client Private Key
        $privateKeyFile = $Location + "\" + "privateKey.pem"

        #Check to see if the Rabbit client cert was already created
        $keys = Send-HPOVRequest $script:applKeypairURI
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Existing keys? $($keys | out-string)"

        #If the client cert was not created, an error will be generated and we should send the request to create the cert
        #HTTP StatusCode should be 404, not 500.  QUIx entered to fix HTTP StatusCode from 500 to 404.
        If (([int]$script:lastWebResponse.StatusCode -eq 500) -or ([int]$script:lastWebResponse.StatusCode -eq 404)){
			
			Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved StatusCode: $([int]$script:lastWebResponse.StatusCode)"
            #Generate the client private key request
            $body = @{type="RabbitMqClientCertV2";commonName="default"} 
			Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Body: $($body | out-string)"

            $task = Send-HPOVRequest $script:applRabbitmqUri POST $body

            #Wait for task to complete
            Wait-HPOVTaskComplete $task.uri

            #Retrieve generated keys
            $keys = Send-HPOVRequest $script:applKeypairURI
        }
        
        try{
            New-Item $privateKeyFile -type file -force -value $keys.base64SSLKeyData | write-verbose
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Created rabbitmq_readonly user $($privateKeyFile)"
			If ($ConvertToPFx){
				$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($privateKeyFile)
				$bytes = $c.Export("Pfx",$decryptPassword)
				$privateKeyFile = $privateKeyFile.Replace(".pem",".pfx")
				[System.IO.File]::WriteAllBytes($privateKeyFile, $bytes)
				Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Created PFX certificate $($privateKeyFile)"
			}
        }
        catch{
            Write-Error $error[0] -ErrorAction Stop
        }
        try{
            New-Item $publicKeyFile -type file -force -value $keys.base64SSLCertData | Write-Verbose
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Created rabbitmq_readonly user $($publicKeyFile)"
			If ($ConvertToPFx){
				$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($publicKeyFile)
				$bytes = $c.Export("Pfx",$decryptPassword)
				$publicKeyFile = $publicKeyFile.Replace(".pem",".pfx")
				[System.IO.File]::WriteAllBytes($publicKeyFile, $bytes)
				Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Created PFX certificate $($publicKeyFile)"
			}
        }
        catch{
            Write-Error $error[0] -ErrorAction Stop
        }

        try{
            $ca = Send-HPOVRequest $script:applCaURI
            New-Item $caFile -type file -force -value $ca | Write-Verbose
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Created $($caFile)"
        }
        catch{
            Write-Error $error[0] -ErrorAction Stop
        }

    }
}

function Show-HPOVSSLCertificate {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    param( 
    
        [parameter(Mandatory = $false)]
        [String]$Appliance = $script:HPOneViewAppliance
    
    )

    Begin { 
    
        if (! $Appliance ) {

            $errorRecord = New-ErrorRecord ArgumentNullException InvalidArgumentValue InvalidArgument 'Show-HPOVSslCertificate' -Message "You are not connected to an appliance.  Please specify the -appliance parameter and provide the appliance FQDN, Hostname or IP Address." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)

        }
    
    }

    Process {

        $Chain = $Null
        $Status = $Null
        $Cert = $Null
        $certObject = $Null

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Checking '$Appliance' appliance SSL Certificate"

        $ConnectString = "https://$Appliance"

        $WebRequest = [System.Net.HttpWebRequest]::Create($ConnectString)

        #Attempt connection to appliance.
        try { $Response = $WebRequest.GetResponse() }
        catch [Net.WebException] { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] System.Net.WebException caught."
            
            if ($_.Exception -match "The remote name could not be resolved") {
                
                $errorRecord = New-ErrorRecord System.Net.WebException ApplianceNotResponding ObjectNotFound 'Show-HPOVSslCertificate' -Message "Unable to resolve hostname '$Appliance'.  Please check the name and try again." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }
            elseif ($_.Exception -match "Unable to connect to the remote server") {

                $errorRecord = New-ErrorRecord System.Net.WebException ApplianceNotResponding ObjectNotFound 'Show-HPOVSslCertificate' -Message "Unable to connect to '$Appliance' due to timeout or remote system didn't respond to the connection request." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            else {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Error caught, likely untrusted certificate."
            }
        
        }
        
        #Close the response connection, as it is no longer needed, and will cause problems if left open.
        if ($response) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Closing response connection"; $Response.Close() }

        if ($WebRequest.ServicePoint.Certificate -ne $null) {

            $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle

            try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}
            catch {$SAN = $null}
            $chain = New-Object Security.Cryptography.X509Certificates.X509Chain 

            [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
            $Status = $chain.Build($Cert)

            #$certObject = New-Object PKI.Web.WebSSL -Property @{
            $certObject = [HPOneView.PKI.SslCertificate] @{
                OriginalUri = $ConnectString;
                ReturnedUri = $Response.ResponseUri;
                Certificate = $WebRequest.ServicePoint.Certificate;
                Issuer = $WebRequest.ServicePoint.Certificate.Issuer;
                Subject = $WebRequest.ServicePoint.Certificate.Subject;
                SubjectAlternativeNames = $SAN;
                CertificateIsValid = $Status;
                Response = $Response;
                ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}
            }

            #If the certificate is NOT valid, display it and warn user
            if ((! $certObject.CertificateIsValid) -and ($certObject.ErrorInformation -eq "UntrustedRoot")) { 
        
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Cert is NOT trusted"

                #Display the certificate output in Yellow
                $originalFGColor = [System.Console]::ForegroundColor
                [System.Console]::ForegroundColor = [System.ConsoleColor]::Yellow
            
                #Display certificate details
                $certObject

                #Restore the console ForegroundColor
                [System.Console]::ForegroundColor = [System.ConsoleColor]::$originalFGColor

                Write-Warning "The appliance SSL Certificate is UNTRUSTED.  Use the Import-HPOVSSLCertificate to import the appliance Self-Signed certificate to your user accounts local Trusted Root Certification Authorities store to not display this warning when you first connect to your appliance."

                #Value will be False, in String format, not Bool
                $global:certTrusted = $certObject.CertificateIsValid
            
            }

            elseif ($certObject.CertificateIsValid) {
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Cert is trusted"

                if ($VerbosePreference -eq "Continue") {

                    #Display the certificate output in Green
                    $originalFGColor = [System.Console]::ForegroundColor
                    [System.Console]::ForegroundColor = [System.ConsoleColor]::Green
            
                    #Display certificate details
                    $certObject

                    #Restore the console ForegroundColor
                    [System.Console]::ForegroundColor = [System.ConsoleColor]::$originalFGColor

                }

                $global:certTrusted = $certObject.CertificateIsValid
            }

            else {
                Write-Error $Error[-1] -ErrorAction Stop
            }

            
            $chain.Reset()

        } 
        
        else {
        
            Write-Error $Error[-1] -ErrorAction Stop
        
        }
    
        $certObject = $Null
        $WebRequest = $Null
    }

}

function Import-HPOVSslCertificate {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
    param(
        [parameter(Mandatory = $false)]
        [String]$Appliance = $script:HPOneViewAppliance
    )

	begin {

        if (! $Appliance ) {

            $errorRecord = New-ErrorRecord ArgumentNullException InvalidArgumentValue InvalidArgument 'Import-HPOVSslCertificate' -Message "You are not connected to an appliance.  Please specify the -appliance parameter and provide the appliance FQDN, Hostname or IP Address." #-verbose

            $pscmdlet.ThrowTerminatingError($errorRecord)

        }

    }
	
	process {

        $ConnectString = "https://$Appliance"
        
        $WebRequest = [Net.WebRequest]::Create($ConnectString)

        try {$Response = $WebRequest.GetResponse()}
        catch [Net.WebException] { 

            if ( !($WebRequest.Connection) -and ([int]$Response.StatusCode -eq 0)) {

                Write-Error $_.Exception.Message -Category ObjectNotFound -ErrorAction Stop

            } 

        }

        #Close the response connection, as it is no longer needed, and will cause problems if left open.
        if ($response) { write-verbose "Closing response connection"; $Response.Close() }

        if ($WebRequest.ServicePoint.Certificate -ne $null) {

            #Get certificate
            $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate #.Handle

            $StoreScope = "CurrentUser"
            $StoreName = "Root" 

            #Save to users Trusted Root Authentication Hosts store
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            try {

                $store.Add($cert)
                $store.Close()

                #Reset [System.Net.ServicePointManager]::CertificatePolicy after cert has been successfully imported.
                if (($script:SSLCheckFlag) -and ([System.Net.ServicePointManager]::CertificatePolicy)) {

                    [System.Net.ServicePointManager]::CertificatePolicy = $Null
                    $script:SSLCheckFlag = $False

                }
            }

            catch {

                $store.Close()
                Write-Error $_.Exception.Message -Category InvalidResult -ErrorAction Stop

            }
        }

    }
	
	end	{ Write-Warning "Please note that the Subject Alternate Name (SAN) must match that of the Appliance hostname you use to connect to your appliance.  If it does not, an SSL conenction failure will ocurr.  When creating a CSR on the appliance, make sure to include the additional FQDN and IP address(es) in the Alternative Name field." }
}

function Restart-HPOVAppliance {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param ()

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Restart-HPOVAppliance' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }


    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Appliance Restart being request."
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Presenting confirmation prompt."

        if ($pscmdlet.ShouldProcess($script:HPOneViewAppliance,"Restart appliance? WARNING: Restarting the appliance will cause all users to be disconnected and all ongoing tasks to be interrupted.")){
            
            $resp = Send-HPOVRequest -uri $script:applianceRebootUri -method POST
            
            if ([int]$script:lastWebResponse.StatusCode -ne 200) { <# ERROR CONDITION #> return $resp }
            else { 
            
                Write-Warning "Please wait while the appliance retarts..."
                return $resp
            }
        
        }

        else {

            write-verbose "[STOP-HPOVAPPLIANCE] User cancelled shutdown request or passed -WhatIf."
        }
        
    }

}

function Stop-HPOVAppliance {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param ()

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Restart-HPOVAppliance' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }


    Process {

        write-verbose "[STOP-HPOVAPPLIANCE] Appliance SHUTDOWN being request."
        write-verbose "[STOP-HPOVAPPLIANCE] Presenting confirmation prompt."

        if ($pscmdlet.ShouldProcess($script:HPOneViewAppliance,"Shutdown appliance? WARNING: Shutdown of the appliance will cause all users to be disconnected and all ongoing tasks to be interrupted.")){
        
            write-verbose "[STOP-HPOVAPPLIANCE] User confirmed appliance shutdown."    
            $resp = Send-HPOVRequest -uri $script:applianceRebootUri -method POST

            if ([int]$script:lastWebResponse.StatusCode -ne 200) { <# ERROR CONDITION #> return $resp }
            else { 
            
                Write-Warning "Shutting down appliance..." 
                return $resp
            }
        
        }

        else {

            write-verbose "[STOP-HPOVAPPLIANCE] User cancelled shutdown request or passed -WhatIf."
        }
        
    }
    # $script:applianceShutDownUri = '/rest/appliance/shutdown?type=HALT'

}

#######################################################
# Server Hardware and Enclosures: 
#

function Get-HPOVServer {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "Default")]
	Param (
		
        [parameter(Position = 0, Mandatory = $false, ParameterSetName = "Default")]
		[string]$name=$null,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias('report')]		
        [switch]$list,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [switch]$NoProfile
	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVServer" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

	Process {

        $uri = $script:serversUri + "?sort=name:asc"

        #if ($name -and $NoProfile) { 
        #    
        #    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved name '$($name)' and filtering for no Profile Assigned."
        #    $uri += "?filter=name matches '$name'&filter=serverProfileUri=null&sort=name:asc" -replace ("[*]","%25")
        #
        #}
		#
        #elseif ($name) { 
        #    
        #    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved name: $($name)"
        #    $uri += "?filter=name matches '$name'&sort=name:asc" -replace ("[*]","%25")
        #
        #}
        #
        ##elseif ($NoProfile) { 
        if ($NoProfile) { 
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering for server hardware with no assigned profiles."
            $uri += "&filter=serverProfileUri=null"
        
        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
	    $svrs = Send-HPOVRequest $uri

        if($name) {

            $svrs.members = $svrs.members | ? { $_.name -like $name }
            if ($svrs.members -is [PSCustomObject]) { $svrs.total = 1}
            else { $svrs.total = $svrs.members.count }

        }

        if ($svrs.total -eq 0 -and $name) {
				
            $errorRecord = New-ErrorRecord InvalidOperationException ServerHardwareResourceNotFound ObjectNotFound 'Get-HPOVServer' -Message "Server '$name' not found. Please check the name again, and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)

		}

        elseif ($svrs.total -eq 0) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No server resources found."
            Return
            
        }
        
	}

    end {

        if ($list) {

            #Display Pertinant Server Profile data in Table format
            $a = @{Expression={$_.name};Label="Server Name";width=20}, `
            @{Expression={$_.serialNumber};Label="Serial Number";width=15}, `
            @{Expression={$_.shortModel};Label="Model";width=12}, `
            @{Expression={$_.romVersion};Label="System ROM";width=15}, `
            @{Expression={($_.mpModel + " " + $_.mpFirmwareVersion)};Label="iLO Firmware Version";width=22}, `
            @{Expression={
						    if (!$_.serverProfileUri){ 'No Profile' }
						    else { (Send-HPOVRequest $_.serverProfileUri).name }
				    };Label="Server Profile";width=30},`
            @{Expression={$_.status};Label="Status";width=15},`
            @{Expression={$_.powerState};Label="Power";width=15},`
            @{Expression={$_.licensingIntent};Label="Licensing";width=15}

		    #Display List
            $svrs.members | Sort-Object -Property name | format-table $a -AutoSize -wrap

        }

        else {

            if ($svrs.members.length -eq 1) { $svrs.members[0] }
            else { $svrs.members }

        }

        "Done. {0} server resource(s) found." -f $svrs.total | out-host 

    }

}

function Add-HPOVServer {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [parameter(ValueFromPipeline = $True, Mandatory = $true, HelpMessage = "Enter the host name (FQDN) or IP of the server's iLO.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$hostname = $Null,
         
        [parameter(Mandatory = $true, HelpMessage = "Enter the iLO administrative user name.", Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$username = $Null,

        [parameter(Mandatory = $true, HelpMessage = "Enter the iLO administrative account password.", Position=2)]
        [ValidateNotNullOrEmpty()]
        [string]$password = $Null,

        [parameter(Mandatory = $true, HelpMessage = "Enter licensing intent for the server being imported (OneView or OneViewNoiLO).", Position=3)]
        [ValidateSet("OneView", "OneViewNoiLO")]
        [string]$licensingIntent = $NULL,

	    [parameter(Mandatory = $false)]
	    [switch]$force
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'New-HPOVServer' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if ($force.ispresent) { write-warning "-Force parameter is deprecated. Please use the -Confirm:`$false parameter to bypass force import confirmation." }

    }

    Process {

        $import = [PsCustomObject]@{
            hostname = $hostname;
            username = $username;
            password = $password;
            licensingIntent = $licensingIntent 
        }
    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to add server resource ($hostname)"
        $resp = Send-HPOVRequest $script:serversUri POST $import

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request response: $($resp | out-string)"

        $resp = Wait-HPOVTaskStart $resp $hostname

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task response: $($resp | out-string)"

        #Check to see if the task errored, which should be in the Task Validation stage
        if ($resp.taskState -ne "Running") {

            if (($resp.taskState -eq "Error") -and ($resp.stateReason -eq "ValidationError")) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task error found: $($resp.taskState), $($resp.stateReason)"
                
                #taskErrors should contain only a single value, so we will force pick the first one.
                $errorMessage = $resp.taskerrors[0]
                
                switch ($errorMessage.errorCode) {

                    "SERVER_ALREADY_MANAGED" { 
                    
                        $externalManagerType = $errorMessage.data.managementProduct
                        $externalManagerIP = $errorMessage.data.managementUrl.Replace("https://","")
                        $externalManagerFQDN = [System.Net.DNS]::GetHostByAddress($externalManagerIP)

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found server '$hostname' is already being managed by $externalManagerType at $externalManagerIP."
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] $externalManagerIP resolves to $($externalManagerFQDN | out-string)"
                        write-warning "Server '$hostname' is already being managed by $externalManagerType at $externalManagerIP ($($externalManagerFQDN.HostName))."

		        
                        if ($pscmdlet.ShouldProcess($hostname,"Server is already being managed by $externalManagerType at $externalManagerIP ($($externalManagerFQDN.HostName)). Force add?") -and -not $Force) {
		    	    
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server was claimed and user chose YES to force add."
                	        $import | add-member -MemberType NoteProperty -name force -value $true
                            $resp = Send-HPOVRequest $script:serversUri POST $import
		                }
		                else {
                            if ($PSBoundParameters['whatif'].ispresent) { 
                    
                                write-warning "-WhatIf was passed, would have force added '$hostname' server to appliance."
                                $resp= $null
                    
                            }
                            else {

		    	                #If here, user chose "No", end processing
		    	                write-warning "Not importing server, $hostname."
                                $resp = $Null

                            }

		                }
                    
                    }

                    "INVALID_ADDR" { 
                    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating error: $($errorMessage.message)"
                        $errorRecord = New-ErrorRecord InvalidOperationException ServerResourceNotFound ObjectNotFound 'New-HPOVServer' -Message ($errorMessage.message + " " + $errorMessage.recommendedActions )
                        $PSCmdlet.ThrowTerminatingError($errorRecord)
                    
                    }

                }
                    
            }

        }
       
    }

    end {
        
        $resp

    }
}

function Remove-HPOVServer {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [parameter (Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Enter the rackmount server to be removed.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri","name")]
        [object]$server,

	    [parameter(Mandatory = $false)] 
        [switch]$force
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)


        }

    }

    Process {

        foreach ($svr in $server) {
            
            $serverNameOrUri = $null;
            $serverDisplayName = $null;

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verifying server input object type"
            if ($svr -is [String]) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server input object type is System.String ($($svr)) "
                $serverNameOrUri = $svr
                $serverDisplayName = $svr
            }
            elseif ($svr -is [PSCustomObject] -and $svr.category -ieq 'server-hardware') {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server input object is type System.PSCsustomObject: $($svr | out-string)"
                [string]$model = $svr.shortModel
                if ($model.StartsWith("BL")) {
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Blade Server was passed. Displaying error."
                    $errorRecord = New-ErrorRecord InvalidOperationException InvalidRemoveServerMethod InvalidOperation 'Remove-HPOVServer' -Message "Blade servers must be removed with the enclosure they are contained in.  To remove a BL server, either physically remove it or remove the Enclosure from the appliance that contains the BL server." #-verbose
                    $pscmdlet.ThrowTerminatingError($errorRecord)
                    #Write-Error "Blade servers must be removed with the enclosure they are contained in.  To remove a BL server, either physically remove it or remove the Enclosure from the appliance that contains the BL server." -Category InvalidOperation -CategoryTargetName "Remove-HPOVServer" -RecommendedAction "To remove a BL server, either physically remove it or remove the Enclosure from the appliance that contains the BL server."
                    #Break
                }
                else {
                    $serverNameOrUri = $svr.uri;
                    $serverDisplayName = $svr.name;
                }
            }
            else {
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVServer' -Message "Invalid server parameter: $svr" #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)
                #Write-error "Invalid server parameter: $svr" 
                #Break
            }

            if ($pscmdlet.ShouldProcess($serverDisplayName,'Remove server from appliance?')){    
                #Remove-HPOVResource -nameOrUri $serverNameOrUri -force $force
                if ([bool]$force) { Remove-HPOVResource -nameOrUri $serverNameOrUri -force }
                else { Remove-HPOVResource -nameOrUri $serverNameOrUri }
            }
        }
    }
}

function Set-HPOVServerPower {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true,ValueFromPipeline=$true,HelpMessage = "Enter the uri or name for the server resource.", position = 0)]
        [ValidateNotNullOrEmpty()]
        [alias("name","uri","serverUri")]
        [object]$server,

        [parameter(Mandatory = $false, position = 1)]
        [ValidateSet("On", "Off")]
        [string]$powerState="On",

        [parameter(Mandatory = $false, position = 2)]
        [ValidateSet("PressAndHold", "MomentaryPress", "ColdBoot", "Reset")]
        [string]$powerControl="MomentaryPress"
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVServerPower" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }


    }


    Process {

        #Validate input object type
        #Checking if the input is System.String and is NOT a URI
        if (($server -is [string]) -and (!$server.StartsWith($script:serversUri))) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server is a Server Name: $($server)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Server URI"
            $serverUri = (Get-HPOVServer $server).uri

        }

        #Checking if the input is System.String and IS a URI
        elseif (($server -is [string]) -and ($server.StartsWith($script:serversUri))) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server is a Server device URI: $($server)"
            $serverUri = $server
        
        }

        #Checking if the input is PSCustomObject, and the category type is server-profiles, which could be passed via pipeline input
        elseif (($server -is [System.Management.Automation.PSCustomObject]) -and ($server.category -ieq "server-hardware")) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server is a Server Device object: $($server.name)"
            $serverUri = $server.uri
        
        }

        #Checking if the input is PSCustomObject, and the category type is server-hardware, which would be passed via pipeline input
        elseif (($server -is [System.Management.Automation.PSCustomObject]) -and ($server.category -ieq "server-profiles") -and ($server.serverHardwareUri)) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server is a Server Profile object: $($server.name)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Server Profile is assigned to $((Get-HPOVServer $server.serverHardwareUri).name)"
            $serverUri = $server.serverHardwareUri
        
        }

        else {

            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Set-HPOVServerPower' -Message "The parameter 'Server' value is invalid.  Please validate the 'Server' parameter value you passed and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)
            #Write-Error "The parameter 'Server' value is invalid.  Please validate the 'Server' parameter value you passed and try again." -Category InvalidArgument -CategoryTargetName "Set-HPOVServerPower" -RecommendedAction "Validate the SourceName parameter value you passed and try again."
            #Break

        }

        #Validate the server power state and lock
        $serverPowerState = Send-HPOVRequest $serverUri

        if (($serverPowerState.powerState -ine $powerState) -and (!$serverPowerState.powerLock)) {

            #Enforce the proper string case
            $powerState = (Get-Culture).TextInfo.ToTitleCase($powerState)
        
            #Enforce the proper string case
            switch ($powerControl) {

                "PressAndHold" { $powerControl = "PressAndHold" }
                "MomentaryPress" { $powerControl = "MomentaryPress" }
                "ColdBoot" { $powerControl = "ColdBoot" }
                "Reset" { $powerControl = "Reset" }

            }

            $uri = $serverUri + "/powerState"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server to change power state: $($uri)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server Power State requested: $($powerControl)"
            $body = [pscustomobject]@{powerState=$powerState; powerControl=$powerControl}
            Send-HPOVRequest $uri PUT $body
        }
        else { 
        
            if ($serverPowerState.powerState -ieq $powerState) { $errorMessage += "Requested Power State `($($powerState)`) is the same value as the current Server Power State `($($serverPowerState.powerState)`).  "  }
            if ($serverPowerState.powerLock) { $errorMessage += "Server is currently under Power Lock.  "  }

            if ($errorMessage) { write-error $errorMessage -Category InvalidOperation -CategoryTargetName "Set-HPOVServerPower" -ErrorAction Stop}
        }
    }
}

function Get-HPOVEnclosureGroup {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]    
    Param (
        [parameter(Mandatory = $false)]
        [string]$name=$null,

        [parameter (Mandatory = $false)]
        [alias("x", "export")]
        [ValidateScript({split-path $_ | Test-Path})]
        [String]$exportFile
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVEnclosureGroup" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        if ($name) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Group name provided: '$name'"

            $uri = $enclosureGroupsUri + "?filter=name='$name'"
        }
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Enclosure Group name provided. Looking for all Enclosure Group resources."
            $uri = $enclosureGroupsUri

        }

        $enclGrps = Send-HPOVRequest $uri

        if ($enclGrps.count -eq 0 -and $name) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Group '$name' resource not found. Generating error"
            $errorRecord = New-ErrorRecord InvalidOperationException EnclosureGroupNotFound ObjectNotFound 'Get-HPOVEnclosureGroup' -Message "Specified Enclosure Group '$name' was not found.  Please check the name and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)  
            #write-error "Specified Enclosure Group '$name' was not found.  Please check the name and try again." -ErrorId EnclosureGroupNotFound -TargetObject 'Get-HPOVEnclosureGroup' -ErrorAction Stop
            
        }
        elseif ($enclGrps.count -eq 0) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Enclosure Group resources found."
            $members = $null

        }

        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found $($enclGrps.count) Enclosure Group resources."
            $members = $enclGrps.members 
 
        }
   
    }

    end {

        if($exportFile){ $members | convertto-json -Depth 99 | Set-Content -Path $exportFile -force -encoding UTF8 }
                
        else { $members }

        Write-Host "Done. $($enclGrps.count) enclosure group(s) found."        

    }

}

function New-HPOVEnclosureGroup {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (
        [parameter(Position = 0, Mandatory = $true, HelpMessage = "Enter a name for the new enclosure group.")]
        [ValidateNotNullOrEmpty()]
        [string]$name = $Null,
         
        [parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Enter the URI of the Logical Interconect Group to apply.")]
        [ValidateNotNullOrEmpty()]
        [alias('logicalInterconnectGroupUri')]
        [object]$logicalInterconnectGroup = $Null,

        [parameter(Position = 2, Mandatory = $false)]
        [string]$interconnectBayMappingCount = 8,

        [parameter(Position = 3, Mandatory = $false)]
        [string]$configurationScript = $null,

        [parameter(Position = 4, Mandatory = $false)]
        [validateset('Enclosure')]
        [string]$stackingMode = "Enclosure"
    )

    Begin {

        $PipelineInput = -not $PSBoundParameters.ContainsKey("logicalInterconnectGroup")

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVEnclosureGroup" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }


    Process {

        if ($PipelineInput) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG was passed via pipeline." }

        switch ($logicalInterconnectGroup.GetType().name) {

            "String" {
            
                if ($logicalInterconnectGroup -is [String] -and $logicalInterconnectGroup.StartsWith($script:logicalInterconnectGroupsUri)) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG URI was provided: '$logicalInterconnectGroup'"
                    $logicalInterconnectGroupUri = $logicalInterconnectGroup

                }

                elseif ($logicalInterconnectGroup -is [String] -and $logicalInterconnectGroup.StartsWith("/rest")) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Invalid [String] value provided '$logicalInterconnectGroup'"
                    $errorRecord = New-ErrorRecord InvalidOperationException Parameter.logicalInterconnectGroup.InvalidArgumentDataType InvalidType 'New-HPOVEnclosureGroup' -Message "Invalid [String] value provided '$logicalInterconnectGroup'.  Logical Interconnect Group URI must begin with /rest/logical-interconnect-groups." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }
                elseif ($logicalInterconnectGroup -is [String] -and -not $logicalInterconnectGroup.StartsWith($script:logicalInterconnectGroupsUri)) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG Name was provided: '$logicalInterconnectGroup'"
                    Try {

                        $logicalInterconnectGroupUri = (Get-HPOVLogicalInterconnectGroup -name $logicalInterconnectGroup).uri
                    
                    }
                    
                    catch {
                           
                        $errorRecord = New-ErrorRecord InvalidOperationException NologicalInterconnectGroupFound ObjectNotFound  'New-HPOVEnclosureGroup' -Message "The '$logicalInterconnectGroup' Logical Interconnect Group was not found.  Please check the value and try again." #-verbose
                        $PSCmdlet.ThrowTerminatingError($errorRecord)

                    }

                }
            
            }

            "PsCustomObject" { 
            
                if ($logicalInterconnectGroup.category -eq "logical-interconnect-groups") {

                    if ($PipelineInput) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG Resource Object was passed via pipeline." }
                    else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG Resource Object was provided" }
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG Resource Name: '$($logicalInterconnectGroup.name)'"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG Resource uri: '$($logicalInterconnectGroup.uri)'"
                    $logicalInterconnectGroupUri = $logicalInterconnectGroup.uri

                }

                else {

                    $errorRecord = New-ErrorRecord InvalidOperationException Parameter.logicalInterconnectGroup.InvalidCategory InvalidType 'New-HPOVEnclosureGroup' -Message "The logicalInterconnectGroup resource object category provided '$($logicalInterconnectGroup.category) does not match the expected 'logical-interconnect-groups' category.  Please check the paraemter resource value and try again." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }
            
            }

        }

        [System.Array]$interconnectBayMappings = $null;
        for ($i=1; $i -le $interconnectBayMappingCount; $i++) {
            $interconnectBayMappings += [PsCustomObject]@{
                interconnectBay = $i;
                logicalInterconnectGroupUri = $logicalInterconnectGroupUri;
            }
        }

        $eg = [PsCustomObject] @{
            type = "EnclosureGroupV2";
            name = $name;
            stackingMode = $stackingMode;
            configurationScript = $configurationScript;
            interconnectBayMappings = $interconnectBayMappings;
            interconnectBayMappingCount = $interconnectBayMappingCount
        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Group object: $($eg | out-string)"

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Creating $($name) Enclosure Group"
        $resp = New-HPOVResource $enclosureGroupsUri $eg
    }

    end {

        return $resp

    }

}

function Remove-HPOVEnclosureGroup {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True,ConfirmImpact = 'High')]
    Param (
        [parameter(Mandatory = $true,ValueFromPipeline = $true,ParameterSetName = "default",
            HelpMessage = "Enter the Enclosure Group to be removed.", Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        $enclosureGroup,

	    [parameter(Mandatory = $false)] 
        [switch]$force
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVEnclosureGroup" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
    }

    Process {

        foreach ($eg in $enclosureGroup) {

            $egNameOrUri = $null
            $egDisplayName = $null

            if ($eg -is [String]) {

                $egNameOrUri = $eg
                $egDisplayName = $eg

            }
            elseif ($eg -is [PSCustomObject] -and $eg.category -ieq 'enclosure-groups') {

                $egNameOrUri = $eg.uri
                $egDisplayName = $eg.name

            }
            else {
            
                #Write-Error "Invalid enclosure group parameter: $eg" -Category InvalidArgument -CategoryTargetName "Get-HPOVEnclosureGroup" -ErrorAction Stop               
                $errorRecord = New-ErrorRecord HPOneView.EnclosureGroupResourceException EnclosureGroupParameterInvalid InvalidOperation "EG" -Message "Invalid enclosure group parameter: $($eg | out-string)" #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)    
                
            }

            if (-not ($egNameOrUri)) {

                #Write-Error "Invalid enclosure group parameter: $eg" -Category InvalidArgument -CategoryTargetName "Get-HPOVEnclosureGroup" -ErrorAction Stop
                $errorRecord = New-ErrorRecord HPOneView.EnclosureGroupResourceException EnclosureGroupParameterInvalid InvalidOperation "EG" -Message "Invalid enclosure group parameter: $($eg | out-string)" #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)      
                
            }

            elseif ($pscmdlet.ShouldProcess($egDisplayName,'Remove enclosure group from appliance?')){  
            
                if ($force) { Remove-HPOVResource -nameOrUri $egNameOrUri -force }
                else { Remove-HPOVResource -nameOrUri $egNameOrUri }

                if ([int]$script:lastWebResponse.statuscode -eq 204) {

                    Write-Verbose "'$($egDisplayName)' Enclsoure Group resource successfully deleted"
                    #return [int]$script:lastWebResponse.statuscode

                }

            }

        }

    }

}

function Add-HPOVEnclosure {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    Param (
        [parameter(Position = 0, Mandatory = $true, HelpMessage = "Enter the host name (FQDN) or IP of the primary OA.")]
        [ValidateNotNullOrEmpty()]
        [Alias("oa")]
        [string]$hostname,
         
        [parameter(position = 1, Mandatory = $true, HelpMessage = "Enter the enclosure group name with which to associate the new enclosure.")]
        [ValidateNotNullOrEmpty()]
        [Alias("eg")]
        [string]$enclGroupName,

        [parameter(position = 2,Mandatory = $true, HelpMessage = "Enter the OA administrative user name.")]
        [ValidateNotNullOrEmpty()]
        [Alias("u", "user")]
        [string]$username,

        [parameter(position = 3,Mandatory = $true, HelpMessage = "Enter the OA administrative account password.")]
        [ValidateNotNullOrEmpty()]
        [Alias("p", "pw")]
        [string]$password,

        [parameter(position = 4,Mandatory = $true, HelpMessage = "Enter licensing intent for servers in this enclosure (OneView or OneViewNoiLO).")]
        [ValidateSet("OneView", "OneViewNoiLO")]
        [Alias("license", "l")]
        [string]$licensingIntent,

        [parameter(position = 5, Mandatory = $false)]
        [Alias("fwIso")]
        [string]$fwBaselineIsoFilename=$NULL,

        [parameter(Mandatory = $false)]
        [Switch]$Force

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVEnclosure" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {
                
        #Locate the Enclosure Group specified
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Starting"

        try { 
            
            $enclGroup = Get-HPOVEnclosureGroup $enclGroupName

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Found Enclosure Group $($enclGroupName)"

            $import = @{
                hostname=$hostname;
                username=$username;
                password=$password;
                force=[bool]$force;
                licensingIntent=$licensingIntent;
                enclosureGroupUri=$enclGroup.uri;
                updateFirmwareOn="EnclosureOnly"    
            }

            if ($fwBaselineIsoFilename) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Getting Firmware Baseline"
                $fwBaseLine = Get-hpovSppFile $fwBaselineIsoFilename
                $import += @{firmwareBaselineUri=$fwBaseLine.uri}
            }       
    
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Sending request to import enclosure"
            $resp = Send-HPOVRequest $script:enclosuresUri POST $import

            #Wait for task to get into Starting stage
            $resp = Wait-HPOVTaskStart $resp
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - task response: $($resp | out-string)"

            #Check to see if the task errored, which should be in the Task Validation stage
            if ($resp.taskState -ne "Running") {

                if (($resp.taskState -eq "Error") -and ($resp.stateReason -eq "ValidationError")) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Task error found $($resp.taskState) $($resp.stateReason) "

                    if ($resp.taskerrors | Where-Object { $_.errorCode -eq "ENCLOSURE_ALREADY_MANAGED" }) {
                        
                        $errorMessage = $resp.taskerrors | Where-Object { $_.errorCode -eq "ENCLOSURE_ALREADY_MANAGED" }

                        $externalManagerType = $errorMessage.data.managementProduct
                        $externalManagerIP = $errorMessage.data.managementUrl.Replace("https://","")
                        try { $externalManagerFQDN = [System.Net.DNS]::GetHostByAddress($externalManagerIP) }
                        
                        #Unable to resolve IP Address to FQDN
                        catch { $externalManagerFQDN = $externalManagerIP }

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Found enclosure '$hostname' is already being managed by $externalManagerType at $externalManagerIP."
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - $externalManagerIP resolves to $($externalManagerFQDN | out-string)"
                        write-warning "Enclosure '$hostname' is already being managed by $externalManagerType at $externalManagerIP ($($externalManagerFQDN.HostName))."

                        if ($pscmdlet.ShouldProcess($hostname,"Enclosure '$hostname' is already being managed by $externalManagerType at $externalManagerIP ($($externalManagerFQDN.HostName)). Force add?")) {
		        	        
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Server was claimed and user chose YES to force add."
                            $import | add-member -MemberType NoteProperty -name force -value $true
                            $resp = Send-HPOVRequest $script:enclosuresUri POST $import
		                }
		                else {

                            if ($PSBoundParameters['whatif'].ispresent) { 
                            
                                write-warning "-WhatIf was passed, would have force added '$hostname' enclosure to appliance."
                                $resp= $null
                            
                            }
                            else {

		        	            #If here, user chose "No", end processing
		        	            write-warning "Not importing enclosure, $hostname."
                                $resp = $Null

                            }

		                }

                    }
                    else {

                        $errorMessage = $resp.taskerrors
                        if ($errorMessage -is [Array]) { 
                        
                            #Loop to find a Message value that is not blank.
                            $displayMessage = $errorMessage | ? { $_.message }

                            $errorRecord = New-ErrorRecord InvalidOperationException $displayMessage.errorCode InvalidResult 'New-HPOVEnclosure' -Message $displayMessage.message }
                        
                        else { $errorRecord = New-ErrorRecord InvalidOperationException $errorMessage.errorCode InvalidResult 'New-HPOVEnclosure' -Message ($errorMessage.details + " " + $errorMessage.message) }

                        $PSCmdlet.ThrowTerminatingError($errorRecord)

                    }

                }

            }

        }
        catch [System.InvalidOperationException]{
            
            write-host "caught System.InvalidOperationException exception"
            $errorRecord = New-ErrorRecord InvalidOperationException EnclosureGroupResourceNotFound ObjectNotFound 'New-HPOVEnclosure' -Message "Enclosure group '$enclGroupName' not found!  Please check the Enclosure Group Name and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)

        }


    }

    end {
        
        $resp

    }

}

function Update-HPOVEnclosure {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (
        
        [parameter(Position = 0, ValueFromPipeline = $True, Mandatory = $false, HelpMessage = "Enter the Enclosure Name, or an Array of names.", ParameterSetName = "Update")]
        [parameter(Position = 0, ValueFromPipeline = $True, Mandatory = $false, HelpMessage = "Enter the Enclosure Name, or an Array of names.", ParameterSetName = "Reapply")]
        [parameter(Position = 0, ValueFromPipeline = $True, Mandatory = $false, HelpMessage = "Enter the Enclosure Name, or an Array of names.", ParameterSetName = "Refresh")]
        [ValidateNotNullOrEmpty()]
        [object]$Enclosure,

        [parameter(Mandatory = $true, HelpMessage = "Refresh the Enclosure configuration.", ParameterSetName = "Refresh")]
        [Switch]$Refresh,

        [parameter(Mandatory = $true, HelpMessage = "Update Enclosure configuration from Enclosure Group for compliance.", ParameterSetName = "Update")]
        [Alias('update')]
        [Switch]$UpdateFromEG,

        [parameter(Mandatory = $true, HelpMessage = "Enter the Enclosure Name", ParameterSetName = "Reapply")]
        [Switch]$Reapply,

        [parameter(Mandatory = $false, HelpMessage = "Monitor the progress.", ParameterSetName = "Update")]
        [parameter(Mandatory = $false, HelpMessage = "Monitor the progress.", ParameterSetName = "Reapply")]
        [parameter(Mandatory = $false, HelpMessage = "Monitor the progress.", ParameterSetName = "Refresh")]
        [ValidateNotNullOrEmpty()]
        [switch]$Monitor

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Update-HPOVEnclosure" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process { 

        if (! $Enclosure) { 
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure parameter not provided.  Calling Get-HPOVEnclosure for all Enclosure resources."
            $Enclosures = Get-HPOVEnclosure 
        
        }
        elseif ($Enclosure -and $Enclosure -is [String]) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure parameter provided: '$Enclosure'.  Calling Get-HPOVEnclosure looking for it."        
            $Enclosures = Get-HPOVEnclosure $Enclosure 
    
        }
        elseif ($Enclosure -is [Array]) {

            $Enclosures += $Enclosure | % { Get-HPOVEnclosure $_ }

        }
        else { $Enclosures = $Enclosure }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Parameter Set Name resolved to: '$($PSCmdlet.ParameterSetName)' "

        #Perform the work
        ForEach ($encl in $Enclosures) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing Enclosure: '$($encl.name) [$($encl.uri)]'"
            
            switch ($PSCmdlet.ParameterSetName) {

                "Refresh" { 
                
                    #Set the URI
                    $uri = $encl.uri + "/refreshState"
                    
                    #Required to send Refresh command to Enclosure resource
                    $request = [pscustomobject]@{ refreshState = "RefreshPending"}
                    
                }

                "Reapply" { $uri = $encl.uri + "/configuration" }
                "Update" { $uri = $encl.uri + "/compliance" }
                
            }

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
            if ($request) { $task = Send-HPOVRequest $uri PUT $request }
            else { $task = Send-HPOVRequest $uri PUT }

            if ($monitor) { Wait-HPOVTaskComplete $task }
            else { $task }

        }

    }

}

function Get-HPOVEnclosure {

    # .ExternalHelp HPOneView.110.psm1-help.xml
  
    [CmdletBinding(DefaultParameterSetName = "default")]    
    Param (
        [parameter(Mandatory = $false,ParameterSetName = "default", Position = 0)]
		[parameter(Mandatory = $false,ParameterSetName = "export", Position = 0)]
		[parameter(Mandatory = $false,ParameterSetName = "report", Position = 0)]
        [parameter(Mandatory = $false,ParameterSetName = "list", Position = 0)]
        [string]$name=$null,

        [parameter (Mandatory = $false,ParameterSetName = "export", Position = 1)]
        [Alias("x", "export")]
        [ValidateScript({split-path $_ | Test-Path})]
        [String]$exportFile,
			
		[parameter (Mandatory = $false,ParameterSetName = "report")]
		[switch]$Report,

		[parameter (Mandatory = $false,ParameterSetName = "list")]
		[switch]$List

    )

    Begin {
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bound PS Parameters: $($PSBoundParameters | out-string)"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVEnclosure" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

	Process{

        $Uri = $enclosuresUri + "?sort=name:asc"
	    
        if ($name) { 
      
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for '$name' enclosure."
            $uri += "&filter=`"name matches '$name'`"" -replace "[*]","%25"

        }

        else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for all enclosures." }

        $encls = Send-HPOVRequest $uri

        if (-not ($encls.members) -and -not ($name)) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Enclosure resources found."
            #Return

        }
        elseif (-not ($encls.members) -and $name) {

            $errorRecord = New-ErrorRecord InvalidOperationException EnclosureResourceNotFound ObjectNotFound 'Get-HPOVEnclosure' -Message "Specified Enclosure '$name' was not found.  Please check the name and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)
            
        }
            		
		#Display a report of an enclsosure
        if ($Report) { $encls.members | % { Enclosure-Report $_ } }
        elseif ($List) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating list of enclosures"

            $e = @{Expression={$_.name};Label="Enclosure Name"},
                 @{Expression={$_.serialNumber};Label="Serial Number"},
                 @{Expression={$_.enclosureType};Label="Enclosure Model"},
                 @{Expression={$_.rackName};Label="Rack Name"},
                 @{Expression={$_.state};Label="State"},
                 @{Expression={
                
                    if ($_.enclosureGroupUri) { (Send-HPOVRequest $_.enclosureGroupUri).name }
                    else { "N/A" }
                
                 };Label="EG"},
                 @{Expression={
                 
                    $deviceBays = $_.deviceBays 
                    $count = ($deviceBays | ? { $_.devicePresence -eq "Present" -or $_.devicePresence -eq "subsumed"}).count
                    "$count/$($_.deviceBayCount)"};Label="Populated Bays"}

            $encls.members | Format-Table $e -AutoSize -Wrap
        }
		
		#display the JSON body of the enclosure
		elseif ($exportFile) { $encls.members | convertto-json > $exportFile }
		
		# else Return enclosure object
		else { 

            if ($encls.count -eq 1) { $encls.members[0] }
            else { $encls.members }
        
        }

        write-host "Done. $($encls.count) enclosure(s) found."

	}

}

function Enclosure-Report {
    <#
        .DESCRIPTION
        Internal helper function to display the report of an enclosure

        .PARAMETER Enclosure
        The enclosure object.
	
        .PARAMETER file
        File to save the report to.
	
        .INPUTS
        Enclosure object.

        .OUTPUTS
        Enclosure report.

        .LINK
        Get-HPOVEnclosure

        .LINK
        Send-HPOVRequest

        .EXAMPLE
        PS C:\> $enclosures = Get-HPOVEnclosure
        Return all the enclosure hardware  managed by this appliance.

    #>
     [CmdletBinding()]    
    Param
        (
            [parameter(Mandatory = $true,ValueFromPipeline=$true, Position=0)]
            [object]$Enclosure,
	
	        [parameter(Mandatory = $false,ValueFromPipeline=$false, Position=1)]
            [object]$file = $null,
	
		    [parameter(Mandatory = $false)]
            [switch]$fwreport
        )
	Process{	
		
		write-verbose "ENCLOSURE OBJECT:  $($enclosure)"
        write-verbose "ENCLOSURE UUID:  $($Enclosure.uuid)"
	
	#ENCLOSURE REPORT DATA
        $a = @{Expression={$_.name};Label="Enclosure Name";width=15}, `
        @{Expression={$_.serialNumber};Label="Serial Number";width=15}, `
        @{Expression={$_.enclosureType};Label="Enclosure Model";width=30}, `
        @{Expression={$_.rackName};Label="Rack Name";width=12}, `
        @{Expression={$_.isFwManaged};Label="FW Managed";width=10}, `
        @{Expression={$_.fwBaseLineName};Label="Baseline Name";width=30}

		#Generate Report
        $enclosure | format-table $a -AutoSize
		
		#License Intent Report
		$a = @{Expression={$_.licensingIntent};Label="Licensing";width=15}
		$enclosure | format-table $a -AutoSize
		
	#ONBOARD ADMINISTRATOR REPORT DATA
        $a = @{Expression={$_.bayNumber};Label="OA Bay";width=10}, `
        @{Expression={$_.role};Label="Role";width=15}, `
        @{Expression={$_.ipAddress};Label="IP Address";width=15}, `
        @{Expression={($_.fwVersion + " " + $_.fwBuildDate)};Label="Firmware Version";width=20}
        
        $enclosure.oa | Format-Table $a -AutoSize
		
	#DEVICE BAY REPORT DATA
		#Looking for servers related to the requested enclosure
		Write-Verbose "/rest/index/associations?parentUri=/rest/enclosures/$($Enclosure.uuid)&name=ENCLOSURE_TO_DEVICE_BAY"
		[object]$enclosureDeviceAssociation = Send-HPOVRequest "/rest/index/associations?parentUri=/rest/enclosures/$($Enclosure.uuid)&name=ENCLOSURE_TO_DEVICE_BAY"
        write-verbose $($enclosureDeviceAssociation)
		#temporary array variable to loop through device bays
		$deviceBays = @()
		$serversCol = @()
		
		#Loop through index results
		if ($enclosureDeviceAssociation.count -gt 0) {
			
			#Loop through index association results
			$enclosureDeviceAssociation.members | % { $deviceBays += send-hpovrequest $_.childuri }
			
			#Get server specific information that is not store in the Enclosure object, and save to $servers array
			$deviceBays | % { if ($_.devicePresence -eq 'present'){$serversCol += Send-HPOVRequest $_.deviceUri}}
		}
		
        $serversCol | out-string | write-verbose
		
		$a = @{Expression={$_.name};Label="Server Name";width=20}, `
        @{Expression={$_.serialNumber};Label="Serial Number";width=15}, `
        @{Expression={$_.shortModel};Label="Model";width=12}, `
        @{Expression={$_.romVersion};Label="System ROM";width=15}, `
        @{Expression={($_.mpModel + " " + $_.mpFirmwareVersion)};Label="iLO Firmware Version";width=22}, `
        @{Expression={
						if (!$_.serverProfileUri){ 'No Profile' }
						else { (Send-HPOVRequest $_.serverProfileUri).name }
				};Label="Server Profile";width=30},`
        @{Expression={$_.licensingIntent};Label="Licensing";width=15}
		
        $serversCol | Sort-Object name | format-table $a -AutoSize
		
	#INTERCONNECT BAY REPORT DATA
		#Loop through interconnect bays
		$interconnectsCol = @()

		foreach ($interconnect in $enclosure.interconnectBays){
			Write-Verbose "INTERCONNECT:  $($interconnect)"
            if ($interconnect.interconnectUri){

                #Get the Interconnect object to read properties
			    $tempInterconnect = Send-HPOVRequest $interconnect.interconnectUri

                #Get Logical Interconnect associated with the Interconnect to report its Name
				$li = Send-HPOVRequest $interconnect.logicalInterconnectUri
				$tempInterconnect | Add-Member -type NoteProperty -name liName -value $li.name
                $tempInterconnect | out-string | Write-Verbose
				$interconnectsCol += $tempInterconnect
		    }
		}

        #Display Interconnect information (Name, Model, Serial Number, FW Ver)
		$a = @{Expression={$_.name};Label="Interconnect Name";width=22}, `
		@{Expression={$_.model};Label="Module";width=38}, `
		@{Expression={$_.serialNumber};Label="Serial Number";width=20}, `
		@{Expression={$_.firmwareVersion};Label="Firmware Version";width=20}

        $interconnectsCol | format-Table $a -AutoSize

        #Display Interconnect information (PAD, Name, Logical Interconnect Name, State, Status)
        $a = @{Expression={'     '};Label="     ";width=5}, `
        @{Expression={$_.name};Label="Interconnect Name";width=22}, `
		@{Expression={$_.liName};Label="Logical Interconnect";width=30}, `
		@{Expression={$_.state};Label="State";width=14}, `
		@{Expression={$_.status};Label="Status";width=20},`
        @{Expression={ $tempLI = Send-HPOVRequest $_.logicalInterconnectUri
                        switch ($tempLI.consistencyStatus) {
        
                        'CONSISTENT' { "Consistent" }
                        'NOT_CONSISTENT' { "Inconsistent with group" }
                        default { $tempLI.consistencyStatus }
                     }};Label="Consistency state";width=26}

        $interconnectsCol | format-Table $a -AutoSize
		Write-Host "=================================================================================================================="
	}
}

function Remove-HPOVEnclosure {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param
    (
        [parameter (Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "default",
            HelpMessage = "Enter the enclosure to remove.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        [object]$enclosure,

        [parameter(Mandatory = $false)]
        [switch]$force
    )

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVEnclosure" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        foreach ($encl in $enclosure) {

            $enclosureNameOrUri = $null;
            $enclosureDisplayName = $null;
            
            if ($encl -is [String]) {
                $enclosureNameOrUri = $encl
                $enclosureDisplayName = $encl
            }

            elseif ($encl -is [PSCustomObject] -and $encl.category -ieq 'enclosures') {
                $enclosureNameOrUri = $encl.uri;
                $enclosureDisplayName = $encl.name;
            }

            #Invalid Enclosure parameter value
            else {
                $errorRecord = New-ErrorRecord System.ArgumentException InvalidParameter InvalidArgument "Remove-HPOVEnclosure" -Message "Invalid enclosure parameter: $encl" #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            if (!$enclosureNameOrUri) {

                $errorRecord = New-ErrorRecord System.ArgumentException InvalidParameter InvalidArgument "Remove-HPOVEnclosure" -Message "Invalid enclosure parameter: $encl" #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }
            elseif ($pscmdlet.ShouldProcess($enclosureDisplayName,'Remove enclosure from appliance?')){  
              
                if ([bool]$force) { Remove-HPOVResource -nameOrUri $enclosureNameOrUri -force }
                else { Remove-HPOVResource -nameOrUri $enclosureNameOrUri }

            }
        }
    }
}

function Get-HPOVServerHardwareType {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
	Param(
		[parameter(Position = 0, Mandatory = $false)]
		[string]$name=$null
	)

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVServerHardwareType" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        $sht = [PSCustomObject]@{ count = 0; total = 0; members = @() }

    }

    Process {
	
        if ($name.StartsWith($script:serverHardwareTypesUri)) {

            $object = Send-HPOVRequest $name

            if ($object) {

                $sht.members += $object
                $sht.count = 1
                $sht.total = 1

            }

        }
        else {

            if ($name) { $sht = Send-HPOVRequest ($script:serverHardwareTypesUri + "?filter=name='$name'") }
            else { $sht = Send-HPOVRequest $script:serverHardwareTypesUri }

        }

    }

    end {

        if (-not $sht.members -and $name ) {

            $errorRecord = New-ErrorRecord InvalidOperationException ServerHardwareTypeNotFound ObjectNotFound 'Get-HPOVSeverHardwareType' -Message "'$name' Server Hareware Type not found. Please check the name and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)

        }

        elseif (-not $sht.members) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Server Hardware Types found. Have you added an enclosure or supported server platform?"

        }

        else { $sht.members }
        
        "Done. {0} server hardware type resource(s) found." -f $sht.total | out-host
    }
}

function Show-HPOVFirmwareReport {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdletBinding()]
     
    Param (

        [parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [validateSet("EG","Enclosure","Server","Interconnect")]
        [String]$Resource,
	
	    [parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [String]$Name = $Null,
	
	    [parameter(Mandatory = $false, ValueFromPipeline = $True)]
        [Object]$Baseline,
            
		[parameter(Mandatory = $false)]
        [Switch]$Export,
            
		[parameter(Mandatory = $false)]
        [String]$Location = (get-location).Path

     )
	
    Begin { 
    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Validating user is authenticated"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Show-HPOVFirmwareReport" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        
        #Test for location
        if ($Export) {
        
            if ( -not (Test-Path $Location)) {  

                $errorRecord = New-ErrorRecord InvalidOperationException LocationPathNotFound ObjectNotFound 'Show-HPOVFirmwareReport' -Message "The specified path $Location does not exist. Please verify it and try again." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)
            
            }
        }
    
    }

    Process {	

        
    
        switch ($Resource) {

            "eg" {

                if ($name) { [array]$egs = Get-HPOVEnclosureGroup $name }
                else { [array]$egs = Get-HPOVEnclosureGroup }

                #If no results were found, terminate.  Error reporting is handled by Get-HPOVEnclosureGroup
                if ($egs) {

                    $Collection = @()

                    #Keep track of the number of Enclosure Groups
                    $script:g = 0

                    #Keep track of the number of Enclosures
                    $script:e = 0

                    foreach ($eg in $egs) {

                        $script:g++

                        #Handle the call from -Verbose so Write-Progress does not get borked on display.
                        if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Collecting Enclosure Firmware Information - Skipping Write-Progress display."  }
                    
                        else { Write-Progress -Id 1 -activity "Collecting Enclosure Group Firmware Information" -CurrentOperation "Processing `'$($eg.name)`': $g of $($egs.count) Enclosure Groups" -percentComplete (($g / $egs.count) * 100) }

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Enclosure Group to Enclosure associations, then getting found Enclosure Resources."
                        [Array]$enclosures = (Send-HPOVRequest "/rest/index/associations?parentUri=$($eg.uri)&name=ENCLOSURE_GROUP_TO_ENCLOSURE").members  | % { Send-HPOVRequest $_.childUri }
                        
                        #Make sure the EG has associated Enclosures.
                        if ($enclosures) {

                            foreach ($enclosure in $enclosures) { 

                                $script:e++

                                #Handle the call from -Verbose so Write-Progress does not get borked on display.
                                if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Collecting Enclosure Firmware Information - Skipping Write-Progress display."  }
                    
                                else { Write-Progress -ParentId 1 -id 2 -activity "Collecting Enclosure Firmware Information" -CurrentOperation "Processing `'$($enclosure.name)`': $e of $($enclosures.count) Enclosure(s)" -percentComplete (($e / $enclosures.count) * 100) }

                                $temp = Get-EnclosureFirmware $Enclosure $Baseline 1
                                $temp | add-member -Type NoteProperty -Name eg -value $eg.name
                                $Collection += $temp

                            } #End Enclosures

                        } #End Enclosure to EG check
                        
                        #Clear Child Write-Progress progress bars

                        #Handle the call from -Verbose so Write-Progress does not get borked on display.
                        if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Completed Collecting Enclosure Firmware Information - Skipping Write-Progress display."  }
             
                        else { Write-Progress -ParentId 1 -id 2 -activity "Collecting Enclosure Firmware Information" -CurrentOperation "Completed" -Completed }

                    } #End EG
                    
                    #Handle the call from -Verbose so Write-Progress does not get borked on display.
                    if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Completed Collecting Enclosure Group Firmware Information Skipping Write-Progress display."  }
             
                    else { Write-Progress -Id 1 -activity "Collecting Enclosure Group Firmware Information" -CurrentOperation "Completed" -Completed }

                }

            } #end eg switch

            "enclosure" {

	            if ($name) { [array]$enclosures = Get-HPOVEnclosure $name }
		
	            else { [array]$enclosures = Get-HPOVEnclosure}
		    
                $Collection = @()

                #Keep track of the number of enclosures
                $script:e = 0

                foreach ($enclosure in $enclosures) {

                    $script:e++

                    #Handle the call from -Verbose so Write-Progress does not get borked on display.
                    if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Collecting Enclosure Firmware Information - Skipping Write-Progress display."  }
                    
                    else { Write-Progress -Id 1 -activity "Collecting Enclosure Firmware Information" -CurrentOperation "Processing `'$($enclosure.name)`': $e of $($enclosures.count) Enclosure(s)" -percentComplete (($e / $enclosures.count) * 100) }

                    $Collection += Get-EnclosureFirmware $Enclosure $Baseline

                } #End Enclosures Collection

                #Handle the call from -Verbose so Write-Progress does not get borked on display.
                if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Completed Collecting Enclosure Firmware Information - Skipping Write-Progress display."  }
                
                else { Write-Progress -id 1 -activity "Collecting Enclosure Firmware Information" -CurrentOperation "Completed" -Completed }

            } #End Enclosure switch

            "server" { 

                $Collection = @()
            
                #Keep track of the number of Servers
                $script:s = 0

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Servers"
                
                if ($name) { [Array]$servers = Get-HPOVServer $Name }
                else { [Array]$servers = Get-HPOVServer }

                foreach ($server in $servers) {

                    $script:s++
                    
                    #Handle the call from -Verbose so Write-Progress does not get borked on display.
                    if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Collecting Server Firmware Information - Skipping Write-Progress display."  }
                     
                    else { Write-Progress -id 1 -activity "Collecting Server Firmware Information" -CurrentOperation "Processing `'$($server.name)`': $s of $($servers.Count) Server(s)" -percentComplete (($s / $servers.Count) * 100) }

                    $Collection += Get-ServerFirmware -server $server -baseline $baseline

                } #End Server Collection
                
                #Handle the call from -Verbose so Write-Progress does not get borked on display.
                if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Completed Collecting Server Firmware Information - Skipping Write-Progress display."  }
             
                else { Write-Progress -id 1 -activity "Collecting Server Firmware Information" -CurrentOperation "Completed" -Completed }
            
            } #End Server switch

            "interconnect" { 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Interconnects"

                if ($name) { [Array]$interconnects = Get-HPOVInterconnect -name $Name }
                else { [Array]$interconnects = Get-HPOVInterconnect }

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found $($interconnects.Count) Interconnects"

                $Collection = @()

                $script:i = 0
            
                #Get Interconnect Information
		        foreach ($interconnect in $interconnects) {

                    $script:i++

                    #Handle the call from -Verbose so Write-Progress does not get borked on display.
                    if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Collecting Interconnect Firmware Information - Skipping Write-Progress display."  }
             
                    else { Write-Progress -id 1 -activity "Collecting Interconnect Firmware Information" -CurrentOperation "Processing `'$($interconnect.name)`': $i of $($interconnects.Count) Interconnects" -percentComplete (($i / $interconnects.Count) * 100) }

                    $Collection += Get-InterconnectFirmware $interconnect $Baseline

                } #End Interconnects Collection
            
                #Handle the call from -Verbose so Write-Progress does not get borked on display.
                if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Completed Collecting Interconnect Firmware Information - Skipping Write-Progress display."  }
             
                else { Write-Progress -id 1 -activity "Collecting Interconnect Firmware Information" -CurrentOperation "Completed" -Completed }
            
            } #End Interconnect switch

        }

    }

    End {

        Write-Progress -Activity "Firmware collection report complete." -PercentComplete (100) -Status "Finished." -Completed

        #Generate alternate report for Enclosure Groups
        switch ($Resource) {
        
            "interconnect" {

                #Export to CSV
                if ($Export) { $collection | select-object EG, Name,Device,Component,Installed,Baseline,BaselinePolicy,Compliance | Export-Csv -Path $Location\interconnect_report_$(get-Date -uformat "%Y.%m.%d").csv -Encoding UTF8 -NoTypeInformation }

                #Display Report
                else {
                
                    $Table = @{Expression={$_.name};Label="Name"},
                             @{Expression={$_.device};Label="Device";width=16},
                             @{Expression={$_.installed};Label="Installed"},
                             @{Expression={$_.Baseline};Label="Baseline"},
                             @{Expression={$_.BaselinePolicy};Label="Baseline Policy"},
                             @{Expression={$_.Compliance};Label="Compliance"}

                     $collection | Sort-Object name | format-table $Table -Wrap

                }

                "Done: {0} interconnect(s) processed." -f $i

            }

            "server" {

                #Export to CSV
                if ($Export) { $collection | select-object Name,Device,Component,Installed,Baseline,BaselinePolicy,Compliance | Export-Csv -Path $Location\server_report_$(get-Date -uformat "%Y.%m.%d").csv -Encoding UTF8 -NoTypeInformation }

                #Display Report
                else {
                
                    $Table = @{Expression={$_.name};Label="Name"},
                             @{Expression={$_.device};Label="Device"},
                             @{Expression={$_.Component};Label="Component";width=10},
                             @{Expression={$_.installed};Label="Installed"; width=14},
                             @{Expression={$_.Baseline};Label="Baseline"; width=14},
                             @{Expression={$_.BaselinePolicy};Label="Baseline Policy"},
                             @{Expression={$_.Compliance};Label="Compliance"}

                     $collection | Sort-Object name | format-table $Table -Wrap

                }

                "Done: {0} server(s) processed." -f $s

            }

            "enclosure" {


                #Export to CSV
                if ($Export) { $collection | select-object Name,Device,Component,Installed,Baseline,BaselinePolicy,Compliance | Export-Csv -Path $Location\enclosure_report_$(get-Date -uformat "%Y.%m.%d").csv -Encoding UTF8 -NoTypeInformation }

                #Display Report
                else {
                
                    $Table = @{Expression={$_.name};Label="Name"},
                             @{Expression={$_.device};Label="Device";width=16},
                             @{Expression={$_.Component};Label="Component"},
                             @{Expression={$_.installed};Label="Installed"},
                             @{Expression={$_.Baseline};Label="Baseline"},
                             @{Expression={$_.BaselinePolicy};Label="Baseline Policy"},
                             @{Expression={$_.Compliance};Label="Compliance"}

                     $collection | Sort-Object name | format-table $Table -Wrap

                }

                write-host ""
                "Done: {0} enclosure(s), {1} server(s), {2} interconnect(s) processed." -f $e, $s, $i

            }
            
            "eg" {

                #Export to CSV
                if ($Export) { $collection | select-object Name,Device,Component,Installed,Baseline,BaselinePolicy,Compliance | Export-Csv -Path $Location\eg_report_$(get-Date -uformat "%Y.%m.%d").csv -Encoding UTF8 -NoTypeInformation }

                #Display Report
                else {
                
                    $Table = @{Expression={$_.eg};Label="EG"},
                             @{Expression={$_.name};Label="Name"},
                             @{Expression={$_.device};Label="Device";width=16},
                             @{Expression={$_.Component};Label="Component"},
                             @{Expression={$_.installed};Label="Installed"},
                             @{Expression={$_.Baseline};Label="Baseline"},
                             @{Expression={$_.BaselinePolicy};Label="Baseline Policy"},
                             @{Expression={$_.Compliance};Label="Compliance"}

                     $collection | Sort-Object name | format-table $Table -Wrap

                }

                "Done: {0} enclosure group(s), {1} enclosure(s), {2} server(s), {3} interconnect(s) processed." -f $g, $e, $s, $i

            }

        }

    }

}

function Get-EnclosureFirmware {

    <#
        Internal-only function.
    #>

    [CmdletBinding()]
    Param (
    
        [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Default", HelpMessage = "Enclosure resource object")]
        [PsCustomObject]$EnclosureObject = $Null, 

        [parameter(Position = 1, Mandatory = $false, ParameterSetName = "Default", HelpMessage = "SPP Baseline resource object, Name or URI")]
        [object]$Baseline = $Null,

        [parameter(Position = 2, Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Specify the level of the Write-Progress ID")]
        [int]$ProgressID = 0
        
    )


    Begin {

        #Reset private variables
        $BaseLinePolicy = $Null
        $enclosureReport = @()

        #Keep track of the number of Servers
        $script:s = 0

        #Keep track of the number of Interconnects
        $script:i = 0
		
        #Keep track of the number of OAs
        $o = 0

        #See if EnclosureObject was passed via Pipeline
        if (-not $PSBoundParameters['EnclosureObject']) { $PipelineInput = $True }

    }

    Process {
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Object passed via pipeline: $($PipelineInput)"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing Enclosure firmware report for: '$($enclosureObject.name)'"

        #Use the Enclosure FwBaseline if it is set
        if (($EnclosureObject.isFwManaged) -and ($Baseline -eq $Null)) { 

            $BaseLinePolicy = Send-HPOVRequest $EnclosureObject.fwBaselineUri
        
        }

        elseif (($Baseline) -and ($Baseline -is [PsCustomObject]) -and ($Baseline.category -eq "firmware-drivers")) { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline resource passed."
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline resource name: $($Baseline.baselineShortName)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline resource uri: $($Baseline.uri)"
            $BaseLinePolicy = $Baseline
            
        }
        
        #Check to see if the wrong Object has been passed
        elseif (($Baseline) -and ($Baseline -is [PsCustomObject]) -and ($Baseline.category -ne "firmware-drivers")) { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Invalid Baseline resource passed. Generating error."
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentType InvalidArgument 'GET-ENCLOSUREFIRMWARE' -Message "The wrong Baseline Object was passed.  Expected Category type `'firmware-drivers`', recieved `'$($Baseline.category)`' (Object Name: $($Baseline.name)" #-verbose
            $PsCmdLet.ThrowTerminatingError($errorRecord)
            
        }
        
        elseif (($Baseline) -and ($Baseline -is [string]) -and ($Baseline.StartsWith(($script:fwDriversUri)))) { 
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline URI passed: $Baseline"
            $BaseLinePolicy = Send-HPOVRequest $Baseline 
        
        }
        
        #Check to see if the wrong URI has been passed
        elseif (($Baseline) -and ($Baseline -is [string]) -and $Baseline.StartsWith("/rest/") -and ( ! $Baseline.StartsWith(("/rest/firmware-drivers/")))) { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Invalid Baseline URI passed. Generating error."
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentType InvalidArgument 'GET-ENCLOSUREFIRMWARE' -Message "The wrong Baseline URI was passed.  URI must start with '/rest/firmware-drivers/', recieved '$($Baseline)'" #-verbose
            $PsCmdLet.ThrowTerminatingError($errorRecord)        
            
        }
        
        elseif (($Baseline) -and ($Baseline -is [string])) { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline Name passed: $Baseline"
            $BaseLinePolicy = Get-HPOVSppFile -name $Baseline 
            
        }
        
        else { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Baseline provided."
            $BaseLinePolicy = [PsCustomObject]@{ baselineShortName = "No Policy Set" } 
        
        }

        #Get OA Firmware Information
		foreach ($oa in $EnclosureObject.oa) {

            #Handle the call from -Verbose so Write-Progress does not get borked on display.
            if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Collecting Onboard Administrator Firmware Information - Skipping Write-Progress display."  }
            
            else { Write-Progress -id (2 + $ProgressID) -ParentId 1 -activity "Collecting Onboard Administrator Firmware Information" -CurrentOperation "Processing `'$($oa.role)`': $o of $($enclosure.oa.count) OAs" -percentComplete (($o / $EnclosureObject.oa.count) * 100) }

            #If OA is absent report it as such
            if ($oa.role -eq "OaAbsent") { $enclosureReport += [pscustomobject]@{ Name = $EnclosureObject.name; Device = ($Enclosure.enclosureType.substring(0,($enclosure.enclosureType.length - 3))); Component = "OA Bay $($oa.bayNumber) Absent"; Installed = "N/A"; Baseline = "N/A" ; BaselinePolicy = "N/A"; Compliance = "N/A" } }
		    
            else {
                if ($BaseLinePolicy.baselineShortName -eq "No Policy Set") { $BaselineVer = "N/A" }

                else { $BaselineVer = ($BaseLinePolicy.fwComponents | where { $_.swKeyNameList -match "oa" }).componentVersion }

                if ($BaselineVer -eq "N/A") { $Compliance = "N/A" }
                elseif (($oa.fwVersion -lt $BaselineVer) -or ($oa.fwVersion -lt $BaselineVer)) { $Compliance = "Not Compliant" } 
                else { $Compliance = "Compliant" }

		        $enclosureReport += [pscustomobject]@{ Name = $EnclosureObject.name; Device = ($Enclosure.enclosureType.substring(0,($enclosure.enclosureType.length - 3))); Component = "OA Bay $($oa.bayNumber) $($oa.role)"; Installed = $oa.fwVersion; Baseline = $BaselineVer ; BaselinePolicy = $BaseLinePolicy.baselineShortName; Compliance = $Compliance }
            }
		          
            $o++
		
		} #End OA's

        #Get Server Resource Objects
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Server resources from the enclosure."
        $servers = ($EnclosureObject.deviceBays | where { $_.devicePresence -eq "present" } | % { Send-HPOVRequest $_.deviceUri })

        foreach ($server in $servers) {

            $script:s++

            #Handle the call from -Verbose so Write-Progress does not get borked on display.
            if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Collecting Server Firmware Information - Skipping Write-Progress display."  }
             
            else { Write-Progress -id (3 + $ProgressID) -ParentId 1 -activity "Collecting Server Firmware Information" -CurrentOperation "Processing `'$($server.name)`': $s of $($servers.Count) Server(s)" -percentComplete (($s / $servers.Count) * 100) }

            $enclosureReport += Get-ServerFirmware $server $Baseline

        } #end Servers Collection

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Interconnect resources from the enclosure."
        $interconnects = ($enclosure.interconnectBays | where { $_.interconnectUri -ne $Null } | % { Send-HPOVRequest $_.interconnectUri })

        #Get Interconnect Information
		foreach ($interconnect in $interconnects) {

            $script:i++

            #Handle the call from -Verbose so Write-Progress does not get borked on display.
            if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Collecting Interconnect Firmware Information - Skipping Write-Progress display."  }
             
            else { Write-Progress -id (4 + $ProgressID) -ParentId 1 -activity "Collecting Interconnect Firmware Information" -CurrentOperation "Processing `'$($interconnect.name)`': $i of $($interconnectS.Count) Interconnects" -percentComplete (($i / $interconnectS.Count) * 100) }

            $enclosureReport += Get-InterconnectFirmware $interconnect $Baseline

        } #End Interconnects Collection

        #Handle the call from -Verbose so Write-Progress does not get borked on display.
        if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Completed Collecting OA/Server/Interconnect Firmware Information - Skipping Write-Progress display."  }
         
        else { 
        
            Write-Progress -ParentId 1 -id (2 + $ProgressID) -activity "Collecting Onboard Administrator Firmware Information" -CurrentOperation "Completed" -Completed                    
            Write-Progress -ParentId 1 -id (3 + $ProgressID) -activity "Collecting Server Firmware Information" -CurrentOperation "Completed" -Completed
            Write-Progress -ParentId 1 -id (4 + $ProgressID) -activity "Collecting Interconnect Firmware Information" -CurrentOperation "Completed" -Completed

        }

    }


    end {

        Return $enclosureReport

    }

}

function Get-ServerFirmware {

    <#
        Internal-only function.
    #>

    [CmdletBinding()]
    Param (
    
        [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Default", HelpMessage = "Server resource object")]
        [PsCustomObject]$serverObject, 

        [parameter(Position = 1, Mandatory = $false, ParameterSetName = "Default", HelpMessage = "SPP Baseline resource object, Name or URI")]
        [object]$Baseline = $Null
        
    )


    Begin {

        #See if serverObject was passed via Pipeline
        if (-not $PSBoundParameters['serverObject']) { $PipelineInput = $True }
        
        $serverReport = @()

    }

    Process {
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server Object passed via pipeline: $($PipelineInput)"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing Server firmware report for: '$($server.name)'"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Server Hardware Type"
        #Check if the server hardware type allows firmware management
        $sht = Send-HPOVRequest $server.serverHardwareTypeUri

        if ($sht.capabilities -match "FirmwareUpdate") {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server Hardware Type supports firmware management."

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline value provided: '$Baseline'"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($Baseline | out-string)'"

            #If a bladeserver and that the caller hasn't specified a Baseline, Use the Enclosure FwBaseline if it is set
            if (-not $Baseline) { 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Baseline provided.  Checking Server Profile."

                #Check to see if there is a profile
                if ($server.serverProfileUri) {
                            
                    $profile = Send-HPOVRequest $server.serverProfileUri

                    #Then check if a Baseline is attached there
                    if ($profile.firmware.manageFirmware) { 
                    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server Profile has baseline attached. Geting baseline details."
                        $BaselinePolicy = Send-HPOVRequest $profile.firmware.firmwareBaselineUri 
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server Profile Baseline name: $($BaselinePolicy.name)"
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server Profile Baseline name: $($BaselinePolicy.uri)"
                    }
                    
                    #If firmware is not managed by the profile, check if the server is a BL and if Enclosure has a baseline assigned.
                    elseif ($server.locationUri) {
                    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server Profile does not have a baseline attached. Checking Enclosure."
                        $Enclosure = Send-HPOVRequest $server.locationUri

                        #Use the Enclosure FwBaseline if it is set
                        if ($enclosure.isFwManaged) { 
                        
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure has baseline attached. Geting baseline details."                
                            $BaseLinePolicy = Send-HPOVRequest $enclosure.fwBaselineUri
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Baseline name: $($BaselinePolicy.name)"
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Baseline name: $($BaselinePolicy.uri)"
                                
                        }

                        else {
                        
                            write-verbose "[GETSERVERFIRMWARE] Enclosure does not have a baseline policy set."
                            $BaseLinePolicy = [PsCustomObject]@{ baselineShortName = "No Policy Set" } 

                        }

                    }
                                    
                    #If not, set $BaselinePolicy to No Policy Set
                    else { 
                    
                        if (-not $server.locationUri) { write-verbose "[GETSERVERFIRMWARE] Server is not a BL, so no Enclosure to check." }
                        write-verbose "[GETSERVERFIRMWARE] Server Profile does not have a baseline attached."
                        $BaseLinePolicy = [PsCustomObject]@{ baselineShortName = "No Policy Set" } 
                        
                    }

                }

                else {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Server Profile assigned."

                    if ($server.locationUri) {
                    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Checking Enclosure for policy."
                        $Enclosure = Send-HPOVRequest $server.locationUri

                        #Use the Enclosure FwBaseline if it is set
                        if ($enclosure.isFwManaged) { 

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure has baseline attached. Geting baseline details."                
                            $BaseLinePolicy = Send-HPOVRequest $enclosure.fwBaselineUri
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Baseline name: $($BaselinePolicy.name)"
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Baseline name: $($BaselinePolicy.uri)"
                                
                        }

                        else {
                        
                            write-verbose "[GETSERVERFIRMWARE] Enclosure does not have a baseline policy set."
                            $BaseLinePolicy = [PsCustomObject]@{ baselineShortName = "No Policy Set" } 

                        }

                    }

                    #If not, set $BaselinePolicy to No Policy Set
                    else { 
                    
                        if (-not $server.locationUri) { write-verbose "[GETSERVERFIRMWARE] Server is not a BL, so no Enclosure to check." }
                        write-verbose "[GETSERVERFIRMWARE] Server Profile does not have a baseline attached."
                        $BaseLinePolicy = [PsCustomObject]@{ baselineShortName = "No Policy Set" } 
                        
                    }

                }
                   
            }

            elseif (($Baseline) -and ($Baseline -is [PsCustomObject]) -and ($Baseline.category -eq "firmware-drivers")) { 
            
                write-verbose "[GETSERVERFIRMWARE] Baseline resource passed."
                write-verbose "[GETSERVERFIRMWARE] Baseline resource name: $($Baseline.baselineShortName)"
                write-verbose "[GETSERVERFIRMWARE] Baseline resource uri: $($Baseline.uri)"
                $BaseLinePolicy = $Baseline
                
            }

            #Check to see if the wrong Object has been passed
            elseif (($Baseline) -and ($Baseline -is [PsCustomObject]) -and ($Baseline.category -ne "firmware-drivers")) { 
            
                write-verbose "[GETSERVERFIRMWARE] Invalid Baseline resource passed. Generating error."
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentType InvalidArgument 'getserverfirmware' -Message "The wrong Baseline Object was passed.  Expected Category type `'firmware-drivers`', recieved `'$($Baseline.category)`' (Object Name: $($Baseline.name)" #-verbose
                $PsCmdLet.ThrowTerminatingError($errorRecord)
                
            }

            elseif (($Baseline) -and ($Baseline -is [string]) -and ($Baseline.StartsWith(($script:fwDriversUri)))) { 
                
                write-verbose "[GETSERVERFIRMWARE] Baseline URI passed: $Baseline"
                $BaseLinePolicy = Send-HPOVRequest $Baseline 
            
            }

            #Check to see if the wrong URI has been passed
            elseif (($Baseline) -and ($Baseline -is [string]) -and $Baseline.StartsWith("/rest/") -and ( ! $Baseline.StartsWith(("/rest/firmware-drivers/")))) { 

                write-verbose "[GETSERVERFIRMWARE] Invalid Baseline URI passed. Generating error."
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentType InvalidArgument 'getserverfirmware' -Message "The wrong Baseline URI was passed.  URI must start with '/rest/firmware-drivers/', recieved '$($Baseline)'" #-verbose
                $PsCmdLet.ThrowTerminatingError($errorRecord)        
                
            }

            elseif (($Baseline) -and ($Baseline -is [string])) { 
            
                write-verbose "[GETSERVERFIRMWARE] Baseline Name passed: $Baseline"
                $BaseLinePolicy = Get-HPOVSppFile -name $Baseline 
                
            }

            else { 
            
                write-verbose "[GETSERVERFIRMWARE] No Baseline provided."
                $BaseLinePolicy = [PsCustomObject]@{ baselineShortName = "No Policy Set" } 
            
            }

            write-verbose "[GETSERVERFIRMWARE] Processing Server ROM Information."

            #Saving SystemROM Information
            $serverRomVersion = ($server.romVersion -replace "/",".").SubString(4)

            #Check Baseline Policy and set Compliance statement
            if ($BaseLinePolicy.baselineShortName -eq "No Policy Set") { 
                            
                $BaselineVer = "N/A" 
                $Compliance = "N/A"
                                    
            }

            else { 
                            
                $BaselineVer = ($BaseLinePolicy.fwComponents | where { $_.swKeyNameList -match $server.romVersion.SubString(0,3) }).componentVersion
                write-verbose "Found Baseline version: $($BaselineVer | out-string)"
                if ($BaselineVer -is [Array]) { $BaselineVer = get-Date -format MM.dd.yyyy $BaselineVer[0] }
                else { $BaselineVer = get-Date -format MM.dd.yyyy $BaselineVer }

                if ($BaselineVer -eq "N/A") { $Compliance = "N/A" }
                elseif (($serverRomVersion -gt $BaseLineVer) -or ($serverRomVersion -lt $BaseLineVer)) { $Compliance = "Not Compliant" } 
                else { $Compliance = "Compliant" } 
            }

            $serverReport += [pscustomobject]@{ Name = $server.name; Device = $server.shortModel; Component = "ROM"; Installed = $serverRomVersion; Baseline = $BaselineVer ; BaselinePolicy = $BaseLinePolicy.baselineShortName; Compliance = $Compliance }

            write-verbose "[GETSERVERFIRMWARE] Processing Server iLO Information."

            #Saving iLO Information
            $mpFirmwareVersion = $server.mpFirmwareVersion.SubString(0,4)

            #Check Baseline Policy and set Compliance statement
            if ($BaseLinePolicy.baselineShortName -eq "No Policy Set") {
                            
                $BaselineVer = "N/A" 
                $Compliance = "N/A"
                                    
            }

            else { 
                            
                $BaselineVer = ($BaseLinePolicy.fwComponents | where { $_.swKeyNameList -match $script:mpModelTable.($server.mpModel) }).componentVersion

                if ($BaselineVer -is [Array]) { $BaselineVer = $BaselineVer[0] }

                #Check iLO Version Compliance
                if ($BaselineVer -eq "N/A") { $Compliance = "N/A" }
                elseif (($mpFirmwareVersion -gt $BaseLineVer) -or ($mpFirmwareVersion -lt $BaseLineVer)) { $Compliance = "Not Compliant" } 
                else { $Compliance = "Compliant" } 
                                
            }

            $serverReport += [pscustomobject]@{ Name = $server.name; Device = $server.shortModel; Component = "iLO"; Installed = $mpFirmwareVersion; Baseline = $BaselineVer ; BaselinePolicy = $BaseLinePolicy.baselineShortName; Compliance = $Compliance  }

        }

        #Server firmware is unmanageable based on its Server Hardware Type
        else { 
            
            write-verbose "[GETSERVERFIRMWARE] Server Hardware Type does not support firmware management."      
            $serverReport += [pscustomobject]@{ Name = $server.name; Device = $server.shortModel; Component = "N/A"; Installed = "N/A"; Baseline = "N/A" ; BaselinePolicy = "Unmanageable" }

        }

    }


    end {

        Return $serverReport

    }

}

function Get-InterconnectFirmware {

    <#
        Internal-only function.
    #>

    [CmdletBinding()]
    Param (
    
        [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Default", HelpMessage = "Interconnect resource object")]
        [PsCustomObject]$interconnectObject, 

        [parameter(Position = 1, Mandatory = $false, ParameterSetName = "Default", HelpMessage = "SPP Baseline resource object, Name or URI")]
        [object]$Baseline = $Null
        
    )


    Begin {

        $interconnectReport = @()

    }

    Process {
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing Interconnect firmware report for: '$($InterconnectObject.name)'"
        
        if (-not $Baseline) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline was not provided, checking Enlosure Firmware Baseline set."
            $enclosure = send-hpovrequest $interconnect.enclosureUri

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enlosure Firmware Baseline set: $($enclosure.isFwManaged )"

            #Check if the Enclosure has a Firmware Baseline attached
            if ($enclosure.isFwManaged -and $enclosure.fwBaselineUri){ 
    
                $baseline = Get-HPOVSppFile $enclosure.fwBaselineUri
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enlosure Firmware Baseline name: $($baseline.name )"
            }

            else { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Baseline provided."
                $BaseLinePolicy = [PsCustomObject]@{ baselineShortName = "No Policy Set" } 
            
            }
        }

        else {
            
            if (($Baseline) -and ($Baseline -is [PsCustomObject]) -and ($Baseline.category -eq "firmware-drivers")) { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline resource passed."
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline resource name: $($Baseline.baselineShortName)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline resource uri: $($Baseline.uri)"
                $BaseLinePolicy = $Baseline
                
            }

            #Check to see if the wrong Object has been passed
            elseif (($Baseline) -and ($Baseline -is [PsCustomObject]) -and ($Baseline.category -ne "firmware-drivers")) { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Invalid Baseline resource passed. Generating error."
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentType InvalidArgument 'Get-InterconnectFirmware' -Message "The wrong Baseline Object was passed.  Expected Category type `'firmware-drivers`', recieved `'$($Baseline.category)`' (Object Name: $($Baseline.name)" #-verbose
                $PsCmdLet.ThrowTerminatingError($errorRecord)
                
            }

            elseif (($Baseline) -and ($Baseline -is [string]) -and ($Baseline.StartsWith(($script:fwDriversUri)))) { 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline URI passed: $Baseline"
                $BaseLinePolicy = Send-HPOVRequest $Baseline 
            
            }

            #Check to see if the wrong URI has been passed
            elseif (($Baseline) -and ($Baseline -is [string]) -and $Baseline.StartsWith("/rest/") -and ( ! $Baseline.StartsWith(("/rest/firmware-drivers/")))) { 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Invalid Baseline URI passed. Generating error."
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentType InvalidArgument 'Get-InterconnectFirmware' -Message "The wrong Baseline URI was passed.  URI must start with '/rest/firmware-drivers/', recieved '$($Baseline)'" #-verbose
                $PsCmdLet.ThrowTerminatingError($errorRecord)        
                
            }

            elseif (($Baseline) -and ($Baseline -is [string])) { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Baseline Name passed: $Baseline"
                $BaseLinePolicy = Get-HPOVSppFile -name $Baseline 
                
            }

            else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Unknown baseline." }

        }

        if ($BaseLinePolicy.baselineShortName -eq "No Policy Set") { 
        
            $BaselineVer = "N/A"
            $Compliance = "N/A"

        }
        else { 
        
            $BaselineVer = ($BaseLinePolicy.fwComponents | where { $_.swKeyNameList -match "vceth" }).componentVersion

            if (($InterconnectObject.firmwareVersion -lt $BaselineVer) -or ($InterconnectObject.firmwareVersion -lt $BaselineVer)) { $Compliance = "Not Compliant" } 
            else { $Compliance = "Compliant" }

        }
        
        $interconnectReport = [pscustomobject]@{ Name = $InterconnectObject.name; Device = $InterconnectObject.model; Component = (Get-Culture).TextInfo.ToTitleCase($InterconnectObject.type) ; Installed = $InterconnectObject.firmwareVersion; Baseline = $BaselineVer ; BaselinePolicy = $BaseLinePolicy.baselineShortName; Compliance = $Compliance }
    }

    end {

        Return $interconnectReport

    }

}

#######################################################
# Storage Systems and Volume Management:
#

function Get-HPOVStorageSystem {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "Name")]
    Param (
        [parameter(Mandatory = $false, HelpMessage = "Enter the Storage System name.", ParameterSetName = "Name", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string]$SystemName,

        [parameter(Mandatory = $false, HelpMessage = "Enter the Storage System serial number.", ParameterSetName = "Serial",Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('SN')]
        [string]$SerialNumber,

        [parameter(Mandatory = $false, HelpMessage = "Display output in Table List format.", ParameterSetName = "Name")]
        [parameter(Mandatory = $false, HelpMessage = "Display output in Table List format.", ParameterSetName = "Serial")]
        [Alias('Report')]
        [switch]$List

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageSystem' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process { 

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of Storage Systems"
        $uri = $script:storageSystemUri

        if ($SystemName)       { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering for systemName property"
            $uri += "?filter=name matches $SystemName'" -replace "[*]","%25"
            
        }
        
        elseif ($SerialNumber) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering for serialNumber property"
            $uri += "?filter=serialNumber='$SerialNumber'"
            
        }

        $storageSystems = Send-HPOVRequest $uri

        #Generate Terminating Error if resource not found
        if (-not $storageSystems.members -and ($SystemName -or $SerialNumber)) {
            
            if ($SystemName) { 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! No '$SystemName' Storage System found."
                    
                $errorRecord = New-ErrorRecord InvalidOperationException StorageSystemResourceNotFound ObjectNotFound 'Get-HPOVStorageSystem' -Message "No Storage System with '$SystemName' system name found.  Please check the name or use Add-HPOVSanManager to add the Storage System." #-verbose

            }

            elseif ($SerialNumber) { 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! No Storage System with '$SerialNumber' serial number found."
                    
                $errorRecord = New-ErrorRecord InvalidOperationException StorageSystemResourceNotFound ObjectNotFound 'Get-HPOVStorageSystem' -Message "No Storage System with '$SerialNumber' serial number found.  Please check the serial number or use Add-HPOVSanManager to add the Storage System." #-verbose

            }

                                
            #Generate Terminating Error
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! No Storage Systems found."

        }

    }

    end {

        if ($List) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating List display"

            foreach ($system in $storageSystems.members) {
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($system.name)' Storage System."
                
                #Storage System Details
                $a = @{Expression={$_.status};Label="Status"}, `
                     @{Expression={$_.name};Label="Name"}, `
                     @{Expression={$_.serialNumber};Label="Serial Number"}, `
                     @{Expression={$_.model};Label="Model"}, `
                     @{Expression={$_.managedDomain};Label="Storage Domain"}, `
                     @{Expression={$_.wwn};Label="WWN"}, `
                     @{Expression={$_.firmware};Label="Firmware"}

                $system | format-table $a -autosize -wrap

                #Storage System Credentials and Address
                $b = @{Expression={"   "};Label="[Credentials]"}, `
                     @{Expression={$_.credentials.username};Label="Username"}, `
                     @{Expression={$_.credentials.ip_hostname};Label="Address"}

                $system | format-table $b -autosize -wrap
 
                #Capacity Details
                $c = @{Expression={"   "};Label="[Capacity]"}, `
                     @{Expression={$_.status};Label="Status"}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.totalCapacity / 1TB)
                        $value + "TB"
                     };Label="Total   "}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.allocatedCapacity / 1TB)
                        $value + "TB"
                     };Label="Allocated  "}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.freeCapacity / 1TB)
                        $value + "TB"
                     };Label="Free   "}

                $system | format-table $c -autosize -wrap
                
                #Managed Storage Pools
                $d = @{Expression={"   "};Label="[Managed Storage Pools]"}, `
                     @{Expression={$_.status};Label="Status"}, `
                     @{Expression={$_.name};Label="Name   "}, `
                     @{Expression={$_.deviceType};Label="Drive Type"}, `
                     @{Expression={$_.supportedRAIDLevel};Label="RAID"}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.totalCapacity / 1GB)
                        $value + "GB"
                     };Label="Total   "}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.allocatedCapacity / 1GB)
                        $value + "GB"
                     };Label="Allocated  "}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.freeCapacity / 1GB)
                        $value + "GB"
                     };Label="Free   "},`
                     @{Expression={ (Send-HPOVRequest ($script:indexUri + "?category=storage-volumes&query=storage_volume_storagepool_uri:'$($_.uri)'")).count};Label="Volumes"}

                $system.managedPools | sort-object 'Name' | format-table $d -autosize -wrap

                #Unmanaged Pools
                $e = @{Expression={"   "};Label="[Unmanaged Storage Pools]"}, `
                     @{Expression={$_.name};Label="Name   "}, `
                     @{Expression={$_.deviceType};Label="Drive Type"}, `
                     @{Expression={$_.supportedRAIDLevel};Label="RAID"}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.totalCapacity / 1GB)
                        $value + "GB"
                     };Label="Total   "}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.allocatedCapacity / 1GB)
                        $value + "GB"
                     };Label="Allocated  "}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.freeCapacity / 1GB)
                        $value + "GB"
                     };Label="Free   "}

                $unmanagedPools = $system.unmanagedPools | ? { $_.domain -eq $system.managedDomain }
                if ($unmanagedPools) { $unmanagedPools | sort-object 'Name' | format-table $e -autosize -wrap }
                else { 
                    ""
                    "[Unmanaged Storage Pools] Name     Drive Type RAID  Total          Allocated   Free"
                    "------------------------- -------  ---------- ----  --------       ----------- -------"
                    "No unmanaged pools available in '{0}' Managed Domain" -f $system.managedDomain 
                    ""
                    ""
                }

                #Configured Host Ports
                $f = @{Expression={"   "};Label="[Host Ports]"}, `
                     @{Expression={$_.status};Label="Status"}, `
                     @{Expression={$_.portName};Label="Port   "}, `
                     @{Expression={$_.portWwn};Label="WWPN                   "}, `
                     @{Expression={
                         $net = send-hpovrequest $_.expectedNetworkUri
                         "$($net.name) ($(if ($net.fabricType -eq "FabricAttach") {"FA"}
                                          else {"DA"}))"
                     };Label="Expected Network"}, `
                     @{Expression={
                         $net = send-hpovrequest $_.actualNetworkUri
                         "$(if ($net.name) {$net.name} else { "None" }) ($(if ($net.fabricType -eq "FabricAttach") {"FA"}
                                          else {"DA"}))"
                     };Label="Actual Network"}, `
                     @{Expression={$_.groupName};Label="Port Group Name"}

                $system.managedPorts | sort-object 'Port' | format-table $f -autosize -wrap

                if ($storageSystems.count -gt 1) {

                    "=================================================================================================================="
                    ""
                }
                                
            }

        }

        else {
        
            if( $storageSystems.members.length -eq 1) { $storageSystems.members[0] }
            else { $storageSystems.members }
        }

        write-host "Done. $($storageSystems.count) storage system(s) found."
    }

}

function Update-HPOVStorageSystem {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "Name")]
    Param (
        [parameter(Mandatory = $false, ValueFromPipeLine = $True, HelpMessage = "Enter the Storage System name.", ParameterSetName = "Name", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [Object]$StorageSystem,

        [parameter(Mandatory = $false, HelpMessage = "Enter the Storage System serial number.", ParameterSetName = "Serial",Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('SN')]
        [string]$SerialNumber

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageSystem' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process { 

        if (-not $StorageSystem) { 
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Storage System resource(s) provided. Calling Get-HPOVStorageSystem."
            $StorageSystem = Get-HPOVStorageSystem 
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found [$($StorageSystem.length)] Storage Systems."
        
        }

        ForEach ($system in $StorageSystem) {

            switch ($system.gettype().name) {

                "String" { 
                    
                    #URI of Storage System provided
                    if ($system.StartsWith($script:storageSystemUri)) {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] URI was provided, getting resource."
                        $ss = Send-HPOVRequest $system

                    }

                    #Storage System Name
                    else {
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] System Name was provided, calling Get-HPOVStorageSystem."
                        $ss = Get-HPOVStorageSystem $system

                    }
                
                }

                "PSCustomObject" {
                
                    if ($system.category -eq "storage-systems") {
                    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage System resource object provided"
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage System Name: $($system.name)"
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage System URI: $($system.uri)"
                    }

                    else {

                        #Wrong category, generate error
                        $errorRecord = New-ErrorRecord ArgumentException WrongCategoryType InvalidResult 'Update-HPOVstorageSystem' -Message "The '$($system.category)' is the wrong value.  Only 'storage-systems' category is allowed.  Please check the value and try again." #-verbose
                        $PSCmdlet.ThrowTerminatingError($errorRecord)

                    }
                }

                default {                         
                    
                    #Wrong category, generate error
                    $errorRecord = New-ErrorRecord ArgumentException UnsupportedDataType InvalidArgument 'Update-HPOVstorageSystem' -Message "The [$($system.Gettype())] is unsupported.  Only [System.String], [System.Array] or [System.Management.Automation.PSCustomObject] are allowed.  Please check the value and try again." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                        
                }

            }

            $ss.refreshState = "RefreshPending"
            $results += @(Send-HPOVRequest $ss.uri PUT $ss)
        }
   
    }

    end {

        if ($results.length -eq 1) { return $results[0] }
        else { return $results }

    }

}

function Add-HPOVStorageSystem {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true, position = 0, HelpMessage = "Enter the host name (FQDN) or IP of the Storage System.")]
        [ValidateNotNullOrEmpty()]
        [string]$hostname,
         
        [parameter(Mandatory = $true, position = 1, HelpMessage = "Enter the administrative user name (i.e. 3paradm).")]
        [ValidateNotNullOrEmpty()]
        [string]$username="",

        [parameter(Mandatory = $true, position = 2, HelpMessage = "Enter the administrative account password (i.e. 3pardata).")]
        [ValidateNotNullOrEmpty()]
        [string]$password="",

        [parameter(Mandatory = $false, position = 3, HelpMessage = "Specify the HP 3PAR Virtual Domain Name to Import resources from.")]
        [ValidateNotNullOrEmpty()]
        [String]$Domain = 'NO DOMAIN',

        [parameter(Mandatory = $false, position = 4, HelpMessage = "Specify the Host Ports and Expected Network in an Array of PSCustomObject entries. Example: @{`"1:1:1`"=`"Fabric A`";`"2:2:2`"=`"Fabric B`"}")]
        [ValidateNotNullOrEmpty()]
        [PsCustomObject]$Ports
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Add-HPOVStorageSystem' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $storageSystemCredentials = [pscustomobject]@{ip_hostname = $hostname; username = $username; password = $password}

        $storageSystemDiscoveryTask = Send-HPOVRequest $script:storageSystemUri POST $storageSystemCredentials

        $storageSystemDiscoveredTask = Wait-HPOVTaskComplete $storageSystemDiscoveryTask

        if ($storageSystemDiscoveredTask.taskState -eq "Completed") {

            $connectedStorageSystem = Send-HPOVRequest $storageSystemDiscoveredTask.associatedResource.resourceUri
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($connectedStorageSystem.name)' Storage System."
            
            $connectedStorageSystem | ForEach-Object -process {    
                #Storage System Details
                $a = @{Expression={$_.status};Label="Status"}, `
                        @{Expression={$_.name};Label="Name"}, `
                        @{Expression={$_.serialNumber};Label="Serial Number"}, `
                        @{Expression={$_.model};Label="Model"}, `
                        @{Expression={$_.wwn};Label="wwn"}, `
                        @{Expression={$_.firmware};Label="Firmware"}

                $connectedStorageSystem | format-table $a -autosize | out-host

                #Capacity Details
                $c = @{Expression={"   "};Label="[Capacity]"}, `
                        @{Expression={$_.status};Label="Status"}, `
                        @{Expression={
                        $value = '{0:N2}' -f ($_.totalCapacity / 1TB)
                        $value + "TB"
                        };Label="Total   "}, `
                        @{Expression={
                        $value = '{0:N2}' -f ($_.allocatedCapacity / 1TB)
                        $value + "TB"
                        };Label="Allocated  "}, `
                        @{Expression={
                        $value = '{0:N2}' -f ($_.freeCapacity / 1TB)
                        $value + "TB"
                        };Label="Free   "}

                $connectedStorageSystem | format-table $c -autosize | out-host
                
                #Storage Pools
                $d = @{Expression={"   "};Label="[Storage Pools]"}, `
                        @{Expression={$_.status};Label="Status"}, `
                        @{Expression={$_.name};Label="Name   "}, `
                        @{Expression={if($_.domain) {$_.domain} else { "None" } };Label="Domain "}, `
                        @{Expression={$_.deviceType};Label="Drive Type"}, `
                        @{Expression={$_.supportedRAIDLevel};Label="RAID"}, `
                                    @{Expression={
                    $value = '{0:N2}' -f ($_.totalCapacity / 1GB)
                    $value + "GB"
                    };Label="Total   "}, `
                                    @{Expression={
                    $value = '{0:N2}' -f ($_.allocatedCapacity / 1GB)
                    $value + "GB"
                    };Label="Allocated  "}, `
                                    @{Expression={
                    $value = '{0:N2}' -f ($_.freeCapacity / 1GB)
                    $value + "GB"
                    };Label="Free   "}

                $connectedStorageSystem.unmanagedPools | sort-object 'Name' | format-table $d -autosize | out-host

                #Configured Host Ports
                $e = @{Expression={"   "};Label="[Storage Ports]"}, `
                        @{Expression={$_.status};Label="Status"}, `
                        @{Expression={$_.portName};Label="Port   "}, `
                        @{Expression={$_.portWwn};Label="WWPN                   "}, `
                        @{Expression={
                            if ($_.expectedNetworkUri -and -not ($_.expectedNetworkUri -eq "unknown") ) {
                                $net = send-hpovrequest $_.expectedNetworkUri
                                if ($net.fabricType -eq "FabricAttach") {"$($net.name) [FA]"}
                                else {" $($net.name) [DA]"}
                            }
                            else { $_.expectedNetworkUri }
                        };Label="Expected Network"}, `
                        @{Expression={
                            if ($_.actualNetworkUri -and -not ($_.actualNetworkUri -eq "unknown") ) {
                                $net = send-hpovrequest $_.actualNetworkUri
                                if ($net.fabricType -eq "FabricAttach") {"$($net.name) [FA]"}
                                else {" $($net.name) [DA]"}
                            }
                            else { $_.actualNetworkUri }
                        };Label="Actual Network"}, `
                        @{Expression={$_.groupName};Label="Port Group Name"}

                $connectedStorageSystem.unmanagedPorts | sort-object 'Port' | format-table $e -autosize | out-host
            }

            #Handle Host Port configuration
            if (-not $Ports) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Ports parameter was not provided.  Using Default values."

                $managedPorts = @()

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $($connectedStorageSystem.unmanagedPorts.count) unmanaged ports."

                #Loop through all ports, looking for actualNetworkUri property set.
                foreach ($port in $connectedStorageSystem.unmanagedPorts) {

                    $tempManagedPort = [pscustomobject]@{type = "StorageTargetPort"; portName = $Null; actualNetworkUri = $Null; portWwn = $Null; expectedNetworkUri = $Null; groupName = $Null; name = $Null}
    
                    #If $Ports parameter was not passed, take the discovered Actual Network URI and default
                    if ($port.actualNetworkUri -and $port.actualNetworkUri -ne "unknown") {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] actualNetworkUri contains value for port '$($port.name)'"

                        $tempManagedPort.portName = $port.portName
                        $tempManagedPort.actualNetworkUri = $port.actualNetworkUri
                        $tempManagedPort.portWwn = $port.portWwn
                        $tempManagedPort.expectedNetworkUri = $port.actualNetworkUri
                        $tempManagedPort.groupName = "Auto"
                        $tempManagedPort.name = $port.name

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] tempManagedPort: $($tempManagedPort | out-string)"
                        $managedPorts += $tempManagedPort
                    }

                }

                if ($managedPorts.Count -eq 0) { 
                
                    #Output warning or non-terminating error?
                    write-warning "No storage system ports have an expected network value!"
                }

            }

            #If user provided the ports
            elseif ($Ports) {

                $managedPorts = @()

                $Ports.GetEnumerator() | ForEach-Object -process {
                    # First get the network.  Will error if network does not exist
                    $sNet = Get-HPOVNetwork -type fc -name $_.value

                    #if the network exists, get the port from unmanaged ports list
                    $pname = $_.key
                    $tempPort = $connectedStorageSystem.unmanagedPorts | ? {$_.name -eq $pname}

                    #update the port parameters
                    $tempPort.expectedNetworkUri = $sNet.uri
                    $tempPort.actualNetworkUri = $sNet.uri
                    $tempPort.groupName = "Auto"

                    #add the port to the managed ports list
                    $managedPorts += $tempPort

                    #remove the port from the unmanaged ports list
                    $tempUnmanagedPorts = $connectedStorageSystem.unmanagedPorts | ? {$_.name -ne $pname}
                    $connectedStorageSystem.unmanagedPorts = $tempUnmanagedPorts
                }

            }
                
            #update managed ports list
            $connectedStorageSystem.managedPorts = $managedPorts

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Adding $($managedPorts.count) managed ports. $($connectedStorageSystem.unmanagedPorts.count - $managedPorts.count) remaining unmanaged ports to be claimed later." 

            #Validate the $Domain parameter exists in the list of unmanaged domains returned in the connect call
            if ($connectedStorageSystem.unmanagedDomains -contains $Domain){

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found Virtual Domain '$Domain'."
                #The domain exists, update the managedDomain property
                $connectedStorageSystem.managedDomain = $Domain

                #remove the domain from the unManagedDomains property
                $unManaged=@()
                $unManaged = $connectedStorageSystem.unmanagedDomains | ? {$_ -ne $Domain}
                $connectedStorageSystem.unmanagedDomains = $unManaged
                }
            else {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Domain '$Domain' not found. Cleaning up."
                Send-HPOVRequest -uri $connectedStorageSystem.uri -method DELETE

                $errorRecord = New-ErrorRecord InvalidOperationException StorageDomainResourceNotFound ObjectNotFound 'Add-HPOVStorageSystem' -Message "Storage Domain, '$Domain', not found.  Please check the storage domain exist on the storage system." #-verbose
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
            #$ports.Keys | %{ "key is: $($_), value is $($ports[$_])" }

        }

        else {

            #ERROR
            $connectedStorageSystem
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task error ocurred. Generating error message."
            
            $errorRecord = New-ErrorRecord InvalidOperationException $storageSystemDiscoveredTask.taskErrors[0].errorCode InvalidResult 'Add-HPOVStorageSystem' -Message "$($storageSystemDiscoveredTask.taskErrors[0].message)" #-verbose
            #WRITE-ERROR "AN ERROR OCURRED. $($storageSystemDiscoveredTask.taskErrors[0].errorCode) $($storageSystemDiscoveredTask.taskErrors[0].message)" -ErrorAction Stop
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #$connectedStorageSystem
        
        $task = Send-HPOVRequest -method PUT -body $connectedStorageSystem -uri $connectedStorageSystem.uri
    }

    end {

        return $task

    }
   
}

function Remove-HPOVStorageSystem {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [parameter (Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "default", HelpMessage = "Enter the Storage System to remove.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri","name")]
        [object]$storageSystem,

        [parameter(Mandatory = $false)]
        [switch]$force
    )

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVStorageSystem" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
        
    }

    Process {

        foreach ($ss in $storageSystem) {
            $ssNameOrUri = $null;
            $ssDisplayName = $null;
            if ($ss -is [String] -and ! $ss.startswith($script:storageSystemUri)) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] storageSystem (NAME) parameter type is System.String, and value passed is $($ss)"
                $ssNameOrUri = $ss
                $ssDisplayName = $ss
            }
            elseif ($ss -is [String] -and $ss.startswith($script:storageSystemUri)) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] storageSystem (URI) parameter type is System.String, and value passed is $($ss)"
                $ssNameOrUri = $ss
                $ssDisplayName = $ss
            }
            elseif ($ss -is [PSCustomObject] -and $ss.category -ieq 'storage-systems') {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] storageSystem parameter type is PsCustomObject."
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] storageSystem URI is $($ss.uri)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] storageSystem URI is $($ss.name)"

                $ssNameOrUri = $ss.uri
                $ssDisplayName = $ss.name

            }
            else {

                $errorRecord = New-ErrorRecord System.ArgumentException InvalidStorageSystemParameter InvalidArgument 'Remove-HPOVStorageSystem' -Message "Invalid storage system parameter: $ss" #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)

            }

            if (!$ssNameOrUri) {

                if ($ss.name) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] The storage system '$($ss.nam)' provided was not found. Please check the storageSystem parameter value and try again." }
                else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] The storage system '$($ss)' provided was not found. Please check the storageSystem parameter value and try again." }

            }
            elseif ($pscmdlet.ShouldProcess($ssDisplayName,'Remove storage system from appliance?')){

                if ([bool]$force) { Remove-HPOVResource -nameOrUri $ssNameOrUri -force }
                else { Remove-HPOVResource -nameOrUri $ssNameOrUri }                
                
            }
        }
    }
}

function Get-HPOVStoragePool {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "Name")]
    Param (
        [parameter(Mandatory = $false, HelpMessage = "Enter the Storage Pool name.", ParameterSetName = "Name", Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('pool', 'name')]
        [string]$poolName,

        [parameter(Mandatory = $false, HelpMessage = "Enter the Storage System Name or provide the Resource Object.", ParameterSetName = "Name", Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('systemName', 'system')]
        [object]$storageSystem,

        [parameter(Mandatory = $false, HelpMessage = "Display output in Table List format.", ParameterSetName = "Name")]
        [Alias('Report')]
        [switch]$List

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageSystem' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of Storage Pools"

        $uri = $script:storagePoolUri

        #if poolName parameter was provided, append an API filter for the Pool Resource Name
        if ($poolName) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] -poolName was provided.  Filtering for '$poolname'"
            $uri += "?filter=name matches '$poolName'" -replace "[*]","%25"
            
        }

        #Send the query
        $storagePools = Send-HPOVRequest $uri

        if ($storageSystem -is [String] -and !$storageSystem.startswith($script:storageSystemUri)) { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem Name was provided."
            $system = Get-HPOVStorageSystem -SystemName $storageSystem

            if (!$system.uri) {
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage system $storageSystem does not exist on the appliance"
            
                $errorRecord = New-ErrorRecord InvalidOperationException StorageSystemResourceNotFound ObjectNotFound 'Get-HPOVStoragePool' -Message "Storage system '$storageSystem' not found.  Please check the name and try again." #-verbose

                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)    

            }
            
            #Filter results until the API can provide them for us.
            [array]$storagePools.members = $storagePools.members | ? { $_.storageSystemUri -eq $system.uri }
            $storagePools.count = $storagePools.members.length
            $storagePools.total = $storagePools.members.length
            
        }

        elseif ($storageSystem -is [PsCustomObject] -and $storageSystem.category -eq "storage-systems") { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem Object provided"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem Name: $($storageSystem.name)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem Uri: $($storageSystem.uri)"
            
            [array]$storagePools.members = $storagePools.members | ? { $_.storageSystemUri -eq $storageSystem.uri }
            $storagePools.count = $storagePools.members.length
            $storagePools.total = $storagePools.members.length

        }

    }

    end {

        if (!$storagePools.members -and $name){
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage Pool '$name' not found."
            
                $errorRecord = New-ErrorRecord InvalidOperationException StoragePoolResourceNotFound ObjectNotFound 'Get-HPOVStoragePool' -Message "Storage Pool '$name' not found.  Please check the name and try again." #-verbose

                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)    

        }
        elseif (!$storagePools.members -and -not $name){
            
            #No storage pools found matching the provided crterial
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No storage pools found."
            
            $Null

        }

        else {
            
            if ($List) {

                $d = @{Expression={$_.status};Label="Status"}, `
                     @{Expression={$_.name};Label="Name"}, `
                     @{Expression={(send-hpovrequest $_.storageSystemUri).name};Label="Storage System"}, `
                     @{Expression={$_.domain};Label="Storage Domain"}, `
                     @{Expression={$_.deviceType};Label="Drive Type"}, `
                     @{Expression={$_.supportedRAIDLevel};Label="RAID"}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.totalCapacity / 1GB)
                        $value + "GB"
                     };Label="Total   "}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.allocatedCapacity / 1GB)
                        $value + "GB"
                     };Label="Allocated  "}, `
                     @{Expression={
                        $value = '{0:N2}' -f ($_.freeCapacity / 1GB)
                        $value + "GB"
                     };Label="Free   "}, `
                     @{Expression={ (Send-HPOVRequest ($script:indexUri + "?category=storage-volumes&query=storage_volume_storagepool_uri:'$($_.uri)'")).count};Label="Volumes"}, `
                     @{Expression={ (Send-HPOVRequest ($script:indexUri + "?sort=name:asc&category=storage-volume-templates&query=storagePoolUri:'$($_.uri)'")).count};Label="Volume Templates"}

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Displaying formated table list."

                $storagePools.members | sort-object 'Name' | format-table $d -autosize
            }
            
            else { $storagePools.members }

        }

        "Done. {0} storage pool(s) found." -f $storagePools.count | out-host

    }

}

function Add-HPOVStoragePool {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "Name")]
    Param (
        [parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Enter the Storage System name.", ParameterSetName = "Name", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Hostname', 'name')]
        [object]$StorageSystem,

        [parameter(Mandatory = $true, HelpMessage = "Provide array of Storage Pool names.", ParameterSetName = "Name", Position=1)]
        [ValidateNotNullOrEmpty()]
        [Alias('pool', 'spName', 'cpg')]
        [array]$poolName

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Add-HPOVStorageSystem' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        [array]$pools = @()

    }

    Process {
        
        ForEach($p in $poolName){

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$p'"

            #If the Storage System resource object was passed, allow it
            if ($StorageSystem -is [PsCustomObject] -and $StorageSystem.category -eq "storage-systems") { 
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage System resource object was provided: $($StorageSystem | out-string)"
                
                $storageSystems = $StorageSystem 
                
            }
            
            #else the PsCustomObject is not the correct Category type, so error.
            elseif ($StorageSystem -is [PsCustomObject]) {
            
                $errorRecord = New-ErrorRecord InvalidOperationException WrongResourceCategoryValue InvalidArgument 'Add-HPOVStoragePool' -Message "The -StroageSystem paramete value is the wrong resource type ($($StorageSystem.category)). The correct resource category 'storage-systems' is allowed.  Please check the value and try again." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

            #Do not allow an array
            elseif ($StorageSystem -is [Array]) {

                $errorRecord = New-ErrorRecord InvalidOperationException ArrayNotAllow InvalidArgument 'Add-HPOVStoragePool' -Message "The -StorageSystem parameter only accepts [System.String] or [System.Management.Automation.PSCustomObject] value.  Please correct the value and try again." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            else {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage System Name is passed"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of Storage Systems"
                $storageSystems = Get-HPOVStorageSystem -SystemName $StorageSystem
            }

            #Generate Terminating Error if Storage System resource not found
            if (!$storageSystems) {
                    
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! No '$StorageSystem' Storage System found."
                $errorRecord = New-ErrorRecord InvalidOperationException StorageSystemResourceNotFound ObjectNotFound 'Add-HPOVStoragePool' -Message "No Storage System with '$StorageSystem' system name found.  Please check the name or use Add-HPOVStorageSystem to add the Storage System." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

            #Get the list of unmanaged and managed pools in the managed domain
            
            $ump = $storageSystems.unmanagedPools | ? {$_.domain -eq $storageSystems.managedDomain}
            $mp = $storageSystems.managedPools | ? {($_.domain -eq $storageSystems.managedDomain) -and ($_.name -eq $p)}
            if($mp){
                #Should this be terminating, or just write-error?
                #Storage pool resource already exists in the managed list
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage pool resource '$($p)' already exists in the managed list. Generating non-terminating error"
                $errorRecord = New-ErrorRecord InvalidOperationException StoragePooResourceExists ResourceExists 'Add-HPOVStoragePool' -Message "Storage pool resource '$p' already exists in the managed list." #-verbose
                $PSCmdlet.WriteError($errorRecord) #"Storage pool resource '$p' already exists"
            }
            elseif(!$ump){
                #Storage pool resource does not exist in the existing managed list or in the unmanaged list in the managed domain
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Storage pool resource with '$p' found in the managed Storage System.  Generating terminating error."
                $errorRecord = New-ErrorRecord InvalidOperationException StorageSystemResourceNotFound ObjectNotFound 'Add-HPOVStoragePool' -Message "No Storage pool resource with '$p' found in the managed Storage System." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

            else{
                #Good here... Add the storage pool
                $addPool = @{
                            storageSystemUri = $storageSystems.uri;
                            poolName = $p
                            }
                
                #add the pool to array of pools to manage
                $pools += $addPool
            }

        }

    }

    end  {

        if($pools){
            #$pools | convertto-json
            #If any pools in the passed array of names are valid, add them
            #append to uri for this call
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to appliance."
            
            $uri = $script:storagePoolUri + "?multiResource=true"
            $resp = Send-HPOVRequest -method POST -body $pools -uri $uri
            $resp
            #if (-not $resp -is [Array]) { }
        }

    }

}

function Remove-HPOVStoragePool {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param
    (
        [parameter (Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "default",HelpMessage = "Specify the storage pool to remove.",Position=0)]
        [parameter (Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "StorageSystem",HelpMessage = "Specify the storage pool to remove.",Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        [object]$storagePool=$null,

        [parameter (Mandatory = $true,ValueFromPipeline=$false, ParameterSetName = "StorageSystem",HelpMessage = "Specify the Storage System Name, URI or Resource Object where the Storage Pool is located to remove.",Position=1)]
        [ValidateNotNullOrEmpty()]
        [Alias("storage")]
        [object]$storageSystem=$null
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVStoragePool" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        [array]$taskResp = @()

    }

    Process {

        foreach ($sp in $storagePool) {
            $spNameOrUri = $null;
            $storagePoolDisplayName = $null;

            #Network passed is a URI
            if (($sp -is [String]) -and ($sp.startsWith("/rest"))) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received URI: $($sp)"
                $spNameOrUri = $sp
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting storage pool Name"
                $spDisplayName = (Send-HPOVRequest $sp).name
            }

            #Storage pool passed is the Name
            elseif (($sp -is [string]) -and (!$sp.startsWith("/rest"))) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received storage pool Name $($sp)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting storage pool"

                #NEED TO VALIDATE
                [object]$storagePool = (Get-HPOVStoragePool -poolName $sp)
                if ($storagePool.count -gt 1 -and !$storageSystem) { 
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received multiple Storage Pool resources with the same name.  Generating terminating error."
                    $errorRecord = New-ErrorRecord InvalidOperationException MultipleResultsFound InvalidResult 'Remove-HPOVStoragePool' -Message "Storage pool Name $sp is not unique. Please use the -StorageSystem parameter and try again." #-verbose
                    $pscmdlet.ThrowTerminatingError($errorRecord)
                    #Write-Error "Storage pool Name $($sp) is not unique" -Category InvalidResult -CategoryTargetName "REMOVE-HPOVSTORAGEPOOL"; return
                }

                elseif ($storagePool.count -gt 1 -and $storageSystem) { 
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] -StorageSystem parameter was passed."
                        
                    if ($storageSytem -is [String] -and $storageSystem.startsWith("/rest")) {
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem parameter is an resource URI. Getting resource object."    
                        $storageSystemObj = send-hpovrequest $storageSystem

                    }
                    
                    elseif ($storageSystem-is [String] -and !$storageSystem.startsWith("/rest")) {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem parameter is a resource Name. Sending request to Get-HPOVStorageSystem."
                        $storageSystemObj = Get-HPOVStorageSystem -SystemName $storageSystem
                    }

                    elseif ($storageSystem -is [PSCustomObject] -and $storageSystem.category -ieq 'storage-systems') {
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem parameter is a resource object."
                        $storageSystemObj = $storageSystem
                        
                    }

                    else {
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem parameter is invalid. Generating terminating error."

                        #generate error due to wrong object or object data with $storageSystem parameter
                        $errorRecord = New-ErrorRecord System.ArgumentException InvalidArgumentValue InvalidArgument 'Remove-HPOVStoragePool' -Message "StorageSystem parameter is invalid and not of type System.String or PSCustomObject with Category of 'storage-systems'." #-verbose
                        $pscmdlet.ThrowTerminatingError($errorRecord)

                    }
                    

                    #Loop through managed pools ($storageSystemObj.managedPools) to locate pool resource ($sp)
                    $storageSystemObj = $storageSystemObj.managedPools | ? { $_.name -eq $sp }
                    $spNameOrUri = $storageSystemObj.uri
                    $spDisplayName = $storageSystemObj.name

                }
                else {
                    $spNameOrUri = $storagePool.uri
                    $spDisplayName = $storagePool.name
                }
            }

            #Network passed is the object
            elseif ($sp -is [PSCustomObject] -and ($sp.category -ieq 'storage-pools')) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())]"
                $spNameOrUri = $sp.uri;
                $spDisplayName = $sp.name;
            }
            else {
                
                $errorRecord = New-ErrorRecord System.ArgumentException InvalidArgumentValue InvalidArgument 'Remove-HPOVStoragePool' -Message "Invalid storage pool parameter value: $sp" #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)
                #Write-Error "Invalid storage pool parameter: $sp"
                #return

            }

            if (!$spNameOrUri) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No storage pool resources found."

            }
            elseif ($pscmdlet.ShouldProcess($spDisplayName,'Remove storage pool from appliance?')) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User confirmed removal of storage pool resource."
                $taskResp += Remove-HPOVResource -nameOrUri $spNameOrUri

            }

        }

    }

    end {

        Return $taskResp

    }

}

function Get-HPOVStorageVolumeTemplate {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "Name")]
    Param (

        [parameter(Position = 0, Mandatory = $false, HelpMessage = "Enter the Volume template name.", ParameterSetName = "Name")]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string]$templateName,

        [parameter(Mandatory = $false, ParameterSetName = "Name")]
        [switch]$List

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageVolumeTemplate' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process { 

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of Storage Volume Templates"
        $storageVolumeTemplates = (Send-HPOVRequest $script:storageVolumeTemplateUri).members

        if ($templateName) { $storageVolumeTemplates = $storageVolumeTemplates | where { $_.name -eq $templateName } }

        #Generate Terminating Error if resource not found
        if (! $storageVolumeTemplates) {
            
            if ($storageVolumeTemplates) { 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$storageVolumeTemplates' Storage Volume Template not found."
                    
                $errorRecord = New-ErrorRecord InvalidOperationException StorageVolumeResourceNotFound ObjectNotFound 'Get-HPOVStorageVolumeTemplate' -Message "No Storage Volume with '$storageVolumeTemplates' name found.  Please check the name or use New-HPOVStorageVolumeTemplate to create the volume." #-verbose

                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            
            }

            else {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Storage Volume Templates found."

            }

        }

        if ($List) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating List display"
                
            #Storage Volume Display List
            $a = @{Expression={$_.status};Label="Status"}, `
                    @{Expression={$_.name};Label="Name"}, `
                    @{Expression={$_.provisioning.provisionType};Label="Provisioning"}, `
                    @{Expression={
                    if ($_.provisioning.shareable) { "Shared"}
                    else              { "Private" }
                    };Label="Sharing"}, `
                    @{Expression={
                    $value = '{0:N2}' -f ($_.provisioning.capacity / 1GB)
                    $value + "GB"
                    };Label="Requested Capacity"}, `
                    @{Expression={"$((send-hpovrequest $_.provisioning.storagePoolUri).name) ($((send-hpovrequest $_.storageSystemUri).name))"};Label="Storage Pool (System)"}

            $storageVolumeTemplates | sort-object 'name' | format-table $a -autosize

        }

        else { return $storageVolumeTemplates }
    
    }
}

function New-HPOVStorageVolumeTemplate {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "default")]
    Param (
        [parameter(Mandatory = $true, HelpMessage = "Enter the Volume Template Name.", ParameterSetName = "default")]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string]$templateName,

        [parameter(Mandatory = $false, ParameterSetName = "default")]
        [string]$description=$null,

        [parameter(Mandatory = $true, HelpMessage = "Enter the Storage Pool Name, URI or provide the resource object.", ParameterSetName = "default")]
        [object]$storagePool = $Null,

        [parameter(Mandatory = $false, HelpMessage = "Enter the Storage System Name, URI or provide the resource object.", ParameterSetName = "default")]
        [object]$StorageSystem = $Null,

        [parameter(Mandatory = $true, HelpMessage = "Enter the requested capacity in GB.", ParameterSetName = "default")]
        [Alias('size')]
        [int32]$capacity,

        [parameter(Mandatory = $false, ParameterSetName = "default")]
        [switch]$full=$false,

        [parameter(Mandatory = $false, ParameterSetName = "default")]
        [switch]$shared=$false

    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        #Storage Pool Name
        if ($storagePool -is [String] -and !$storagePool.StartsWith($script:storagePoolUri)) {
            
            write-verbose "[NBEW-HPOVSTORAGEVOLUMETEMPLATE] StoragePool name provided as parameter value: $($storagePool)"
            $tmpStoragePool = $storagePool

            #First look for the Storage Pool.
            if ($StorageSystem -is [string]) { $storagePool = Get-HPOVStoragePool $storagePool $StorageSystem }
            elseif ($StorageSystem -is [PsCustomObject]) { $storagePool = Get-HPOVStoragePool $storagePool $StorageSystem }
            else { $storagePool = Get-HPOVStoragePool $storagePool }

            #If multiple Storage Pool Resources are returned that are of the same name, generate error and indicate the -StorageSystem parameter is needed.
            #Validate that the storage pool object is unique and not a collection
            if($storagePool -is [Array] -and !$StorageSystem){

                write-verbose "[HPOVStorageVolumeTemplate] Multiple Storage Pool resources of the name '$tmpStoragePool'. $($storagePool.count) resources found."
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidStoragePoolResource ObjectNotFound 'New-HPOVStorageVolumeTemplate' -Message "Multiple Storage Pools it the '$tmpStoragePool' name were found.  Please use the -StorageSystem parameter to specify the Storage System the Pool is associated with, or use the Get-HPOVStoragePool cmdlet to get the Storage Pool resource and pass as the -StoragePool parameter value."
                
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

        }

        #Storage Pool URI
        elseif ($storagePool -is [String] -and $storagePool.StartsWith($script:storagePoolUri)) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StoragePool URI provided: $storagePool"
            $storagePool = Send-HPOVRequest $storagePool

            if ($storagePool.statusCode) {

                $errorRecord = New-ErrorRecord InvalidOperationException $storagePool.errorCode InvalidOperation 'New-HPOVStorageVolumeTemplate' -Message ($storagePool.details + " " + $storagePool.recommendedActions[0] )
                
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

        }

        #Storage Pool Object
        elseif ($storagePool -is [PsCustomObject] -and $storagePool.category -eq "storage-pools") {

            write-verbose "[NBEW-HPOVSTORAGEVOLUMETEMPLATE] StoragePool resource provided."
            write-verbose "[NBEW-HPOVSTORAGEVOLUMETEMPLATE] StoragePool Name: $($storagePool.name)"
            write-verbose "[NBEW-HPOVSTORAGEVOLUMETEMPLATE] StoragePool URI: $($storagePool.uri)"

        }

        #PsCustomObject provided but wrong category, which would be wrong resource, so generate error
        elseif ($storagePool -is [PsCustomObject] -and $storagePool.category -ne "storage-pools") {

            $errorRecord = New-ErrorRecord ArgumentException WrongCategoryType InvalidArgument 'New-HPOVStorageVolumeTemplate' -Message "The StoragePool resource category '$($storagePool.category)' is the wrong type.  The resource category should be 'storage-pools'.  Please check the value and try again." #-verbose
            
            #Generate Terminating Error
            $PSCmdlet.ThrowTerminatingError($errorRecord)        

        }

        #End catch and will be error if reaching this point
        else { 
        
            $errorRecord = New-ErrorRecord ArgumentException InvalidArgumentType InvalidArgument 'New-HPOVStorageVolumeTemplate' -Message "The StoragePool data type '$($storagePool.gettype().fullname)' is an unsupported data type.  Only [System.String] or [System.ObjectSystem.Management.Automation.PSCustomObject] are supported date types.  Please check the value and try again." #-verbose
            
            #Generate Terminating Error
            $PSCmdlet.ThrowTerminatingError($errorRecord)        
        
        }
        
        #Validate that the storage pool object is unique and not a collection
        if($storagePool -is [Array]){

            write-verbose "[HPOVStorageVolumeTemplate] Not a valid storage pool resource object."
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidStoragePoolResource ObjectNotFound 'New-HPOVStorageVolumeTemplate' -Message "The storage pool object is not a valid instance of an object"
            
            #Generate Terminating Error
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        

        #Translate the capacity to GB
        [int64]$capacity = $capacity * 1GB

        #Translate for provisioning type (thin/full) from the cmdlet switch
        if([bool]$full){$provisionType = "Full"}
        else {$provisionType = "Thin"}
            
        #Build the Object
        [psCustomObject]$provisioning = @{
                        capacity = $capacity;
                        provisionType = $provisionType;
                        shareable = [bool]$shared;
                        storagePoolUri = $storagePool.uri
                        }

        [psCustomObject]$svt = @{
                name = $templateName;
                description = $description;
                provisioning = $provisioning;
                type = "StorageVolumeTemplate"
                }

        #Send the request
        Send-HPOVRequest -method POST -uri $script:storageVolumeTemplateUri -body $svt

    }

}

function Remove-HPOVStorageVolumeTemplate {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
       [parameter (Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "default",
            HelpMessage = "Specify the storage pool to remove.",
            Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        [object]$templateName=$null
    )

    Process {
        foreach ($svt in $templateName) {
            $svtNameOrUri = $null;
            $svtDisplayName = $null;

            #Network passed is a URI
            if (($svt -is [String]) -and ($svt.startsWith("/rest"))) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received URI: $($svt)"
                $svtNameOrUri = $svt
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting storage volume template name"
                $svtDisplayName = (Send-HPOVRequest $svt).name
            }

            #Storage pool passed is the Name
            elseif (($svt -is [string]) -and (!$svt.startsWith("/rest"))) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received storage volume template name $($svt)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting storage volume template"

                #NEED TO VALIDATE
                $templateName = Get-HPOVStorageVolumeTemplate $svt
                if ($templateName.count -gt 1 ) { 
                Write-Error "Storage volume template name $($svt) is not unique" -Category InvalidResult -CategoryTargetName "REMOVE-HPOVSTORAGEVOLUMETEMPLATE"; return
                }
                else {
                    $svtNameOrUri = $templateName.uri
                    $svtDisplayName = $templateName.name
                }
            }

            #Network passed is the object
            elseif ($templateName -is [PSCustomObject] -and ($svt.category -ieq 'storage-volume-templates')) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())]"
                $svtNameOrUri = $svt.uri;
                $svtDisplayName = $svt.name;
            }
            else {
                Write-Error "Invalid storage volume template parameter: $svt"
                return
            }

            if (!$svtNameOrUri) {
                Write-Error "Invalid storage volume template parameter: $svt"
            }
            elseif ($pscmdlet.ShouldProcess($svtDisplayName,'Remove storage volume template from appliance?')) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())]"
                Remove-HPOVResource -nameOrUri $svtNameOrUri
            }
        }
    }

}

function Get-HPOVStorageVolumeTemplatePolicy {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdLetBinding(DefaultParameterSetName = "default")]
    Param ()

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageVolumeTemplatePolicy' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting global setting value."
        $script:storageVolumeTemplateRequiredGlobalPolicy = (Send-HPOVRequest /rest/global-settings/StorageVolumeTemplateRequired).value
        
        switch ($script:storageVolumeTemplateRequiredGlobalPolicy) {

            "True" { Return $True }
            "False" { Return $False }

        }

    }

}

function Set-HPOVStorageVolumeTemplatePolicy {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdLetBinding(DefaultParameterSetName = "default")]
    Param (
    
        [parameter(Mandatory = $True, HelpMessage = "Enable Storage Volume Template global policy.", ParameterSetName = "Enable")]
        [switch]$Enable,
              
        [parameter(Mandatory = $True, HelpMessage = "Disable Storage Volume Template global policy.", ParameterSetName = "Disable")]
        [switch]$Disable    
    
    
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageVolumeTemplatePolicy' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        switch ($PsCmdlet.ParameterSetName) {

            'Enable' {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User requested to ENABLE the policy"
                $request = [PSCustomObject]@{type = "Setting"; name = "StorageVolumeTemplateRequired"; value = "true"}
            
            }

            'Disable' {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User requested to DISABLE the policy"
                $request = [PSCustomObject]@{type = "Setting"; name = "StorageVolumeTemplateRequired"; value = "false"}
            
            }

        }

        $resp = Send-HPOVRequest /rest/global-settings/StorageVolumeTemplateRequired PUT $request

        if ($resp.errorCode) {
            
            $errorRecord = New-ErrorRecord InvalidOperationException $resp.errorCode InvalidResult 'Set-HPOVStorageVolumeTemplatePolicy' -Message $resp.details #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    end {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Calling 'Get-HPOVStorageVolumeTemplatePolicy' to get global setting."
        Get-HPOVStorageVolumeTemplatePolicy

    }

}

function Get-HPOVStorageVolume {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "Name")]
    Param (
        [parameter(Mandatory = $false, HelpMessage = "Enter the Volume name.", ParameterSetName = "Name", Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string]$VolumeName = $Null,

        [parameter(Mandatory = $false, HelpMessage = "Show only available storage volumes", ParameterSetName = "Name")]
        [switch]$Available,

        [parameter(Mandatory = $false, HelpMessage = "Display output in Table List format.", ParameterSetName = "Name")]
        [Alias('Report')]
        [switch]$List

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageVolume' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process { 

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of Storage Volumes"

        if ($VolumeName -and [bool]!$available) { $uri = $script:storageVolumeUri + "?filter=name matches '$VolumeName'" -replace "[*]","%25" }
        elseif ($VolumeName -and [bool]$available) { $uri = $script:attachableVolumesUri + "?filter=name matches '$VolumeName'"  -replace "[*]","%25" }
        elseif (!$VolumeName -and [bool]$available) { $uri = $script:attachableVolumesUri }
        else { $uri = $script:storageVolumeUri }
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Query: $($uri)"

        #Send the query
        $storageVolumes = Send-HPOVRequest $uri

        #Generate Terminating Error if resource not found
        if (-not $storageVolumes.members) {
            
            if ($VolumeName) { 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! No '$VolumeName' Storage Volume found."
                    
                $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException StorageVolumeResourceNotFound ObjectNotFound 'Get-HPOVStorageVolume' -Message "No Storage Volume with '$VolumeName' name found.  Please check the name or use New-HPOVStorageVolume to create the volume." #-verbose
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            else {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! No Storage Volumes found."

            }
                    
        }

        if ($List) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating List display"

            if ($Available) { 
                
                #Storage Volume Display List
                $a =    @{Expression={$_.name};Label="Name"}, `
                        @{Expression={$_.provisionType};Label="Provisioned Type"}, `
                        @{Expression={
                            if ($_.shareable) { "Shared"}
                            else              { "Private" }
                        };Label="Sharing"}, `
                        @{Expression={$_.raidLevel};Label="RAID"}, `
                        @{Expression={
                            $value = '{0:N2}' -f ($_.provisionedCapacity / 1GB)
                            $value + "GB"
                        };Label="Provisioned "}, `
                        @{Expression={"$($_.storagePoolName) ($($_.storageSystemName))"};Label="Storage Pool (System Name)"}

            }
            
            else {

                #Storage Volume Display List
                $a =    @{Expression={"$($_.name) [$($_.deviceVolumeName)]"};Label="Name [Device Name]"}, `
                        @{Expression={$_.provisionType};Label="Provisioned Type"}, `
                        @{Expression={
                        if ($_.shareable) { "Shared"}
                        else              { "Private" }
                        };Label="Sharing"}, `
                        @{Expression={$_.raidLevel};Label="RAID"}, `
                        @{Expression={
                            $value = '{0:N2}' -f ($_.allocatedCapacity / 1GB)
                            $value + "GB"
                        };Label="Allocated"}, `
                        @{Expression={
                            $value = '{0:N2}' -f ($_.provisionedCapacity / 1GB)
                            $value + "GB"
                        };Label="Provisioned "}, `
                        @{Expression={"$((send-hpovrequest $_.storagePoolUri).name) ($((send-hpovrequest $_.storageSystemUri).name))"};Label="Storage Pool (System)"}, `
                        @{Expression={
                            
                            #$childUri = $_.uri
                            $associationProfileToVol = (send-hpovrequest ($script:associationsUri + "?childUri=$($_.uri)&name=server_profiles_to_storage_volumes")).members
                            if ($associationProfileToVol) {
                                $profileNames = $associationProfileToVol | % { (Send-HPOVRequest $_.parentUri).name }
                                [Array]::Sort([array]$profileNames)
                                $profileNames
                            }

                            else { "No server profiles" }

                        };Label="Used By"},`
                        @{Expression={$_.status};Label="Status"}

            }

            $storageVolumes.members | sort-object 'name' | format-table $a -wrap -AutoSize

        }

        else {
        
            if ($storageVolumes.members.length -eq 1) { $storageVolumes.members[0] }
            else { $storageVolumes.members }
            
        }

        if ($Available) { write-host "Done. $($storageVolumes.count) attachable storage volume(s) found." }
        else { write-host "Done. $($storageVolumes.count) storage volume(s) found." }
    
    }

}

function New-HPOVStorageVolume {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdletBinding(DefaultParameterSetName = "default")]
    Param (

        [parameter (Mandatory = $true, HelpMessage = "Specify the name of the storage volume.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("name")]
        [string]$volumeName,

        [parameter(Mandatory = $false, ParameterSetName="default", Position = 1)]
        [string]$description = "",

        [parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName="default", Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Alias("pool","poolName")]
        [object]$StoragePool,

        [parameter(Mandatory = $false, ParameterSetName="default")]
        [string]$StorageSystem = "",

        [parameter(Mandatory = $true, ParameterSetName="template")]
        [ValidateNotNullOrEmpty()]
        [Alias('template','svt')]
        [object]$VolumeTemplate,

        [parameter(Mandatory = $true, ParameterSetName="default", Position = 3)]
        [parameter(Mandatory = $false, ParameterSetName="template", Position = 2)]
        [ValidateScript({$_ -ge 1})]
        [Alias("size")]
        [int64]$capacity,

        [parameter(Mandatory = $false, ParameterSetName="default", HelpMessage = "Create Thick provisioned volume.")]
        [switch]$full,

        [parameter(Mandatory = $false, ParameterSetName="default", HelpMessage = "Allow the volume to be shared between hosts (i.e. shared datastore).")]
        [parameter(Mandatory = $false, ParameterSetName="template", HelpMessage = "Allow the volume to be shared between hosts (i.e. shared datastore).")]
        [switch]$shared

    )

     Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageVolume' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $newVolume = [PSCustomObject]@{
            name        = $volumeName;
            description = $description;
            type        = "StorageVolume";
            templateUri = $null;
            provisioningParameters = @{
                storagePoolUri    = $null;
                requestedCapacity = $null;
                provisionType     = "Thin";
                shareable         = $false
            }

        }

        #Check to see if Storage Volume Template Global Setting is enabled
        $script:storageVolumeTemplateRequiredGlobalPolicy = (Send-HPOVRequest /rest/global-settings/StorageVolumeTemplateRequired).value

        if ($script:storageVolumeTemplateRequiredGlobalPolicy -ieq "True" -and -not $VolumeTemplate) { 
        
            $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException StorageVolumeTemplateRequired InvalidArgument 'New-HPOVStorageVolume' -Message "Storage Volumes cannot be created without providing a Storage Volume Template due to global policy setting.  Please provide a Storage Volume Template and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        
        }

        else {

            Switch ($PsCmdlet.ParameterSetName) {
                
                "default" {

                    switch ($StoragePool.Gettype().Name) {

                        "String" { 
                        
                            #parameter is correct URI
                            if ($StoragePool.StartsWith($script:storagePoolUri)){

                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StoragePool URI provided by caller."
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request." 
                                                       
                                $sp = Send-HPOVRequest $StoragePool
                            
                            }

                            #Parameter is incorrect URI value
                            elseif ($StoragePool.StartsWith("/rest")) {

                                #Invalid parameter value, generate terminating error.
                                $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException InvalidArgumentValue InvalidArgument 'New-HPOVStorageVolume' -Message "Invalid StoragePool parameter value: $($StoragePool | out-string). Please correct and try again." #-verbose
                                $PSCmdlet.ThrowTerminatingError($errorRecord)

                            }

                            #Parameter is Storage Pool name
                            else {
                                
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StoragePool Name provided by caller."
                                
                                #Get specific storage pool from provi
                                if ($StorageSystem) { 

                                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem name provided: $StorageSystem"
                                
                                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request."

                                    $sp = Get-HPOVStoragePool $StoragePool -storageSystem $StorageSystem 
                                    
                                }
                                else { $sp = Get-HPOVStoragePool $StoragePool }                              

                                if ($sp -and $sp.count -gt 1) {

                                    $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException MultipleStoragePoolsFound InvalidResult 'New-HPOVStorageVolume' -Message "Multiple StoragePool resources found with the name '$StoragePool'.  Please use the -StorageSystem parameter to specify the Storage System the Storage Pool is to be used, or use Get-HPOVStoragePool to provide the specific Storage Pool resource." #-verbose
                                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                                }

                            }

                        }

                        "PSCustomObject" { 
                        
                            #Validate the object
                            if ($StoragePool.category -eq 'storage-pools') { $sp = $StoragePool }
                            else {

                                $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException InvalidStoragePoolCategory InvalidArgument 'New-HPOVStorageVolume' -Message "Invalid StoragePool parameter value.  Expected Resource Category 'storage-pools', recieved '$($VolumeTemplate.category)'." #-verbose
                                $PSCmdlet.ThrowTerminatingError($errorRecord)

                            }                        
                        
                        }

                    }

                    #Amend the request body
                    $newVolume.provisioningParameters.storagePoolUri = $sp.uri
                    $newVolume.provisioningParameters.requestedCapacity = $capacity * 1GB

                    #Check for the presence of the $full and $shared parameters and set values if so
                    if($full.isPresent){$newVolume.provisioningParameters.provisionType = "Full"}
                    if($shared.isPresent){$newVolume.provisioningParameters.shareable = $true}

                }
                "template" {

                    switch ($VolumeTemplate.gettype().name) {

                        "String" {
                            
                            if ($VolumeTemplate.StartsWith($script:storageVolumeTemplateUri)){
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] VolumeTemplate URI provided by caller."
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request."                        
                                $svt = Send-HPOVRequest $VolumeTemplate
                            
                            }

                            elseif ($VolumeTemplate.StartsWith("/rest")) {

                                #Invalid parameter value, generate terminating error.
                                $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException InvalidArgumentValue InvalidArgument 'New-HPOVStorageVolume' -Message "Invalid VolumeTemplate parameter value: $($VolumeTemplate | out-string)" #-verbose
                                $PSCmdlet.ThrowTerminatingError($errorRecord)

                            }

                            else {
                                
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] VolumeTemplate Name provided by caller."
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request."
                                #Get the storage volume template resource.  Terminating error will throw from the Get-* if no resource is found.
                                $svt = Get-HPOVStorageVolumeTemplate -templateName $VolumeTemplate
                            }

                        }

                        "PSCustomObject" {

                            #Validate the object
                            if ($volumeTemplate.category -eq 'storage-volume-templates') { $svt = $VolumeTemplate }
                            else {

                                $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException InvalidArgumentValue InvalidArgument 'New-HPOVStorageVolume' -Message "Invalid VolumeTemplate parameter value.  Expected Resource Category 'storage-volume-templates', recieved '$($VolumeTemplate.category)'." #-verbose
                                $PSCmdlet.ThrowTerminatingError($errorRecord)

                            }

                        }

                        default { }
                    }

                    #Amend the request body
                    $newVolume.templateUri = $svt.uri
                    $newVolume.provisioningParameters.storagePoolUri    = $null
                    $newVolume.provisioningParameters.requestedCapacity = $svt.provisioning.capacity
                    $newVolume.provisioningParameters.provisionType     = $null
                    $newVolume.provisioningParameters.shareable         = $svt.provisioning.shareable

                    #Check if capacity and shareable parameters were overridden in the request and update the object
                    if($capacity){
                        $newVolume.provisioningParameters.requestedCapacity = $capacity * 1GB
                    }

                    if($shared.isPresent -ne $svt.provisioning.shareable){
                        $newVolume.provisioningParameters.shareable = (!$svt.provisioning.shareable)
                    }

                }

            }

            #Send the request
            $resp = Send-HPOVRequest -method POST -body $newVolume -uri $script:storageVolumeUri
        }

    }

    end {

        if ($resp.errorCode) {

            $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException $resp.errorCode InvalidResult 'New-HPOVStorageVolume' -Message $resp.nestedErrors[0].details #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        else {

            Return $resp

        }

    }

}

function Add-HPOVStorageVolume {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdletBinding(DefaultParameterSetName = "default")]
    Param (

        [parameter(Mandatory = $true, ValueFromPipeline = $True, Position = 0, ParameterSetName="default")]
        [ValidateNotNullOrEmpty()]
        [object]$StorageSystem,

        [parameter (Mandatory = $true, HelpMessage = "Specify the name of the storage volume.", Position=1, ParameterSetName="default")]
        [ValidateNotNullOrEmpty()]
        [Alias("volid","id","wwn")]
        [ValidateScript({if ($_ -match $script:wwnAddressPattern) {$true} else { Throw "The input value '$_' does not match the required format of 'AA:BB:CC:DD:EE:AA:BB:CC'. Please correct and try again." }})]
        [string]$VolumeID,

        [parameter (Mandatory = $true, ParameterSetName="default", HelpMessage = "Specify the name of the storage volume.", Position=2)]
        [ValidateNotNullOrEmpty()]
        [Alias("name")]
        [string]$volumeName,

        [parameter(Mandatory = $false, ParameterSetName="default", Position = 3)]
        [string]$description = "",

        [parameter(Mandatory = $false, ParameterSetName="default", HelpMessage = "Allow the volume to be shared between hosts (i.e. shared datastore).")]
        [switch]$shared

    )

     Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVStorageVolume' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        #Create new addVolume object
        $addVolume = [PSCustomObject]@{
            type             = "AddStorageVolumeV2";
            name             = $volumeName;
            description      = $description;
            storageSystemUri = $null;
            wwn              = $VolumeID;
            provisioningParameters = @{
                shareable = $shared.IsPresent
            }

        }

        Switch ($StorageSystem.GetType().Name) {

            "String" {
                            
                if ($StorageSystem.StartsWith($script:storageSystemUri)){

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem URI provided by caller."
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request."                        
                    $ss = Send-HPOVRequest $StorageSystem

                }

                elseif ($StorageSystem.StartsWith("/rest")) {

                    #Invalid parameter value, generate terminating error.
                    $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException InvalidArgumentValue InvalidArgument 'New-HPOVStorageVolume' -Message "Invalid StorageSystem parameter value: $($StorageSystem | out-string)" #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }

                else {
                                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] StorageSystem Name provided by caller."
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request."

                    #Get the storage volume template resource.  Terminating error will throw from the Get-* if no resource is found.
                    $ss = Get-HPOVStorageSystem $StorageSystem
                }

            }

            "PSCustomObject" {

                #Validate the object
                if ($StorageSystem.category -eq 'storage-systems') { $ss = $StorageSystem }
                else {

                    $errorRecord = New-ErrorRecord HPOneView.StorageVolumeResourceException InvalidStorageSystemCategory InvalidArgument 'New-HPOVStorageVolume' -Message "Invalid StorageSystem parameter value.  Expected Resource Category 'storage-systems', recieved '$($VolumeTemplate.category)'." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }

            }

            default { }
        }

        $addVolume.storageSystemUri = $ss.uri

        #Send the request
        [Array]$resp += (Send-HPOVRequest -method POST -body $addVolume -uri $script:storageVolumeUri)
    }

    end {

        if ($resp.errorCode) {

            $errorRecord = New-ErrorRecord InvalidOperationException $resp.errorCode InvalidResult 'New-HPOVStorageVolume' -Message $resp.nestedErrors[0].details #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        else {

            Return $resp

        }

    }

}

function Remove-HPOVStorageVolume {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    #Need to have scope to be OneView or OneView+Storage System
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (

        [parameter (Mandatory = $true, ValueFromPipeline=$true, ParameterSetName="default", HelpMessage = "Specify the storage volume to remove.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        [object]$storageVolume=$null,

        [parameter(Mandatory = $false, HelpMessage = "Specify whether to delete the export reference or export and provisioning volume.")]
        [switch]$exportOnly

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        $taskResults = @()

    }

    Process {
    
        foreach ($volume in $storageVolume) {

            $volumeNameOrUri = $null;
            $volumeDisplayName = $null;

            #Resource passed is a URI
            if (($volume -is [String]) -and ($volume.startsWith($script:storageVolumeUri))) 
            {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received URI: $($volume)"
                $volumeNameOrUri = $volume
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Volume Name"
                $volumeDisplayName = (Send-HPOVRequest $volume).name
            }

            #Resource passed is the Name
            elseif (($volume -is [string]) -and (!$volume.startsWith($script:storageVolumeUri))) 
            {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received Network Name $($volume)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Network"

                #NEED TO VALIDATE
                $storageVolume = Get-HPOVStorageVolume $volume
                if ($storageVolume.count -gt 1 ) 
                { 

                    $errorRecord = New-ErrorRecord InvalidOperationException VolumeNameNotUnique InvalidResult 'Remove-HPOVStorageVolume' -Message "Storage Volume Name '$($volume)' is not unique." #-verbose
                    $PSCmdlet.WriteError($errorRecord)
                    
                }

                else 
                {
                    $volumeNameOrUri = $storageVolume.uri
                    $volumeDisplayName = $storageVolume.name
                }

            }

            #Volume resource passed is the object
            elseif ($volume -is [PSCustomObject] -and ($volume.category -ieq 'storage-volumes')) 
            {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())]"
                $volumeNameOrUri = $storageVolume.uri;
                $volumeDisplayName = $storageVolume.name;
            }
            else 
            {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidVolumeParameter InvalidResult 'Remove-HPOVStorageVolume' -Message "Storage Volume parameter '$($volume)' is invalid." #-verbose
                $PSCmdlet.WriteError($errorRecord)

            }

            if (!$volumeNameOrUri) 
            {
                
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidVolumeParameter InvalidResult 'Remove-HPOVStorageVolume' -Message "Storage Volume parameter '$($volume)' is invalid." #-verbose
                $PSCmdlet.WriteError($errorRecord)

            }
            
            #Prompt for confirmation if user is going to remove both the export and volume
            if (-not ($exportOnly.IsPresent) -and $pscmdlet.ShouldProcess($volumeDisplayName,'Remove storage volume from appliance?')) 
            {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Removing volume and export."
                
                #Handle additional header required for this delete operation
                $results = Send-HPOVRequest $volumeNameOrUri DELETE
            }
            
            #No prompt necessary, as volume export is being removed, not the volume.
            elseif ([bool]$exportOnly) 
            {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] removing export only"
                
                #Handle additional header required for this delete operation
                $results = Send-HPOVRequest $volumeNameOrUri DELETE -addHeader @{exportOnly = [bool]$exportOnly}
            }
            else 
            {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User cancelled volume remove request or passed -WhatIf."
            
            }

            $taskResults += $results
        }

    }



    end {

        $taskResults

    }

}

function Get-HPOVSanManager {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (

        [parameter(Position = 0, Mandatory = $false, HelpMessage = "Enter the SAN Manager Hostname or IP Address.")]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string]$SanManager = $Null,

        [parameter(Mandatory = $false, HelpMessage = "Display output in Table List format.")]
        [switch]$List

    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVSanManager" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process {

        #Send Request
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of SAN Managers"
        $sanManagers = (Send-HPOVRequest $script:fcSanManagersUri).members

        if (! $sanManagers) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No SAN Managers found."
                    
        }

        #Filter results for specific SAN Manager
        if ($SanManager) { 
        
            $sanManagers = $sanManagers | where { $_.name -eq $SanManager } 

            #Generate Terminating Error if resource not found
            if (! $sanManagers) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requested Managed SAN '$($SanManager)' not found."
                    
                $errorRecord = New-ErrorRecord InvalidOperationException SanManagerResourceNotFound ObjectNotFound 'Get-HPOVSanManager' -Message "Request SAN Manager '$($SanManager)' not found.  Please check the name and try again." #-verbose
                    
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

        }

    }

    end {

        if ($List) {

            $a = @{Expression={$_.name};Label="Name"}, `
                 @{Expression={$_.providerDisplayName};Label="SAN Manager Type"}, `
                 @{Expression={$_.deviceManagerVersion};Label="Version"}, `
                 @{Expression={$_.state};Label="State"}, `
                 @{Expression={ 
                    
                     $managedSans = @()
                     $resp = Send-HPOVRequest $_.managedSansUri
                     if ($resp.count -gt 0) { 
                         foreach ($member in $resp.members) { $managedSans += $member.name }
                         [array]::sort($managedSans)
                         $managedSans
                     }
                
                     else { "None" }
                    
                 };Label="Managed SANs"}, `
                 @{Expression={ 
                    
                     $unimportedSans = @()
                     $resp = Send-HPOVRequest $_.unimportedSansUri
                     if ($resp.count -gt 0) { 
                         foreach ($member in $resp.members) { $unimportedSans += $member.name }
                         [array]::sort($unimportedSans)
                         $unimportedSans
                     }
                
                     else { "None" }
                    
                 };Label="Unimported SANs"}
                    
            $sanManagers | Sort-Object name | format-table $a -autosize

        }

        else { return $sanManagers }

    }

}

function Add-HPOVSanManager {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true, HelpMessage = "Specify the SAN Manager Type.  Accepted values are: BNA.", position=0)]
        [ValidateSet("BNA","Brocade Network Advisor")]
        [string]$Type,

        [parameter(Mandatory = $true, HelpMessage = "Enter the SAN Manager Hostname or IP Address.", position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname="",

        [parameter(Mandatory = $false, HelpMessage = "Enter the SAN Manager TCP Port.", position=2)]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,65535)]
        [int]$Port=5989,
         
        [parameter(Mandatory = $true, HelpMessage = "Enter the administrative user name (i.e. Administrator).", position=3)]
        [ValidateNotNullOrEmpty()]
        [string]$Username="",

        [parameter(Mandatory = $true, HelpMessage = "Enter the administrative account password (i.e. password).", position=4)]
        [ValidateNotNullOrEmpty()]
        [string]$Password="",

	    [parameter(Mandatory = $false)]
	    [switch]$UseSsl
    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Add-HPOVSanManager' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process {

        #Get SAN Manager URI
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting available SAN Managers"
        
        $fcSanManagerDeviceManagers = Send-HPOVRequest $script:fcSanManagerProvidersUri

        if ($Type -eq "BNA") { $Type = "Brocade Network Advisor" }

        write-verbose "[NEADDW-HPOVSANMANAGER] SAN Manager Type requested: $($Type)"

        $fcSanManagerDeviceManagerUri = ($fcSanManagerDeviceManagers.members | Where { $_.displayName -eq $Type }).deviceManagersUri

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SAN Manager URI: $($fcSanManagerDeviceManagerUri)"
        

        $newSanManager = @{"connectionInfo" = @(
                            @{name="Host";Value=$Hostname},
                            @{name="Port";Value=$Port},
                            @{name="Username";Value=$Username},
                            @{name="Password";Value=$Password},
                            @{name="UseSsl";Value=[bool]$UseSsl})}

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New SAN Manager Request: $($newSanManager | out-string)"

        $resp = Send-HPOVRequest $fcSanManagerDeviceManagerUri POST $newSanManager

        if (($resp.type -eq "TaskResourceV2") -and ($resp.Uri)) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received aync task, calling Wait-HPOVTaskComplete"
            Wait-HPOVTaskComplete $request
        }
        elseif ( [int]$resp.statusCode -eq 409) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received HTTP 409, 'ResourceExists'.  Generating terminating error."
            $errorRecord = New-ErrorRecord InvalidOperationException SanManagerAlreadyExists ResourceExists 'Add-HPOVSanManager' -Message "The SAN Manager $($Hostname) already exists." #-verbose
            $PsCmdlet.ThrowTerminatingError($errorRecord)
        }

        else { 

            $errorRecord = New-ErrorRecord InvalidOperationException $resp.errorCode InvalidOperation 'Add-HPOVSanManager' -Message ($resp.message  + " " + $resp.recommendedAction) #-verbose
            $PsCmdlet.ThrowTerminatingError($errorRecord)        
            #Write-Error "Something happened: $($request | out-string)" -ErrorAction Stop }

        }

    }

}

function Set-HPOVSanManager {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true,
        HelpMessage = "Specify the SAN Manager Name.")]
        [ValidateNotNullOrEmpty()]
        [string]$Name="",

        [parameter(Mandatory = $false,
        HelpMessage = "Specify the new Hostname or IP Address of the SAN Manager.")]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname="",

        [parameter(Mandatory = $false,
        HelpMessage = "Specify the new TCP Port number of the SAN Manager.")]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,65535)]
        [Int]$Port=0,
                 
        [parameter(Mandatory = $false,
        HelpMessage = "Enter the administrative user name (i.e. 3paradm).")]
        [ValidateNotNullOrEmpty()]
        [string]$Username="",

        [parameter(Mandatory = $false,
        HelpMessage = "Enter the administrative account password (i.e. 3pardata).")]
        [ValidateNotNullOrEmpty()]
        [string]$Password=""

    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError $script:HPOneViewAppliance -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process {

        #Generate Terminating Error if resource no parameters were provided.
        if (! $Hostname -and ! $Username -and ! $Password -and ! $Port) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! No parameter values were provided.  At least one optional parameter (Hostname, Port, Username or Password) must be provided."
                    
            $errorRecord = New-ErrorRecord ArgumentNullException ParametersNotSpecified InvalidArgument 'Set-HPOVSanManager' -Message "No parameter values were provided.  At least one optional parameter (Hostname, Port, Username or Password) must be provided." #-verbose
                    
            #Generate Terminating Error
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #Get SAN Manager URI
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting available SAN Managers"
        $resp = (Send-HPOVRequest $script:fcSanManagersUri).members | where { $_.name -eq $Name }
        $Manager = [pscustomobject]@{connectionInfo = @(); eTag = $resp.eTag}

        #Generate Terminating Error if resource not found
        if (! $resp) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! Request SAN Manager '$($SanManager)' not found."
                    
            $errorRecord = New-ErrorRecord InvalidOperationException SanManagerResourceNotFound ObjectNotFound 'Set-HPOVSanManager' -Message "Request SAN Manager '$($Name)' not found.  Please check the name and try again." #-verbose
                    
            #Generate Terminating Error
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if ($Hostname) { $Manager.connectionInfo += [pscustomobject]@{name = "Host"; value = $Hostname} }
        if ($Port)     { $Manager.connectionInfo += [pscustomobject]@{name = "Port"; value = $Port} }
        if ($Username) { $Manager.connectionInfo += [pscustomobject]@{name = "Username"; value = $Username } }
        if ($Password) { $Manager.connectionInfo += [pscustomobject]@{name = "Password"; value = $Password } }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updated SAN Manager: $($Manager | out-string)"

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"

        $resp = Send-HPOVRequest $resp.uri PUT $Manager

        return $resp

    }

}

function Update-HPOVSanManager {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (

        [parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Enter the Managed SAN Name.")]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [Object]$SANManager = $Null

    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Update-HPOVSanManager" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
        
        #Validate SAN Manager Name Object Type
        if ($SANManager -is [String] -and (! $SANManager.StartsWith($script:fcSanManagersUri))) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SANManager name passed:  $($SANManager)"
            $SANManager = Get-HPOVSanManager -Name $SANManager            
        
        }

        elseif ($SANManager -is [String] -and $SANManager.StartsWith($script:fcSanManagersUri)) {
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LogicalInterconnect URI passed:  $($SANManager)"
            $SANManager = Send-HPOVRequest $SANManager

        }


        elseif ($SANManager -is [String]) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] invalid SANManager passed:  $($SANManager)"
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Update-SANManager' -Message "The 'SANManager' parameter value '$($SANManager)' is invalid.  Please check the parameter value and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        
        }

        else {

            if ($PSBoundParameters.ContainsKey("SANManager")) {
            
    	        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SANManager parameter data type: $($SANManager.gettype() | out-string)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($SANManager.count)' SANManagers."

            }

            else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SANManager parameter passed via pipeline?" }
        
        }

        $resp = @()

    }

    process {

        $request = [PsCustomObject]@{refreshState = "RefreshPending"}

        foreach ($manager in $SANManager) {

            if ($manager.isInternal) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($manager.name)' SAN Manager is internal.  Skipping." }

            else {
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($manager.name)'."

                $resp += Send-HPOVRequest $manager.uri PUT $request

            }
      
        }

    }

    end {

        Return $resp

    }

}

function Remove-HPOVSanManager {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (

        [parameter(Mandatory = $true,ValueFromPipeline=$true, HelpMessage = "Enter the SAN Manager Name, or provide SAN Manager Resource.")]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [System.Object]$SanManager = $Null

    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError $script:HPOneViewAppliance -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }


    process {

        if (($SanManager -is [Hashtable] -or $SanManager -is [PsCustomObject] -or $SanManager -is [Array]) -and $SanManager.category -eq "fc-device-managers") { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SanManager Parameter is '$($SanManager.Gettype().Fullname)' type."
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SanManager contains $($SanManager.Count) items."
        
            foreach ($manager in $SanManager) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($manager.Name)'"
        
                #Check to make sure the request SAN Manager is not an Internal Type, especially the Local Direct Attach Manager
                if ($manager.isInternal) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! Internal SAN Manager was requested to be processed.  Generating non-terminating error."
                    
                    $errorRecord = New-ErrorRecord InvalidOperationException CannotDeleteInternalResource InvalidOperation 'Remove-HPOVSanManager' -Message "Unable to remove an internal SAN Manager resource.  '$($manager.name)' SAN Manager was requested to be removed." #-verbose
                    
                    #Generate Non-Terminating Error
                    $PSCmdlet.WriteError($errorRecord)
                }

                else {

                    if ($pscmdlet.ShouldProcess($manager.Name,"Remove SAN Manager from appliance?")){
                        if ([bool]$force) { Remove-HPOVResource -nameOrUri $manager.uri -force }
                        else { Remove-HPOVResource -nameOrUri $manager } 
                        #Remove-HPOVResource -nameOrUri $enclosureNameOrUri -force $force
                    }

                }

            }
        
        }

        #Expecting a URI to resource
        elseif ($SanManager -is [String] -and $SanManager.startswith("/rest/fc-sans/device-managers/") ){

            #Check to see if the resource exists
            $Manager = Send-HPOVRequest $SanManager
        
            if ($Manager -and $Manager.category -eq "fc-device-managers") {

                if ($pscmdlet.ShouldProcess($Manager.Name,"Remove SAN Manager from appliance?")){    
                    if ([bool]$force) { Remove-HPOVResource -nameOrUri $manager.uri -force }
                    else { Remove-HPOVResource -nameOrUri $manager } 
                    #Remove-HPOVResource -nameOrUri $Manager.uri
                }
                  
            }

            #Generate Terminating Error
            else {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! URI is not a valid SAN Manager.  Expected resource Category: 'fc-device-managers'.  Received resource Category: '$($Manager.category)'"
                    
                $errorRecord = New-ErrorRecord InvalidOperationException WrongCategoryType InvalidResult 'Remove-HPOVSanManager' -Message "URI is not a valid SAN Manager.  Expected resource Category: 'fc-device-managers'.  Received resource Category: '$($Manager.category)'" #-verbose
                    
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

        }

        #Expecting Resource Name
        elseif ($SanManager -is [String] ){
        
            #"?filter=name='$TaskName'"

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to look for '$($SanManager)'."
            $Manager = (Send-HPOVRequest $script:fcSanManagersUri).members | where { $_.name -eq $sanManager }

            #Generate Terminating Error if resource not found
            if (! $Manager) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! Request SAN Manager '$($SanManager)' not found."
                    
                $errorRecord = New-ErrorRecord InvalidOperationException SanManagerResourceNotFound ObjectNotFound 'Remove-HPOVSanManager' -Message "Request SAN Manager '$($SanManager)' not found.  Please check the name and try again." #-verbose
                    
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            else {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found '$($SanManager)' SAN Manager."

                if ($pscmdlet.ShouldProcess($Manager.Name,"Remove SAN Manager from appliance?")){
                    if ([bool]$force) { Remove-HPOVResource -nameOrUri $manager.uri -force }
                    else { Remove-HPOVResource -nameOrUri $manager.uri }  
                    #Remove-HPOVResource -nameOrUri $Manager.uri
                
                }

            }
        
        }

        #Unrecognized SanManager value
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! SanManager value is not recognized."
                    
            $errorRecord = New-ErrorRecord InvalidOperationException CannotDeleteInternalResource InvalidOperation 'Remove-HPOVSanManager' -Message "Unable to remove an internal SAN Manager resource.  '$($manager.name)' SAN Manager was requested to be removed." #-verbose
                    
            #Generate Non-Terminating Error
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

}

function Get-HPOVManagedSan {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (

        [parameter(Mandatory = $false, HelpMessage = "Enter the Managed SAN Name.")]
        [ValidateNotNullOrEmpty()]
        [Alias('Fabric')]
        [string]$Name="",

        [parameter(Mandatory = $false, HelpMessage = "Display output in Table List format.")]
        [switch]$List

    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVManagedSan' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of Managed SANs"
        $managedSans = (Send-HPOVRequest $script:fcManagedSansUri).members

        if ($Name) { 
        
            $managedSans = $managedSans | where { $_.name -eq $Name } 
        
            #Generate Terminating Error if resource not found
            if (! $managedSans) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! Requested Managed SAN '$($ManagedSan)' not found."
                    
                $errorRecord = New-ErrorRecord InvalidOperationException ManagedSanResourceNotFound ObjectNotFound 'Get-HPOVManagedSan' -Message "Request Managed SAN '$($Name)' not found.  Please check the name and try again." #-verbose
                    
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }
            
        }

        else {

            #Generate Terminating Error if resource not found
            if (! $managedSans) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Managed SANs found."
                    
                #$errorRecord = New-ErrorRecord InvalidOperationException ManagedSanResourceNotFound ObjectNotFound 'Get-HPOVManagedSan' -Message "No Managed SANs found.  Run Add-HPOVSanManager to add Managed SAN resources." #-verbose
                    
                #Generate Terminating Error
                #$PSCmdlet.ThrowTerminatingError($errorRecord)

            }

        }

        if ($List) {

            $managedSansCol = @()

            foreach ($san in $managedSans) {

                $tempSanCol = [pscustomobject]@{name = $san.name; 
                                state = $san.state; 
                                status = $san.status;
                                network = (Send-HPOVRequest ($san.publicAttributes | where { $_.name -eq "NetworkUri" }).value).name;
                                zoned = $san.zoningState; 
                                automatezoning = ($san.publicAttributes | where { $_.name -eq "AutomateZoning" }).value }

                $managedSansCol += $tempSanCol
            }

            $a = @{Expression={$_.name};Label="Name"}, `
                 @{Expression={$_.state};Label="State"}, `
                 @{Expression={$_.status};Label="Status"}, `
                 @{Expression={
                 
                     if (!$_.network) { "None" }

                     else { $_.network }

                 };Label="Network"}, `
                 @{Expression={

                     switch ($_.zoned) {
                     
                        "Open" { "Open Zones" }
                        "Unknown" { "Unknown" }
                        "Zoned" { "Zoned" }
                        default { "No" }
                    }
                    
                 };Label="Zoned"}, `
                 @{Expression={ $_.automatezoning };Label="Automated Zoning"}
                    
            $managedSansCol | Sort-Object name | format-table $a -autosize

        }

        else { return $managedSans }
    
    }

}

function Set-HPOVManagedSan {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
    Param (

        [parameter(Mandatory = $true, HelpMessage = "Enter the Managed SAN Name.",ValueFromPipeline=$true,ParameterSetName = "Enable",position=0)]
        [parameter(Mandatory = $true, HelpMessage = "Enter the Managed SAN Name.",ValueFromPipeline=$true,ParameterSetName = "Disable",position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Fabric','Name')]
        [object]$ManagedSan = $Null,

        [parameter(Mandatory = $true, HelpMessage = "Enable Automated Zoning for the specified Managed SAN.",ParameterSetName = "Enable")]
        [Alias('ZoningEnable','Enable')]
        [switch]$EnableAutomatedZoning,

        [parameter(Mandatory = $true, HelpMessage = "Disable Automated Zoning for the specified Managed SAN.",ParameterSetName = "Disable")]
        [Alias('ZoningDisable','Disable')]
        [switch]$DisableAutomatedZoning

    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Set-HPOVManagedSan' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    process {

        $updateManagedSan = [pscustomobject]@{ publicAttributes = @(); eTag = $Null }

        #Check to see if the input is Hashtable/PSCustomObject
        if (($ManagedSan -is [PsCustomObject] -and $ManagedSan.category -eq "fc-sans") -or ($ManagedSan -is [Array])) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ManagedSan Parameter is '$($ManagedSan.Gettype().Fullname)' type."
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ManagedSan contains $($ManagedSan.Count) items."

            foreach ($san in $ManagedSan) {

                if (! $san.isInternal) {
                    $updateManagedSan = $san
                    $updatedPublicAttributesManagedSan = @()
                    $i = 0
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($san.Name)'"
                    foreach ($entry in $ManagedSan.publicAttributes) {
                        
                        if ($entry.name -ne "AutomateZoning") { $updatedPublicAttributesManagedSan += $entry.publicAttributes[$i] }

                        $i++
                    }
                    
                    $updateManagedSan = [pscustomobject]@{ publicAttributes = $updatedPublicAttributesManagedSan; eTag = $san.eTag; valueType = "Boolean"; valueFormat = "None" }
                    
                    if ([bool]$EnableAutomatedZoning ) { $updateManagedSan.publicAttributes += @([pscustomobject]@{name = 'AutomateZoning'; value = [bool]$EnableAutomatedZoning; valueType = "Boolean"; valueFormat = "None"}) }
                    elseif ([bool]$DisableAutomatedZoning ) { $updateManagedSan.publicAttributes += @([pscustomobject]@{name = 'AutomateZoning'; value = [bool]$DisbleAutomatedZoning; valueType = "Boolean"; valueFormat = "None"}) }

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to appliance"
                    $resp += Send-HPOVRequest -uri $san.uri -method PUT -body $updateManagedSan
                }

                else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($san.name)' Internal SAN Manager resource provided. SKipping." }

            }

        }

        #Check to see if the input is type String and is URI
        elseif ($ManagedSan -is [String] -and $ManagedSan.startswith('/rest')) {
        
            $managedSan = Send-HPOVRequest $ManagedSan

            #Generate Terminating Error if resource not found
            if (! $managedSans) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! Requested Managed SAN '$($ManagedSan)' not found."
                    
                $errorRecord = New-ErrorRecord InvalidOperationException SanManagerResourceNotFound ObjectNotFound 'Set-HPOVManagedSan' -Message "Request SAN Manager '$($Name)' not found.  Please check the name and try again." #-verbose
                    
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            else {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found and processing '$($managedSan.Name)'"

                $updateManagedSan = $managedSan
                $updatedPublicAttributesManagedSan = @()
                $i = 0
                
                foreach ($entry in $ManagedSan.publicAttributes) {
                    
                    if ($entry.name -ne "AutomateZoning") { $updatedPublicAttributesManagedSan += $entry.publicAttributes[$i] }

                    $i++
                }
                
                $updateManagedSan = [pscustomobject]@{ publicAttributes = $updatedPublicAttributesManagedSan; eTag = $managedSan.eTag; valueType = "Boolean"; valueFormat = "None" }
                
                if ([bool]$EnableAutomatedZoning ) { $updateManagedSan.publicAttributes += @([pscustomobject]@{name = 'AutomateZoning'; value = [bool]$EnableAutomatedZoning; valueType = "Boolean"; valueFormat = "None"}) }
                elseif ([bool]$DisableAutomatedZoning ) { $updateManagedSan.publicAttributes += @([pscustomobject]@{name = 'AutomateZoning'; value = [bool]$DisbleAutomatedZoning; valueType = "Boolean"; valueFormat = "None"}) }
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to appliance"
                $resp = Send-HPOVRequest -uri $san.uri -method PUT -body $updateManagedSan

            }
        
        }

        #Check to see if the input is type String as it should be the Name of the Managed SAN
        elseif ($ManagedSan -is [String]) {
            $managedSan = (Send-HPOVRequest $script:fcManagedSansUri).members | where { $_.name -eq $ManagedSan }

            #Generate Terminating Error if resource not found
            if (! $managedSans) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Woops! Requested Managed SAN '$($ManagedSan)' not found."
                    
                $errorRecord = New-ErrorRecord InvalidOperationException SanManagerResourceNotFound ObjectNotFound 'Set-HPOVManagedSan' -Message "Request SAN Manager '$($Name)' not found.  Please check the name and try again." #-verbose
                    
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            else {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found and processing '$($managedSan.Name)'"

                $updateManagedSan = $managedSan
                $updatedPublicAttributesManagedSan = @()
                $i = 0
                
                foreach ($entry in $ManagedSan.publicAttributes) {
                    
                    if ($entry.name -ne "AutomateZoning") { $updatedPublicAttributesManagedSan += $entry.publicAttributes[$i] }

                    $i++
                }
                
                $updateManagedSan = [pscustomobject]@{ publicAttributes = $updatedPublicAttributesManagedSan; eTag = $managedSan.eTag; valueType = "Boolean"; valueFormat = "None" }
                
                if ([bool]$EnableAutomatedZoning ) { $updateManagedSan.publicAttributes += @([pscustomobject]@{name = 'AutomateZoning'; value = [bool]$EnableAutomatedZoning; valueType = "Boolean"; valueFormat = "None"}) }
                elseif ([bool]$DisableAutomatedZoning ) { $updateManagedSan.publicAttributes += @([pscustomobject]@{name = 'AutomateZoning'; value = [bool]$DisbleAutomatedZoning; valueType = "Boolean"; valueFormat = "None"}) }
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to appliance"
                $resp = Send-HPOVRequest -uri $san.uri -method PUT -body $updateManagedSan

            }
        }

    }

    end {
        
        Return $resp

    }


}

#######################################################
# Unmanaged Devices: 
#

function Get-HPOVUnmanagedDevice {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = 'Default')]

    Param (

        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Default', HelpMessage = "Enter the name of the unmanaged device.")]
        [String]$Name,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Alias('report')]
        [Switch]$List
    )

    Begin {
    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        #verify-auth "Get-HPOVUnmanagedDevice"
            
    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"

        $collection = Send-HPOVRequest $script:unmanagedDevicesUri

        if ($collection.count -eq 0) {  Write-Warning "No unmanaged devices found." }

        else {

            #Look for the specified name
            If ($name) { $unmanagedDevices = $collection.members | where ( $_.name -eq $name) 
            
                #If not found, throw error
                if (!$unmanagedDevices) { 
                
                    Write-Error "" -Category ObjectNotFound -CategoryTargetName "Get-HPOVUnmanagedDevice" -CategoryReason "$($name) Object Not Found"
                    Break
                }

            }

            else { $unmanagedDevices = $collection.members }

            if ($List) {

                    $a = @{Expression={$_.name};Label="Name"}, `
                         @{Expression={$_.model};Label="Device Model"}, `
                         @{Expression={"$($_.height)U"};Label="Rack Units"}, `
                         @{Expression={"$($_.maxPwrConsumed)W"};Label="Max Power"}
                    
                    $unmanagedDevices | format-table $a -autosize
            }

            else { return $unmanagedDevices }

        }


    }

}

function New-HPOVUnmanagedDevice {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = 'Default')]

    Param (

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', HelpMessage = "Enter the name of the unmanaged device.")]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'Default', HelpMessage = "Provide a device model description (e.g. HPN 5900CP).")]
        [ValidateNotNullOrEmpty()]
        [string]$model,

        [Parameter(Mandatory = $true, Position = 2, ParameterSetName = 'Default', HelpMessage = "Enter the Rack Unit height (e.g. 1).")]
        [ValidateNotNullOrEmpty()]
        [int]$height,

        [Parameter(Mandatory = $true, Position = 3, ParameterSetName = 'Default', HelpMessage = "Enter the max power consumption in WATTS (e.g. 300).")]
        [ValidateNotNullOrEmpty()]
        [int]$maxPower
    )

    Begin {
    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        #verify-auth "New-HPOVUnmanagedDevice"
            
    }

    Process {
        
        $newDevice = [pscustomobject]@{ name = $Name; model = $model; height = $height; maxPwrConsumed = $maxPower }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New Unmanaged Device:  $($newDevice)"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"

        $resp = Send-HPOVRequest $script:unmanagedDevicesUri POST $newDevice

        return $resp

    }

}

#######################################################
# Power Delivery Devices
#

function Get-HPOVPowerDevice {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding()]
	Param (
		[parameter(Mandatory = $false, Position = 0)]
		[string]$name = $null
	)

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError $($MyInvocation.InvocationName.ToString().ToUpper()) -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bound PS Parameters: $($PSBoundParameters | out-string)"
        
        $ipdus = Send-HPOVRequest $powerDevicesUri #($powerDevicesUri + "?filter=`"name matches '$name'`"" -replace ("[*]","%25"))
        #Set-DefaultDisplay $ipdus.members -defProps 'name', 'serialNumber', 'model', 'deviceType', 'uri'

        $ipdus.members | % { $_.psobject.typenames.Insert(0,”HPOneView.PowerDeliveryDevice") }

        if ($name) { $resource = $ipdus.members | Where-Object {$_.name -eq $name} }
        else { $resource = $ipdus.members }

    }

    End {

        if (-not ($resource) -and $name) {

            $errorRecord = New-ErrorRecord HPOneView.PowerDeliveryDeviceException ResourceNotFound ObjectNotFound "Name" -Message "The specific '$name' iPDU was not found." #-verbose
            $pscmdlet.WriteError($errorRecord)

        }

        $resource
        
        if ($resource -is [PSCustomObject]) { write-host "Done. 1 Power Delivery Device(s) found." }
        else { write-host "Done. $($resource.count) Power Delivery Device(s) found." }

    }

}

function Add-HPOVPowerDevice {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(SupportsShouldProcess = $true,ConfirmImpact = "High")]
    Param (
        [parameter(Mandatory = $true, HelpMessage = "Enter the host name (FQDN) or IP of the iPDU's management processor.", Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$hostname,
         
        [parameter(Mandatory = $true, HelpMessage = "Enter the iPDU administrative user name.", Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$username = "",

        [parameter(Mandatory = $true, HelpMessage = "Enter the iPDU administrative account password.", Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$password = "",

	    [parameter(Mandatory = $false)]
	    [switch]$force
    )

    Begin {
       
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bound PS Parameters: $($PSBoundParameters | out-string)"

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Add-HPOVPowerDevice" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $import = @{
            hostname = $hostname;
            username = $username;
            password = $password;
            force    = $false
        }

        write-verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Sending request to add iPDU."

        $resp = Send-HPOVRequest $script:powerDevicesDiscoveryUri POST $import

        #Wait for task to get into Starting stage
        $resp = Wait-HPOVTaskStart $resp
            
        write-verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - task response: $($resp | out-string)"

        #Check to see if the task errored, which should be in the Task Validation stage
        if ($resp.taskState -ne "Running" -and $resp.taskState -eq "Error" -and $resp.stateReason -eq "ValidationError") {

            write-verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Task error found $($resp.taskState) $($resp.stateReason) "

            if ($resp.taskerrors | Where-Object { $_.errorCode -eq "PDD_IPDU_TRAPRECEIVERACCOUNT_TAKEN" }) {
                        
                $errorMessage = $resp.taskerrors | Where-Object { $_.errorCode -eq "PDD_IPDU_TRAPRECEIVERACCOUNT_TAKEN" }

                $externalManagerIP = $errorMessage.data.mgmtSystemIP
                $externalManagerFQDN = [System.Net.DNS]::GetHostByAddress($externalManagerIP)

                write-verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - Found iPDU '$hostname' is already being managed by $externalManagerIP."
                write-verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - $externalManagerIP resolves to $($externalManagerFQDN | out-string)"
                write-warning "iPDU '$hostname' is already claimed by another management system $externalManagerIP ($($externalManagerFQDN.HostName))."

                if ($force -and $pscmdlet.ShouldProcess($hostname,"iPDU is already claimed by another management system $externalManagerIP ($($externalManagerFQDN.HostName)). Force add?")) {
		        	        
                    write-verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - iPDU is being claimed due to user chosing YES to force add."
                    $import.force = $true
                    $resp = Send-HPOVRequest $script:powerDevicesDiscoveryUri POST $import

		        }

                elseif ($pscmdlet.ShouldProcess($hostname,"iPDU is already claimed by another management system $externalManagerIP ($($externalManagerFQDN.HostName)). Force add?")) {
		        	        
                    write-verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] - iPDU is being claimed due to user chosing YES to force add."
                    $import.force = $true
                    $resp = Send-HPOVRequest $script:powerDevicesDiscoveryUri POST $import

		        }
		        else {

                    if ($PSBoundParameters['whatif'].ispresent) { 
                            
                        write-warning "-WhatIf was passed, would have force added '$hostname' iPDU to appliance."
                        $resp = $null
                            
                    }
                    else {

		        	    #If here, user chose "No", end processing
		        	    write-warning "Not importing iPDU, $hostname."
                        $resp = $Null

                    }

		        }

            }
            else {

                $errorMessage = $resp.taskerrors

                if ($errorMessage -is [Array]) { 
                        
                    #Loop to find a Message value that is not blank.
                    $displayMessage = $errorMessage | ? { $_.message }

                    $errorRecord = New-ErrorRecord InvalidOperationException $displayMessage.errorCode InvalidResult 'New-HPOVEnclosure' -Message $displayMessage.message }
                        
                else { $errorRecord = New-ErrorRecord InvalidOperationException $errorMessage.errorCode InvalidResult 'New-HPOVEnclosure' -Message ($errorMessage.details + " " + $errorMessage.message) }

                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

        }
    
        return $resp
    
    }

}

function Remove-HPOVPowerDevice {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [parameter(Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "default",
            HelpMessage = "Enter the the power-device to be removed.")]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        [object]$powerDevice=$null,

	    [parameter(Mandatory = $false)]
	    [switch]$force
    )

    Begin {
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
 
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {
        foreach ($pd in $powerDevice) {
            $powerDeviceNameOrUri = $null;
            $powerDeviceDisplayName = $null;
            if ($pd -is [String]) {
                $powerDeviceNameOrUri = $pd
                $powerDeviceDisplayName = $pd
            }
            elseif ($pd -is [PSCustomObject] -and $pd.category -ieq 'power-devices') {
                $powerDeviceNameOrUri = $pd.uri;
                $powerDeviceDisplayName = $pd.name;
            }
            else {
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVPowerDevice' -Message "Invalid powerDevice parameter: $pd" #-verbose
                $pscmdlet.WriteError($errorRecord)
                #Write-Host "Invalid powerDevice parameter: " + $pd
                #return
            }

            if (!$powerDeviceNameOrUri) {
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVPowerDevice' -Message "Invalid powerDevice parameter: $pd" #-verbose
                $pscmdlet.WriteError($errorRecord)
                #Write-Host "Invalid powerDevice parameter: " + $pd
            }
            elseif ($pscmdlet.ShouldProcess($powerDeviceDisplayName,'Remove power device from appliance?')){
                if ([bool]$force) { Remove-HPOVResource -nameOrUri $powerDeviceNameOrUri -force }
                else { Remove-HPOVResource -nameOrUri $powerDeviceNameOrUri }
            }
        } 
    }
}

#######################################################
# Networking and Connections
#

function New-HPOVNetwork {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "Ethernet")]
    Param (
        [parameter(Mandatory = $true, parameterSetName="FC",Position=0)]
        [parameter(Mandatory = $true, parameterSetName="Ethernet",Position=0)]
        [parameter(Mandatory = $true, parameterSetName="VLANIDRange",Position=0)]
        [string]$Name, 

        [parameter(Mandatory = $true, parameterSetName="FC",Position=1)]
        [parameter(Mandatory = $false, parameterSetName="Ethernet")]
        [parameter(Mandatory = $false, parameterSetName="VLANIDRange")]
        [ValidateSet("Ethernet", "FC", "FibreChannel", "Fibre Channel")]
        [string]$type = "Ethernet",
        
        [parameter(Mandatory = $true, parameterSetName="Ethernet",Position=1)] 
        [int32]$vlanId,

        [parameter(Mandatory = $true, parameterSetName="VLANIDRange",Position=1)]
        [string]$vlanRange,

        [parameter(Mandatory = $false, parameterSetName="Ethernet",Position=2)] 
        [ValidateSet('Untagged','Tagged','Tunnel')]
        [string]$VLANType = "Tagged", 

        [parameter(Mandatory = $false, parameterSetName="VLANIDRange")]
        [parameter(Mandatory = $false, parameterSetName="Ethernet")]
        [ValidateSet("General", "Management", "VMMigration", "FaultTolerance")]
        [string]$purpose = "General", 

        [parameter(Mandatory = $false, parameterSetName="VLANIDRange")]
        [parameter(Mandatory = $false, parameterSetName="Ethernet")]
        [boolean]$smartLink = $true, 

        [parameter(Mandatory = $false, parameterSetName="VLANIDRange")]
        [parameter(Mandatory = $false, parameterSetName="Ethernet")]
        [boolean]$privateNetwork = $false, 

        [parameter(Mandatory = $false, parameterSetName="FC")]
        [ValidateSet("Auto", "Two_Gbps", "Four_Gbps", "Eight_Gbps", IgnoreCase = $false)]
        [string]$fcUplinkBandwidth = $Null, 

        [parameter(Mandatory = $false, parameterSetName="VLANIDRange")]
        [parameter(Mandatory = $false, parameterSetName="Ethernet")]
        [parameter(Mandatory = $false, parameterSetName="FC")]
        [validaterange(2,20000)]
        [int32]$typicalBandwidth = 2500, 
        
        [parameter(Mandatory = $false, parameterSetName="VLANIDRange")]
        [parameter(Mandatory = $false, parameterSetName="Ethernet")]
        [parameter(Mandatory = $false, parameterSetName="FC")]
        [validaterange(100,20000)]
        [int32]$maximumBandwidth = 10000, 

        [parameter(Mandatory = $false, parameterSetName="FC")]
        [int32]$linkStabilityTime = 30, 

        [parameter(Mandatory = $false, parameterSetName="FC")]
        [boolean]$autoLoginRedistribution = $False,

        [parameter(Mandatory = $false, parameterSetName="FC")]
        [ValidateSet("FabricAttach","FA", "DirectAttach","DA")]
        [string]$fabricType="FabricAttach",

        [parameter(Mandatory = $false, parameterSetName="FC", ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [object]$managedSan=$Null,

        [parameter(Mandatory = $true, parameterSetName="importFile", HelpMessage = "Enter the full path and file name for the input file.")]
        [Alias("i", "import")]
        [string]$importFile
    )

    Begin {

        If (!$global:cimgmtSessionId) { 
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException ResourceExists AuthenticationError $script:HPOneViewAppliance -Message "You are already logged into $Appliance. Please use Disconnect-HPOVMgmt to end your existing session, and then call Connect-HPOVMgmt again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        if ($fcUplinkBandwidth) {

            Write-Warning "FcUplinkBandwidth parameter has been deprecated and is no longer used. Please specify the Uplink Bandwidth when creating the Uplink Set using New-HPOVUplinkSet -FcUplinkSpeed parameter."

        }
    }
     
    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resolved Parameter Set Name: $($PsCmdLet.ParameterSetName)"

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Type Requested: $($type)"

        switch ($type) {

            "Ethernet" {

                if (-not $vlanRange) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Creating '$name' Ethernet Network"

                    $network = [pscustomobject]@{
                    
                        type                = "ethernet-networkV2"; 
                        vlanId              = $vlanId; 
                        ethernetNetworkType = $VLANType; 
                        purpose             = $purpose; 
                        name                = $Name; 
                        smartLink           = $smartLink;
                        privateNetwork      = $privateNetwork
                    }

                }

                else {
                    
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Creating bulk '$name' + '$vlanRange' Ethernet Networks"

                    $network = [pscustomobject]@{

                        type           = "bulk-ethernet-network"; 
                        vlanIdRange    = $vlanRange; 
                        purpose        = $purpose; 
                        namePrefix     = $Name; 
                        smartLink      = $smartLink; 
                        privateNetwork = $privateNetwork

                    }

                }

            }

            { @("FC","FibreChannel","Fibre Channel") -contains $_ } {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Creating '$name' FC Network"

                #If maxbandiwdth value isn't specified, 10Gb is the default value, must change to 8Gb
                if ( $maximumBandwidth -eq 10000 ){$maximumBandwidth = 8000}

                #Get Managed SAN Fabric URI for Fabric Attach
                if ($managedSan) { 

                    if ($managedSan -is [PSCustomObject] -and $managedSan.category -eq 'fc-sans') { 
                    
                        $managedSanObject = $managedSan 
                        
                    }

                    elseif ($managedSan -is [PSCustomObject] -and -not ($managedSan.category -eq 'fc-sans')) { 
                    
                        $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException InvalidManagedSanUri InvalidArgument 'New-HPOVNetwork' -Message "The Managed SAN object category provided '$($managedSan.category)' is not the the expected value of 'fc-sans'. Please verify the parameter value and try again." #-verbose
                        $PSCmdlet.ThrowTerminatingError($errorRecord)   
                        
                    }

                    elseif ($managedSan -is [String] -and $managedSan.StartsWith($script:fcManagedSansUri)) { 
                    
                        $managedSanObject = [pscustomobject]@{uri = $managedSan}
                        
                    }
                   
                    elseif ($managedSan -is [String] -and $managedSan.StartsWith('/rest/')) { 
                    
                        $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException InvalidManagedSanUri InvalidArgument 'New-HPOVNetwork' -Message "The Managed SAN Uri provided '$managedSan' is incorrect.  Managed SAN URI must begin with '/rest/fc-sans/managed-sans'." #-verbose
                        $PSCmdlet.ThrowTerminatingError($errorRecord)                       
                    
                    }
                    
                    elseif ($managedSan -is [String]) {

                        $managedSanObject = Get-HPOVManagedSan $managedSan

                    }

                }

                else { $managedSanObject = [PSCustomObject]@{ uri = $Null }}

                $network = [pscustomobject]@{

                    type                    = "fc-networkV2"; 
                    name                    = $Name; 
                    linkStabilityTime       = $linkStabilityTime; 
                    autoLoginRedistribution = $autoLoginRedistribution; 
                    fabricType              = $FabricType; 
                    connectionTemplateUri   = $null;
                    managedSanUri           = $managedSanObject.uri
                
                }
                
            }

            default { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Invalid type: $($type)" }
        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Object:  $($network | fl | out-string)"

        If ($importFile) {

            try {

                $network = [string]::Join("", (gc $importfile -ErrorAction Stop)) | convertfrom-json -ErrorAction Stop

            }
            catch [System.Management.Automation.ItemNotFoundException] {

                $errorRecord = New-ErrorRecord System.Management.Automation.ItemNotFoundException InputFileNotFound ObjectNotFound 'New-HPOVNetwork' -Message "$importFile not found.  Please check the filename or path is valid and try again." #-verbose
                    
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }
            catch [System.ArgumentException] {

                $errorRecord = New-ErrorRecord System.ArgumentException InvalidJSON ParseError 'New-HPOVNetwork' -Message "JSON incorrect or invalid within '$importFile' input file." #-verbose
                    
                #Generate Terminating Error
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

        }

    }

    end {

        $colStatus = $null
        $colStatus = @()

        foreach($net in $network) {

            if ($net.defaultTypicalBandwidth) { $typicalBandwidth = $net.defaultTypicalBandwidth }
            if ($net.defaultMaximumBandwidth) { $maximumBandwidth = $net.defaultMaximumBandwidth }
            if ($net.typicalBandwidth) { $typicalBandwidth = $net.typicalBandwidth }
            if ($net.maximumBandwidth) { $maximumBandwidth = $net.maximumBandwidth }

            switch ($net.type) {

                "ethernet-networkV2" {

                    write-host "Creating Ethernet Network" $net.name 

                    $netUri = $script:ethNetworksUri

                    $net = $net | select name, type, vlanId, smartLink, privateNetwork, purpose, ethernetNetworkType

                }

                "fc-networkV2" {

                    write-host "Creating FC Network" $net.name

                    $netUri = $script:fcNetworksUri

                    $net = $net | select name, linkStabilityTime, autoLoginRedistribution, type, fabricType, managedSanUri, connectionTemplateUri 

                }

                "bulk-ethernet-network" {
                    
                    write-host "Creating bulk '$name' + '$vlanRange' Ethernet Networks"
                    $netUri = $script:ethNetworksUri + "/bulk"

                }
                
                #Should never get here.  If so, this is an internal error we need to fix.
                default {

                    $errorRecord = New-ErrorRecord System.ArgumentException InvalidNetworkType InvalidType 'New-HPOVNetwork' -Message "(INTERNAL ERROR) The Network Resource Type $($net.type) is invalid for '$($net.name)' network." #-verbose
                    
                    #Generate Terminating Error
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }

            }

            $objStatus = [pscustomobject]@{ Name = $net.Name; Status = $Null; Details = $Null }

            #Check if Network Type is Direct Attach and if ManagedFabric parameter is being called at the same time.
            if (($fabricType -eq "DirectAttach" -or $fabricType -eq "DA") -and $managedfabric) { 

                $objStatus.Details = "You specified a DirectAttach Fabric Type and passed the ManagedSan parameter.  The ManagedSan parameter is to be used for FabricAttach networks only."
               
            }

            else { $task = Send-HPOVRequest $netUri POST $net }

            if (!$task.Uri) {

                $objStatus.Status = "Failed"
                
                #Do not want to overwrite the details value from the Fabric Type check above.
                if ($task) { $objStatus.Details = $task }

            }

            else { 
                
                #Wait for the network to be created
                $task = Wait-HPOVTaskComplete $task.Uri
                $objStatus.Status = $task.taskState
                $objStatus.Details = $task

            }

            $colStatus += $objStatus

            if($objStatus.details.associatedResource.resourceUri) {

                $net=Send-HPOVRequest $objStatus.details.associatedResource.resourceUri

                if ($net -and $net.connectionTemplateUri) {

                    $ctUri = $net.connectionTemplateUri

                    $ct = Send-HPOVRequest $ctUri

                    if ($ct -and $ct.bandwidth) {

                        if ($typicalBandwidth) { $ct.bandwidth.typicalBandwidth = $typicalBandwidth }

                        if ($maximumBandwidth) { $ct.bandwidth.maximumBandwidth = $maximumBandwidth }

                        Set-HPOVResource -resource $ct | Out-Null

                    }

                }

            }

        }

        if ($colStatus | ? { $_.Status -ne "Completed" }) { write-error "One or more networks failed the creation attempt!" }

        $colStatus
        
    }

}

function Get-HPOVNetworkCTInfo {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdLetBinding()]
    Param (
       [parameter (Mandatory = $true)]
       [object]$nets
    )

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVNetworkCTInfo" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }
	
    Process {

        foreach ($net in $nets) {

            if ($net.connectionTemplateUri) {
                $ct = Send-HPOVRequest $net.connectionTemplateUri
            
                Add-Member -InputObject $net -NotePropertyName defaultMaximumBandwidth -NotePropertyValue $ct.bandwidth.maximumBandwidth -Force 
                Add-Member -InputObject $net -NotePropertyName defaultTypicalBandwidth -NotePropertyValue $ct.bandwidth.typicalBandwidth -Force
            }

            if ($net.type -eq "ethernet-network") {
                Set-DefaultDisplay $net -defProps 'name', 'type', 'vlanId', 'purpose', 'defaultTypicalBandwidth', 'defaultMaximumBandwidth', 'smartLink', 'privateNetwork', 'status', 'uri'
            } 
            
            elseif ($net.type -eq "fc-network") {
                Set-DefaultDisplay $net -defProps 'name', 'type', 'fabricType', 'uplinkBandwidth', 'linkStabilityTime', 'autoLoginRedistribution', 'status', 'uri'
            }
        }

        return $nets
    }
}

function Get-HPOVNetwork {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
       [parameter (Mandatory = $false, position = 0)]
       [String]$name = $null,

       [parameter (Mandatory = $false, position = 1)]
       [ValidateSet("Ethernet","FC","FibreChannel")]
       [String]$type = $null,

       [parameter (Mandatory = $false, position = 2)]
       [ValidateSet("Management","FaultTolerance","General","VMMigration", IgnoreCase = $False)]
       [String]$Purpose,

       [parameter (Mandatory = $false, position = 3)]
       [alias("x", "export")]
       [ValidateScript({split-path $_ | Test-Path})]
       [String]$exportFile,

       [parameter (Mandatory = $false)]
       [alias('list')]
       [Switch]$Report
    )

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bound PS Parameters: $($PSBoundParameters | out-string)"

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "$($MyInvocation.InvocationName.ToString().ToUpper())" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
        
    }
	
    Process {

         switch -Regex  ($type) {

            "\bFC\b|\bfibre\b|\bfibrechannel\b" {
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for FibreChannel Networks..."

                if ($name) { 
                    
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for '$($name)' FibreChannel network."
                    $fcnets = Send-HPOVRequest ($script:fcNetworksUri + "?filter=`"name matches '$name'`"" -replace ("[*]","%25"))

                    #If network not found, report error
                    if (-not ($fcnets.members)) { 

                        $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException FcNetworkResourceNotFound ObjectNotFound "$($MyInvocation.InvocationName.ToString().ToUpper())" -Message "The specified '$name' Fibre Channel Network resource not found.  Please check the name and try again." #-verbose
                        $PSCmdlet.ThrowTerminatingError($errorRecord)

                    }

                }

                else { $fcnets = Send-HPOVRequest ($script:fcNetworksUri + "?sort=name:ascending") }
                
                $members += $fcnets.members
            }

            "\bEthernet\b" {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for Ethernet networks... "

                if ($name) { 
                    
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for '$($name)' Ethernet Network network."
                    $enets = Send-HPOVRequest ($script:ethNetworksUri + "?filter=`"name matches '$name'`"" -replace ("[*]","%25"))

                    #If network not found, report error
                    if (-not ($enets.members)) { 

                        $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException EthNetworkResourceNotFound ObjectNotFound "$($MyInvocation.InvocationName.ToString().ToUpper())" -Message "The specified '$name' Ethernet Network resource not found.  Please check the name and try again." #-verbose
                        $PSCmdlet.ThrowTerminatingError($errorRecord)

                    }
                }

                else { $enets = Send-HPOVRequest ($script:ethNetworksUri + "?sort=name:ascending") }

                $members += $enets.members
            }

            Default {

                $ethUri = $script:ethNetworksUri + "?sort=name:ascending"
                $fcUri  = $script:fcNetworksUri + "?sort=name:ascending"

                if ($name) {
                    
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Name '$name' was provide, but Type was not. Searching all Network resources... "

                    #Search for Network name.
                    $ethUri += "&filter=`"name matches '$name'`"" -replace ("[*]","%25")
                    $fcUri  += "&filter=`"name matches '$name'`"" -replace ("[*]","%25")

                }

                else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Type not provided. Looking for all networks... " }
                
                $enets = Send-HPOVRequest $ethUri
                $fcnets = Send-HPOVRequest $fcUri
                $members = $enets.members + $fcnets.members

                if ($name -and -not ($members)) {

                    $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException NetworkResourceNotFound ObjectNotFound "$($MyInvocation.InvocationName.ToString().ToUpper())" -Message "The specified '$name' Network resource not found.  Please check the name and try again." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }
                
            }

        }

    }

    end {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Networks Found: $($members | out-string ) "

        if ($members) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Results returned "

            #Export the network(s) to export file
            if ($exportFile) { 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Exporting JSON to $($exportFile)"
                Get-HPOVNetworkCTInfo $members | convertto-json > $exportFile 
            }

            else { $networks = Get-HPOVNetworkCTInfo $members }

            #If user wants report, generate report
            if ($report) {

                $ethNetsCol = @()
                $fcNetsCol = @()

                ForEach ($ethNet in $($networks | where {$_.category -eq "ethernet-networks"})) { 
                
                    $ethNetsCol += $ethNet
                
                }
                
                ForEach ($fcNet in $($networks | where {$_.category -eq "fc-networks"})) { 
                
                    $fcNetsCol += $fcNet
                    
                }

                #Display Pertinant Network data in Table format
                #Ethernet Networks
                $e = @{Expression={$_.name};Label="Name";width=15}, `
                        @{Expression={$_.vlanId};Label="VLAN ID";width=8}, `
                        @{Expression={$_.purpose};Label="Purpose";width=15},`
                        @{Expression={$_.defaultTypicalBandwidth};Label="Typical Bandwidth";width=18},`
                        @{Expression={$_.defaultMaximumBandwidth};Label="Max Bandwidth";width=14},`
                        @{Expression={$_.smartLink};Label="Smartlink";width=10},`
                        @{Expression={$_.privateNetwork};Label="Private Network";width=16},`
                        @{Expression={$_.status};Label="Status";width=6}
                
                #FC Networks
                $f = @{Expression={$_.name};Label="Name"}, `
                        @{Expression={$_.fabricType};Label="Fabric Type"},`
                        @{Expression={$_.defaultTypicalBandwidth};Label="Typical Bandwidth";width=18},`
                        @{Expression={$_.defaultMaximumBandwidth};Label="Max Bandwidth";width=14},`
                        @{Expression={$_.linkStabilityTime};Label="Link Stability Time (sec)"},`
                        @{Expression={$_.autoLoginRedistribution};Label="Auto Login Redistribution"},`
                        @{Expression={$_.status};Label="Status"}
                
		        #Display List
                switch -RegEx ($type) {
                
                    "\bEthernet\b" {
                
                        Write-Host ""
                        Write-Host "Ethernet Networks"
                        Write-Host "-----------------"
                        If ($ethNetsCol) { 
                            $ethNetsCol | sort-object -property name | format-table $e -AutoSize 
                            write-host "Done. $($ethNetsCol.count) ethernet network resource(s) found."
                        }
                        else { Write-Host "None. Maybe you should create some with New-HPOVNetwork." -ForegroundColor Yellow }
                    }

                    "\bFC\b|\bfibre\b|\bfibrechannel\b" {
                        Write-Host ""
                        Write-Host "FC Networks"
                        Write-Host "-----------"
                        If ($fcNetsCol) { 
                            $fcNetsCol | sort-object -property name | format-table $f -AutoSize 
                            "Done. {0} fibre channel network resource(s) found." -f $fcNetsCol.count | out-host
                        }
                        else { Write-Host "None. Maybe you should create some with New-HPOVNetwork." -ForegroundColor Yellow }
                        Write-Host ""
                    }

                    default {

                        Write-Host ""
                        Write-Host "Ethernet Networks"
                        Write-Host "-----------------"
                        If ($ethNetsCol) { 
                            $ethNetsCol | sort-object -property name | format-table $e -AutoSize 
                            "Done. {0} ethernet network resource(s) found." -f $ethNetsCol.count | out-host 
                        }
                        else { Write-Host "None. Maybe you should create some with New-HPOVNetwork." -ForegroundColor Yellow }

                        Write-Host ""
                        Write-Host "FC Networks"
                        Write-Host "-----------"
                        If ($fcNetsCol) { 
                            $fcNetsCol | sort-object -property name | format-table $f -AutoSize 
                            "Done. {0} fibre channel network resource(s) found." -f $fcNetsCol.count | out-host
                        }
                        else { Write-Host "None. Maybe you should create some with New-HPOVNetwork." -ForegroundColor Yellow }
                        Write-Host ""
                    }
                }
            }

            #else return network object(s)
            else { 

                $networks
                if ($networks -is [PsCustomObject]) { write-host "Done. 1 network resource(s) found." }
                else { "Done. {0} network resource(s) found." -f $networks.count | out-host }

            }
        }

        #No networks found
        elseif (!$members) { write-verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Network resources found." }
    }
}

function Set-HPOVNetwork {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
        [parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Provide the Network Name, URI or Resource Object to be modified.",ParameterSetName = "Ethernet")]
        [ValidateNotNullOrEmpty()]
        #[ValidateScript({if (($_ -is [PSCustomObject] -and ($_.category -eq "ethernet-network" -or $_.category -eq "fc-network")) -or ($_ -is [String]) -or ($_ -is [string] -and $_.startswith('/rest'))) {$true} else {throw "Invalid parameter value." }})]
        [Alias('net')]
        [Object]$network,

        [parameter(Position = 1, Mandatory = $false, ValueFromPipeline = $false, HelpMessage = "Enter the new Name of the network object.", ParameterSetName = "Ethernet")]
        [parameter(Position = 1, Mandatory = $false, ValueFromPipeline = $false, HelpMessage = "Enter the new Name of the network object.", ParameterSetName = "FibreChannel")]
        [ValidateNotNullOrEmpty()]
        [string]$Name = $Null,

        [parameter(Position = 2, Mandatory = $false, ValueFromPipeline = $false, HelpMessage = "Enter the new Purpose of the network object.", ParameterSetName = "Ethernet")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("General", "Management", "VMMigration", "FaultTolerance")]
        [string]$Purpose = $Null,

        [parameter(Mandatory = $false, parameterSetName="Ethernet")]
        [bool]$smartLink, 

        [parameter(Mandatory = $false, parameterSetName="Ethernet")]
        [bool]$privateNetwork, 

        [parameter(Position = 5, Mandatory = $false, parameterSetName="Ethernet")]
        [parameter(Position = 2, Mandatory = $false, parameterSetName="FibreChannel")]
        [validaterange(2,20000)]
        [int32]$typicalBandwidth = $null, 
        
        [parameter(Position = 6, Mandatory = $false, parameterSetName="Ethernet")]
        [parameter(Position = 3, Mandatory = $false, parameterSetName="FibreChannel")]
        [validaterange(100,20000)]
        [int32]$maximumBandwidth = $Null, 

        [parameter(Position = 4, Mandatory = $false, parameterSetName="FibreChannel")]
        [ValidateRange(1,1800)]
        [int32]$linkStabilityTime = $NUll, 

        [parameter(Position = 5, Mandatory = $false, parameterSetName="FibreChannel")]
        [bool]$autoLoginRedistribution,

        [parameter(Position = 6, Mandatory = $false, parameterSetName="FibreChannel")]
        [ValidateNotNullOrEmpty()]
        [object]$managedSan = $Null

    )
    
    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVNetwork" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if (-not $PSBoundParameters['Network']) { $PipelineInput = $True }

    }

    Process {

        foreach ($net in $network) {

            switch ($net.Gettype().Name) {

                "PSCustomObject" { 
    
                    if ($net -is [PSCustomObject] -and ($net.category -eq "ethernet-networks" -or $net.category -eq "fc-networks")) {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $($net.type) $($net.name) resource."
                        $updatedNetwork = $net

                    }

                    else {

                        $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException InvalidArgumentValue InvalidArgument 'Set-HPOVNetwork' -Message "[$($net.gettype().name)] is an unspported data type.  Only [System.String] or [PSCustomObject] or an [Array] of [System.String] or [PSCustomObject] network resources are allowed.  Please check the -network parameter value and try again."
                        $PSCmdLet.ThrowTerminatingError($errorRecord)

                    }
                    
                
                }
                "String" { 
                
                    if ($net -is [String] -and -not ($net.StartsWith('/rest/'))) {
                    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting '$($net)' resource from appliance."
                        $updatedNetwork = Get-HPOVNetwork $net -type $PSCmdlet.ParameterSetName
                        
                        if (-not $updatedNetwork) {

                            $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException NetworkResourceNotFound ObjectNotFound 'Set-HPOVNetwork' -Message "'$net' Network was not found.  Please check the value and try again." #-verbose
                            $PSCmdLet.ThrowTerminatingError($errorRecord)

                        }
                    
                    }
                    elseif ($net -is [String] -and ($net.StartsWith('/rest/ethernet-networks/') -or $net.StartsWith('/rest/fc-networks/'))) {
                    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting '$($net)' resource from appliance."
                        $updatedNetwork = Send-HPOVRequest $net
                    
                    }
                
                }

            }

            switch ($updatedNetwork.category) {


                "ethernet-networks" {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $($updatedNetwork.name) Ethernet Network."

                    switch ($PSBoundParameters.keys) {

                        "purpose" { 
                        
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting network Purpose to: $purpose"
                            $updatedNetwork.purpose = $purpose
                            
                        }

                        "smartlink" {

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting smartlink Enabled to: $([bool]$smartlink)"
                            $updatedNetwork.smartlink = [bool]$smartlink

                        }
                        "privateNetwork" { 

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting privateNetwork Enabled to: $([bool]$privateNetwork)"
                            $updatedNetwork.privateNetwork = [bool]$privateNetwork
                        
                        }

                    }

                }
                "fc-networks" {

                    switch ($PSBoundParameters.keys) {

                        "linkStabilityTime" {

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting linkStabilityTime to '$linkStabilityTime' seconds"
                            $updatedNetwork.linkStabilityTime = [int]$linkStabilityTime

                        }
                        "autoLoginRedistribution" {

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting autoLoginRedistribution Enabled to: $([bool]$autoLoginRedistribution)"
                            $updatedNetwork.autoLoginRedistribution = [bool]$autoLoginRedistribution

                        }
                        "managedSan" {

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing ManagedSAN for FC Network."
                    
                            switch ($managedSan.Gettype().Name) {

                                "PSCustomObject" { 
                                
                                    if( $managedSan.category -eq 'fc-sans') { 
                                    
                                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Adding $($managedSan.name) ManagedSAN to '$($originalNetwork.name)' FC Network."
                                        $updatedNetwork.managedSanUri = $managedSan.uri
                                    
                                    }
                                    else {

                                        $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException InvalidArgumentValue InvalidArgument 'Set-HPOVNetwork' -Message "'$($managedSan.category)' is an unspported categroy.  Only 'fc-sans' is supported.  Please check the -managedSan parameter value and try again."
                                        $PSCmdLet.ThrowTerminatingError($errorRecord)

                                    }
                                
                                }
                                "String" { 
                                
                                    if ($managedSan.StartsWith('/rest/fc-sans')) { $updatedNetwork.managedSanUri = $managedSan }
                                    else {
        
                                        $originalNetwork.managedSanUri = (Get-HPOVManagedSan $managedSan).uri
        
                                    }
                                
                                }
                                default { }

                            }

                        }

                    }

                }

            }

            if ($PSBoundParameters["name"]) {
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Network name to '$name'."
                $updatedNetwork.name = $name
            
            }
            if ($PSBoundParameters["typicalBandwidth"] -or $PSBoundParameters["maximumBandwidth"]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Network bandwidth assignment."
                $ct = Send-HPOVRequest $updatedNetwork.connectionTemplateUri
                
                if ($PSBoundParameters["maximumBandwidth"]) {
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Original Maximum bandwidth assignment: $($ct.bandwidth.maximumBandwidth)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New Maximum bandwidth assignment: $maximumBandwidth"
                    $ct.bandwidth.maximumBandwidth = $maximumBandwidth

                }
                if($PSBoundParameters["typicalBandwidth"]) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Original Typical bandwidth assignment: $($ct.bandwidth.typicalBandwidth)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New Typical bandwidth assignment: $typicalBandwidth"
                    $ct.bandwidth.typicalBandwidth = $typicalBandwidth
                    
                }

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Connection Template: $($ct | out-string)"
                $ct = Set-HPOVResource $ct

            }

            $updatedNetwork = $updatedNetwork | select * -ExcludeProperty defaultTypicalBandwidth, defaultMaximumBandwidth, created, modified
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Network Resource object: $($updatedNetwork | out-string)"
            $netNew += Set-HPOVResource $updatedNetwork
        }

    }

    end {

        if ($netNew.count -eq 1) { $netNew[0] }
        else { $netNew }

    }

} 

function Remove-HPOVNetwork {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True,ConfirmImpact = 'High')]
    Param
    (
        [parameter (Mandatory = $true,ValueFromPipeline = $true, ParameterSetName = "default", HelpMessage = "Specify the network to remove.", Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        [System.Object]$network = $null
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVNetwork" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }


    Process {

        foreach ($net in $network) {

            $networkNameOrUri = $null;
            $networkDisplayName = $null;

            #Network passed is a URI
            if (($net -is [String]) -and ($net.startsWith("/rest"))) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received URI: $($net)"
                $networkNameOrUri = $net
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Network Name"
                $networkDisplayName = (Send-HPOVRequest $net).name
            }

            #Network passed is the Name
            elseif (($net -is [string]) -and (!$net.startsWith("/rest"))) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received Network Name $($net)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Network"
                
                #NEED TO UPDATE SO WE DON"T CALL OUT TO Get-HPOVNetwork.  Just attempt to remove and capture HTTP 404 Response.
                $network = Get-HPOVNetwork $net
                if ($network.count -gt 1 ) { 
                    $errorRecord = New-ErrorRecord InvalidOperationException NetworkResourceNameNotUnique InvalidResult 'Remove-HPOVNetwork' -Message "Invalid Network parameter: $net" #-verbose
                    $PSCmdlet.WriteError($errorRecord)                
                    #Write-Error "Network Name $($net) is not unique" -Category InvalidResult -CategoryTargetName "Remove-HPOVNetwork"; return
                }
                else {
                    $networkNameOrUri = $network.uri
                    $networkDisplayName = $network.name
                }
            }

            #Network passed is the object
            elseif ($net -is [PSCustomObject] -and ($net.category -ieq 'ethernet-networks' -or $net.category -ieq 'fc-networks')) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())]"
                $networkNameOrUri = $net.uri;
                $networkDisplayName = $net.name;
            }
            else {
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVNetwork' -Message "Invalid Network parameter: $net" #-verbose
                $PSCmdlet.WriteError($errorRecord)

            }

            if (!$networkNameOrUri) {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVNetwork' -Message "Invalid Network parameter: $net" #-verbose
                $PSCmdlet.WriteError($errorRecord)

            }
            elseif ($pscmdlet.ShouldProcess($networkDisplayName,'Remove network from appliance?')) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Removing Network from appliance."
                Remove-HPOVResource -nameOrUri $networkNameOrUri
            }
        }
    }
}

function New-HPOVNetworkSet {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
       [parameter (Position=0,Mandatory = $True)]
       [String]$name=$null,

       [parameter (Position=1,Mandatory = $True)]
       [alias('networkUris')]
       [Array]$networks=$null,

       [parameter (Position=2,Mandatory = $False)]
       [Alias ('untagged','native','untaggedNetworkUri')]
       [String]$untaggedNetwork=$null,

       [parameter (Position=3,Mandatory = $False)]
       [int32]$typicalBandwidth=2500,

       [parameter (Position=4,Mandatory = $False)]
       [int32]$maximumBandwidth=10000

    )
	
	Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVNetworkSet" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

	}
	
	Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requesting to create $($name)"

        foreach ($net in $networks) {

            if ($net -is [string] -and $net.startswith('/rest/ethernet-networks')) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network is a URI: $net"
                [array]$networkUris += $net

            }
            elseif ($net -is [string]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network is a Name: $net"
                [array]$networkUris += (get-hpovnetwork $net).uri
            }
            elseif ($net -is [string] -and -not $net.startswith('/rest/ethernet-networks')) {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'New-HPOVNetworkSet' -Message "Network '$net' is the correct type, but invalid URI prefix.  Network URI must start with '/rest/ethernet-networks'.  Please correct the parameter value and try again."
                $PSCmdlet.ThrowTerminatingError($errorRecord)


            }
            elseif ($net -is [PsCustomObject] -and $net.category -eq "ethernet-networks") {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network is a type [PsCustomObject]"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Name: $net.name"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network uri: $net.uri"
                [array]$networkUris += $net.uri

            }
            else {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'New-HPOVNetworkSet' -Message "Network '$net' is not a supported type '$($net.gettype().fullname)'.  Network resource must be either [System.String] or [PsCustomObject].  Please correct the parameter value and try again."
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }
            
        }

    	If ($untaggedNetwork){

            if ($untaggedNetwork -is [string] -and $untaggedNetwork.startswith('/rest/ethernet-networks')) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network is a URI: $untaggedNetwork"
                [string]$untaggedNetworkUri = $untaggedNetwork

            }
            elseif ($untaggedNetwork -is [string]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network is a Name: $untaggedNetwork"
                [string]$untaggedNetworkUri = (get-hpovnetwork $untaggedNetwork).uri
            }
            elseif ($untaggedNetwork -is [string] -and -not $untaggedNetwork.startswith('/rest/ethernet-networks')) {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'New-HPOVNetworkSet' -Message "UntaggedNetwork '$untaggedNetwork' is the correct type, but invalid URI prefix.  UntaggedNetwork URI must start with '/rest/ethernet-networks'.  Please correct the parameter value and try again."
                $PSCmdlet.ThrowTerminatingError($errorRecord)


            }
            elseif ($untaggedNetwork -is [PsCustomObject] -and $untaggedNetwork.category -eq "ethernet-networks") {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network is a type [PsCustomObject]"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network Name and is the Untagged Network: $($untaggedNetwork.name)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network uri: $($untaggedNetwork.uri)"
                [string]$untaggedNetworkUri = $untaggedNetwork.uri

            }
            else {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'New-HPOVNetworkSet' -Message "Network '$net' is not a supported type '$($net.gettype().fullname)'.  Network resource must be either [System.String] (which must either be the Network Name or proper URI that starts with '/rest/ethernet-networks') or [PsCustomObject].  Please correct the parameter value and try again."
                $PSCmdlet.ThrowTerminatingError($errorRecord)


            }

			$netset = @{
		        type="network-set"; 
		        name=$name; 
		        networkUris=$networkUris; 
		        nativeNetworkUri=$untaggedNetworkUri; 
	    	}

		}
		else {

			$netset = @{
		        type="network-set"; 
		        name=$name; 
		        networkUris=$networkUris;
    		}

		}

		Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Set object: $($netset | out-string)"

        #Caller is requesting different bandwidth settings.  Need to handle async task to create network set.
        if (($typicalBandwidth -ne 2500) -or ($maximumBandwidth -ne 10000)) {

	        try {

                $task = New-HPOVResource $networkSetsUri $netset

                $taskStatus = Wait-HPOVTaskComplete $task

                if ($taskStatus.taskStatus -eq "Created") {
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Set was succssfully created"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Network Set bandwidth"
			        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requested Typical bandwidth: $($typicalBandwidth)"
			        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requested Maximum bandwidth: $($maximumBandwidth)"

                    #Get NEtwork Set Object
                    $newNetSet = Send-HPOVRequest $taskStatus.associatedResource.resourceUri

	                if ($newNetSet -and $newNetSet.connectionTemplateUri) {
	                    # Update the associated connection template with max & typical bandwidth settings:
	                    $ctUri = $newNetSet.connectionTemplateUri
	                    $ct = Send-HPOVRequest $ctUri
	                    if ($ct -and $ct.bandwidth) {
	                        if ($typicalBandwidth) { $ct.bandwidth.typicalBandwidth = $typicalBandwidth }
	                        if ($maximumBandwidth) { $ct.bandwidth.maximumBandwidth = $maximumBandwidth }
	                        Set-HPOVResource -resource $ct
	                    }
                    }
                }
            }
            catch {

                $errorRecord = New-ErrorRecord InvalidOperationException $task.errorCode InvalidResult 'New-HPOVNetworkSet' -Message $task.message
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

	    }

        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request with default bandwidth."
            $newNetSet = Send-HPOVRequest $networkSetsUri POST $netset

        }

    }

    end {

	    #Return Network Set
	    return $newNetSet
	}
}

function Get-HPOVNetworkSet {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "Default")]
    Param (
       [parameter (Position = 0, ParameterSetName = "Default", Mandatory = $false)]
       [parameter (Position = 0, ParameterSetName = "Export", Mandatory = $false)]
       [String]$name=$null,

       [parameter (ParameterSetName = "Default", Mandatory = $false)]
       [Switch]$List,

       [parameter (ParameterSetName = "Export", Mandatory = $false)]
       [alias("x", "export")]
       [ValidateScript({split-path $_ | Test-Path})]
       [String]$exportFile
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVNetworkSet" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $uri = $networkSetsUri + "?sort=name:asc"

        if ($name) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering for Network Set name: $name"
            $uri += "&filter=name matches '$name'" -replace "[*]","%25"

        }

        $netsets = (Send-HPOVRequest $uri).members

    }

    End {

        if ($netsets) { 
        
            $netsets = Get-HPOVNetworkSetCTInfo $netsets 
        
            If($exportFile){
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Exporting to JSON file: $exportFile"
                $netsets | convertto-json > $exportFile
            
            }
            elseif ($list) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating table view"

                [Array]$netSetsList = @()

                foreach ($netset in $netsets) {
                    [PsCustomObject]$tmpNetSet = $netset
                    
                    [array]$networks = @()

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing NetSet: $($netset.name)"
                    foreach ($netUri in $netset.networkUris) { 
                        
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] looking for $netUri"
                        $tempNet = Send-HPOVRequest $netUri -verbose:$false
                        if ($tempNet.uri -eq $netset.nativeNetworkUri) { 
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found Native Network: $($tempNet.name)"
                            $network = $tempNet.name + " [Untagged]" 
                        }
                        else  { 
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Adding {$($tempNet.name)} to array."
                            $network = $tempNet.name 
                        }
                        [array]$networks +=  $network
                    }
                    [array]::sort($networks)

                    $tmpNetSet | add-member -NotePropertyName networks -NotePropertyValue $networks

                    $netSetsList += $tmpNetSet

                }

                $netSetTable = @{Expression={$_.name};Label="Name"},
                     @{Expression={$_.status};Label="Status"},
                     @{Expression={(Send-HPOVRequest $_.connectionTemplateUri).bandwidth.typicalBandwidth};Label="Typical Bandwidth"},
                     @{Expression={(Send-HPOVRequest $_.connectionTemplateUri).bandwidth.maximumBandwidth};Label="Max Bandwidth"},
                     @{Expression={
                         $Display = $null ; 
                         $i = 0 ; 
                         $count = $_.networks.Count ;
                         $_.networks | %{
                                         $i++
                                         $Display = $Display + $_ ;
                                         if(($i -ne $count) -and ($i % 2 -eq 1)) {$Display = $Display + ", "}
                                         elseif(($i -ne $count) -and ($i % 2 -eq 0)) {$Display = $Display + ", `n"}
                                        } 
                         $Display};Label="Networks"}
                     

                $netSetNetworkTable = @{Expression={$_.networks};Label="Networks"}

                $netSetsList | format-table $netSetTable -wrap -autosize

            }

            else {

                $netsets

            }

            if ($netsets -is [PsCustomObject]) { write-host "Done. 1 network set resource(s) found." }
            else { "Done. {0} network set resource(s) found." -f $netsets.count | out-host }
            
        }
        else { 
        
            if (-not $name) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Network Set resources found." }
            else {                          
                $errorRecord = New-ErrorRecord InvalidOperationException NetworkSetResourceNotFound ObjectNotFound 'Get-HPOVNetworkSet' -Message "'$name' Network Set resource not found.  Please check the name and try again." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        
        }

    }

}

function Get-HPOVNetworkSetCTInfo {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdLetBinding()]
    
    Param (
       [parameter (Mandatory = $true, ValueFromPipeline = $True)]
       [ValidateNotNullorEmpty()]
       [object]$netsets
    )

    Begin { 
    
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVNetworkSetCTInfo" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        foreach ($netset in $netsets) {

            if ($netset.connectionTemplateUri) {

                $ct = Send-HPOVRequest $netset.connectionTemplateUri
                
                Add-Member -InputObject $netset -NotePropertyName maximumBandwidth -NotePropertyValue $ct.bandwidth.maximumBandwidth -Force 
                Add-Member -InputObject $netset -NotePropertyName typicalBandwidth -NotePropertyValue $ct.bandwidth.typicalBandwidth -Force

            }

        }
    
    }

    end {

        $netsets

    }
}

function Set-HPOVNetworkSet {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (

        [parameter (Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullorEmpty()]
        [object]$netSet,

        [parameter (Mandatory = $false, Position = 1)]
        [ValidateNotNullorEmpty()]
        [string]$name,

        [parameter (Mandatory = $false, Position = 2)]
        [ValidateNotNullorEmpty()]
        [object]$networks,

        [parameter (Mandatory = $False, Position = 3)]
        [Alias ('untagged','native','untaggedNetworkUri')]
        [ValidateNotNullorEmpty()]
        [Object]$untaggedNetwork=$null,

        [parameter(Position = 5, Mandatory = $false)]
        [validaterange(2,20000)]
        [int32]$typicalBandwidth = $null, 
        
        [parameter(Position = 6, Mandatory = $false)]
        [validaterange(100,20000)]
        [int32]$maximumBandwidth = $Null

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Set-HPOVNetworkSet" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        #Process Network Set input object is the correct resource and data type.
        switch ($netSet.Gettype().Name) {

            "PSCustomObject" { 
    
                if ($netSet -is [PSCustomObject] -and ($netSet.category -eq "network-sets")) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $($netSet.type) $($netSet.name) resource."
                    $updatedNetworkSet = $netSet

                }

                else {

                    $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException InvalidArgumentValue InvalidArgument 'Set-HPOVNetworkSet' -Message "[$($netSet.gettype().name)] is an unspported data type.  Only [System.String] or [PSCustomObject] or an [Array] of [System.String] or [PSCustomObject] network set resources are allowed.  Please check the -network parameter value and try again."
                    $PSCmdLet.ThrowTerminatingError($errorRecord)

                }
                
            
            }
            "String" { 
            
                if ($netSet -is [String] -and -not ($netSet.StartsWith('/rest/network-sets'))) {
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting '$($netSet)' resource from appliance."
                    $updatedNetworkSet = Get-HPOVNetworkSet $netSet
                    
                    if (-not $updatedNetworkSet) {

                        $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException NetworkSetResourceNotFound ObjectNotFound 'Set-HPOVNetwork' -Message "'$netSet' Network Set was not found.  Please check the value and try again." #-verbose
                        $PSCmdLet.ThrowTerminatingError($errorRecord)

                    }
                
                }
                elseif ($netSet -is [String] -and ($netSet.StartsWith('/rest/network-Sets'))) {
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting '$($netSet)' resource from appliance."
                    $updatedNetworkSet = Send-HPOVRequest $netSet
                
                }
            
            }

        }

        #Process Network Set Name change
        if ($PSBoundParameters["name"]) {
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Network name to '$name'."
            $updatedNetworkSet.name = $name
        
        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $($networks.count) network resources"

        [array]::sort($networks)

        $i = 1

        foreach ($net in $networks) {

            if ($net -is [string] -and $net.startswith('/rest/ethernet-networks')) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network [$i] is a URI: $net"
                [array]$networkUris += $net

            }
            elseif ($net -is [string]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network [$i] is a Name: $net"
                [array]$networkUris += (get-hpovnetwork $net).uri
            }
            elseif ($net -is [string] -and -not ($net.startswith('/rest/ethernet-networks'))) {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Set-HPOVNetworkSet' -Message "Network '$net' is the correct type, but invalid URI prefix.  Network URI must start with '/rest/ethernet-networks'.  Please correct the parameter value and try again."
                $PSCmdlet.ThrowTerminatingError($errorRecord)


            }
            elseif ($net -is [PsCustomObject] -and $net.category -eq "ethernet-networks") {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network [$i] is a type [PsCustomObject]"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network [$i] Name: $($net.name)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network [$i] uri: $($net.uri)"
                [array]$networkUris += $net.uri

            }
            else {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Set-HPOVNetworkSet' -Message "Network '$net' is not a supported type '$($net.gettype().fullname)'.  Network resource must be either [System.String] or [PsCustomObject].  Please correct the parameter value and try again."
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

            $updatedNetworkSet.networkUris = $networkUris

            $i++
            
        }

    	If ($untaggedNetwork){

            if ($untaggedNetwork -is [string] -and $untaggedNetwork.startswith('/rest/ethernet-networks')) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network is a URI: $untaggedNetwork"
                [string]$untaggedNetworkUri = $untaggedNetwork

            }
            elseif ($untaggedNetwork -is [string]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network is a Name: $untaggedNetwork"
                [string]$untaggedNetworkUri = (get-hpovnetwork $untaggedNetwork).uri
            }
            elseif ($untaggedNetwork -is [string] -and -not $untaggedNetwork.startswith('/rest/ethernet-networks')) {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Set-HPOVNetworkSet' -Message "UntaggedNetwork '$untaggedNetwork' is the correct type, but invalid URI prefix.  UntaggedNetwork URI must start with '/rest/ethernet-networks'.  Please correct the parameter value and try again."
                $PSCmdlet.ThrowTerminatingError($errorRecord)


            }
            elseif ($untaggedNetwork -is [PsCustomObject] -and $untaggedNetwork.category -eq "ethernet-networks") {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network is a type [PsCustomObject]"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network Name and is the Untagged Network: $($untaggedNetwork.name)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Untagged Network uri: $($untaggedNetwork.uri)"
                [string]$untaggedNetworkUri = $untaggedNetwork.uri

            }
            else {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'New-HPOVNetworkSet' -Message "Network '$net' is not a supported type '$($net.gettype().fullname)'.  Network resource must be either [System.String] (which must either be the Network Name or proper URI that starts with '/rest/ethernet-networks') or [PsCustomObject].  Please correct the parameter value and try again."
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

			$updatedNetworkSet.nativeNetworkUri = $untaggedNetworkUri

		}

        #Process Network Set Bandwidth assignment change
        if ($updatedNetworkSet["typicalBandwidth"] -or $PSBoundParameters["maximumBandwidth"]) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Network bandwidth assignment."
            $ct = Send-HPOVRequest $updatedNetworkSet.connectionTemplateUri
            
            if ($PSBoundParameters["maximumBandwidth"]) {
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Original Maximum bandwidth assignment: $($ct.bandwidth.maximumBandwidth)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New Maximum bandwidth assignment: $maximumBandwidth"
                $ct.bandwidth.maximumBandwidth = $maximumBandwidth

            }
            if($PSBoundParameters["typicalBandwidth"]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Original Typical bandwidth assignment: $($ct.bandwidth.typicalBandwidth)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New Typical bandwidth assignment: $typicalBandwidth"
                $ct.bandwidth.typicalBandwidth = $typicalBandwidth
                
            }

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Connection Template: $($ct | out-string)"
            $ct = Set-HPOVResource $ct

        }

        $updatedNetworkSet = $updatedNetworkSet | select * -ExcludeProperty typicalBandwidth, maximumBandwidth, created, modified, state, status
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Updating Network Resource object: $($updatedNetworkSet | out-string)"

        $newNetSet = Set-HPOVResource $updatedNetworkSet

    }

    End {
    
        $newNetSet

    }

}

function Remove-HPOVNetworkSet {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        
        [parameter (Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "default", HelpMessage = "Specify the Network Set(s) to remove.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        [object]$networkSet = $null

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVNetworkSet" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }


    }

    Process {
        foreach ($netSet in $networkSet) {
            $networkSetNameOrUri = $null;
            $networkSetDisplayName = $null;
            if ($netSet -is [String]) {
                $networkSetNameOrUri = $netSet
                $networkSetDisplayName = $netSet
            }
            elseif ($netSet -is [PSCustomObject] -and ($netSet.category -ieq 'network-sets')) {
                $networkSetNameOrUri = $netSet.uri;
                $networkSetDisplayName = $netSet.name;
            }
            else {
                
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVNetworkSet' -Message "Invalid network set parameter: $netSet" #-verbose
                $pscmdlet.WriteError($errorRecord)
                #Write-Host "Invalid network set parameter: " + $netSet
                #return
            }

            if (!$networkSetNameOrUri) {
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVNetworkSet' -Message "Invalid network set parameter: $netSet" #-verbose
                $pscmdlet.WriteError($errorRecord)
            }
            elseif ($pscmdlet.ShouldProcess($networkSetDisplayName,'Remove network set from appliance?')){    
                Remove-HPOVResource -nameOrUri $networkSetNameOrUri
            }
        }
    }
}

function Get-HPOVAddressPool {  

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "Default")]
    Param (
        
        [parameter (Mandatory = $false, ParameterSetName = "Default")]
        [Array]$Type = @("all"),

        [parameter (Mandatory = $false, ParameterSetName = "Default")]
        [Switch]$Ranges,

        [parameter (Mandatory = $false, ParameterSetName = "Default")]
        [Switch]$Report

    )


    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }


        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Requested Address Pool type: $($Type) "

        if ($type -ieq "all") { $Type = @("VMAC", "VWWN", "VSN") }

    }

    Process {

        $poolObjects = @()
        ForEach ( $poolType in $Type) {

            switch ($poolType) {

                "vmac" { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Retrieve MAC Address Pool details."
                
                    #Get the VMAC Pool object
                    $pool = Send-HPOVRequest $script:applVmacPoolsUri

                    If ($Ranges) {
                        #Embed the actual range details as a new HashTable node that is not part of the original object
						Add-Member -inputobject $pool -NotePropertyName ranges  -NotePropertyValue @()
						
						Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Retrieve MAC Address Range details."
						
                        ForEach ($range in $pool.rangeUris) {
                        
                            $rangeObj = Send-HPOVRequest $range

                            $pool.ranges += $rangeObj

                        }
                    }
					
					$poolObjects += $pool

                }

                "vwwn" { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Retrieve WWN Address Pool details."

                    $pool = Send-HPOVRequest $script:applVwwnPoolsUri 

                    If ($Ranges) {
                        #Embed the actual range details as a new HashTable node that is not part of the original object
                        Add-Member -inputobject $pool -NotePropertyName ranges  -NotePropertyValue @()
						
						Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Retrieve WWN Address Range details."
						
                        ForEach ($range in $pool.rangeUris) {
                        
                            $rangeObj = Send-HPOVRequest $range

                            $pool.ranges += $rangeObj

                        }
                    }
					
					$poolObjects += $pool
                }
                
                "vsn" {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Retrieve SN Address Pool details."

                    $pool = Send-HPOVRequest $script:applVsnPoolsUri 

                    If ($Ranges) {
                        #Embed the actual range details as a new HashTable node that is not part of the original object
                        Add-Member -inputobject $pool -NotePropertyName ranges  -NotePropertyValue @()
						
						Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Retrieve SN Address Range details."
						
                        ForEach ($range in $pool.rangeUris) {
                        
                            $rangeObj = Send-HPOVRequest $range

                            $pool.ranges += $rangeObj

                        }

                    }
					
					$poolObjects += $pool
                    
                }

            }
			
			write-verbose $($poolObjects | out-string)

        }

        if ($report) {

            ForEach ($pool in $poolObjects) {

                #Display Master Pool information
                $a = @{Expression={$_.name};Label="Pool Name";width=9},
				     @{Expression={$_.enabled};Label="Enabled";width=15},
				     @{Expression={$_.totalCount};Label="Total Count";width=12},
                     @{Expression={$_.allocatedCount};Label="Total Allocated";width=15},
				     @{Expression={$_.freeCount};Label="Total Available";width=15}


                $pool | Format-Table $a

                #Display ID range detail
                If ($pool.ranges) {
                    
                    ForEach ($range in $pool.ranges) {
                        $b = @{Expression={""};Label="|`n|";width=4},`
							 @{Expression={$_.rangeCategory};Label="`nType";width=9},`
                             @{Expression={$_.enabled};Label="`nEnabled";width=8},`
                             @{Expression={$_.startAddress};Label="`nStart Address";width=24},`
                             @{Expression={$_.endAddress};Label="`nEnd Address";width=24},`
                             @{Expression={$_.totalCount};Label="`nCount";width=8},`
                             @{Expression={$_.allocatedIdCount};Label="`nAllocated";width=10},
                             @{Expression={($_.totalCount - $_.allocatedIdCount)};Label="`nAvailable";width=10}
                        
                        $range | format-table $b -AutoSize

                    }
                }
				
				Write-Host "======================================================================================================="
            }
        }

        else { return $poolObjects }
    }

}

function New-HPOVAddressRange {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
    
        [parameter (Mandatory = $true, ParameterSetName = "Default", position = 0)]
        [parameter (Mandatory = $true, ParameterSetName = "Custom", position = 0)]
        [ValidateSet("vmac", "vwwn", "vsn")]
        [String]$PoolType = $Null,

        [parameter (Mandatory = $true, ParameterSetName = "Default", position = 1)]
        [parameter (Mandatory = $true, ParameterSetName = "Custom", position = 1)]
        [ValidateSet("Generated", "Custom")]
        [String]$RangeType = "Generated",

        [parameter (Mandatory = $true, ParameterSetName = "Custom", position = 2)]
        [String]$Start,

        [parameter (Mandatory = $true, ParameterSetName = "Custom", position = 3)]
        [String]$End
    
    )


    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        #verify-auth "New-HPOVAddressRange"

    }

    Process {

        #Get the correct URI to request a new Generated Address Range
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Creating new $($PoolType) type address range"
        switch ($PoolType) {

            "vmac" { 
            
                $newGenRangeUri = $script:applVmacGenerateUri
                $newPoolRangeUri = $script:applVmacPoolRangesUri

            }
            "vwwn" { 
            
                $newGenRangeUri = $script:applVwwnGenerateUri
                $newPoolRangeUri = $script:applVwwnPoolRangesUri
                
            }
            "vsn" { 
            
                $newGenRangeUri = $script:applVsnPoolGenerateUri
                $newPoolRangeUri = $script:applVsnPoolRangesUri
            
            }

        }

        switch ($RangeType) {

            "Generated" {
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating new address range"
            
                #send the request, and remove the fragmentType property as it's not a valid JSON pfield for the request.
                $newRange = (Send-HPOVRequest $newGenRangeUri) | Select-Object -Property * -excludeproperty fragmentType

                $newRange | add-member -NotePropertyName type -NotePropertyValue "Range"
                $newRange | add-member -NotePropertyName rangeCategory -NotePropertyValue "GENERATED"

            }
            
            "Custom" {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Creating custom new address range"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Starting Address: $($Start)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] End Address: $($End)"

                switch ($PoolType) {
                    
                    "vmac" {
                        
                        if (!($start -match ($macAddressPattern ))) { Write-Error "The Start MAC Address $($Start) is invalid." -Category SyntaxError -CategoryTargetName New-HPOVAddressRange; Break}
                        if (!($end -match ($macAddressPattern ))) { Write-Error "The End MAC Address $($End) is invalid." -Category SyntaxError -CategoryTargetName New-HPOVAddressRange; Break }
                     }
                    
                    "vwwn" {
                    
                        if (!($start -match ($wwnAddressPattern ))) { Write-Error "The Start WWN Address $($Start) is invalid." -Category SyntaxError -CategoryTargetName New-HPOVAddressRange; Break }
                        if (!($end -match ($wwnAddressPattern ))) { Write-Error "The End WWN Address $($End) is invalid." -Category SyntaxError -CategoryTargetName New-HPOVAddressRange; Break }
                    
                    }
                }
                
                $newRange = [pscustomobject]@{ startAddress = $Start; endAddress = $End; type = "Range"; rangeCategory = "CUSTOM" }
            
            }

        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New Range Object: $($newRange | format-list | out-string)"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
        $resp = Send-HPOVRequest $newPoolRangeUri POST $newRange
        return $resp

    }
 }

#######################################################
# Interconnects and Uplinks
#

function Get-HPOVInterconnectType {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = 'Name')]
    Param(
        
        [parameter (Position = 0, Mandatory = $false, ParameterSetName = 'Name')]
        [string]$name = $null,

        [parameter (Position = 0, Mandatory = $true, ParameterSetName = 'PartNumber')]
        [string]$partNumber = $null,

        [switch]$list
    )

    Begin { 
    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Validating user is authenticated"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVInterconnectType" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }    
    
    }
    
    Process {

        $uri = $interconnectTypesUri + "?sort=name:descending"

        if ($name) { $uri += "&filter=name='$name'" }
        elseif ($partNumber) { $uri += "&filter=partNumber='$partNumber'" }

        $interconnectTypes = (Send-HPOVRequest $uri ).members
            
    }

    end {

        if (-not $interconnectTypes -and $name) {

            $errorRecord = New-ErrorRecord InvalidOperationException InterconnectTypeNameResourceNotFound ObjectNotFound 'Get-HPOVInterconnectType' -Message "No Interconnect Types with '$name' name were found." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
        elseif (-not $interconnectTypes -and $partNumber) {

            $errorRecord = New-ErrorRecord InvalidOperationException InterconnectTypePartnumberResourceNotFound ObjectNotFound 'Get-HPOVInterconnectType' -Message "No Interconnect Types with '$partNumber' partnumber were found." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
        else { 
        
            if ($List) {

                $report = @{Expression={$_.name};Label="Name"},
                          @{Expression={$_.partNumber};Label="Part Number"},
                          @{Expression={if ($_.minimumFirmwareVersion) {$_.minimumFirmwareVersion} else { "N/A" }};Label="Minimum Firmware Supported"}

                $interconnectTypes | sort-object -Property name -Descending | format-table $report -AutoSize -Wrap
            
            
            }
            
            else { return $interconnectTypes }

        }

    }

}

function Get-HPOVInterconnect {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
       [parameter (Mandatory = $false)]
       [String]$name = $null,

       [parameter (Mandatory = $false)]
       [alias("x", "export")]
       [ValidateScript({split-path $_ | Test-Path})]
       [String]$exportFile,
       
       [parameter (Mandatory = $false)]
       [Alias('list')]
       [Switch]$Report

    )


    
    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Validating user is authenticated"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Show-HPOVFirmwareReport" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        $members = $null

    }

    Process {

        #Cannot implement the following due to CRM filter API bug.  Will generate HTTP 500 error.
        if ($name) {

            $interconnectName = $name -split ", "
            if ($interconnectName.length -gt 2) { "Interconnect Name contains extra commas." }
            else {
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Interconnect Name was provided: $($name)"
                $uri = $script:interconnectsUri + "?filter=name='$name'&filter=enclosureName='$($interconnectName[0])'"

            }
        
        }

        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Interconnect Name provided. Defaulting to getting all Interconnect resources."
            $uri = $script:interconnectsUri

        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to retrieve Interconnects."

        $interconnects = Send-HPOVRequest $uri

        if ($interconnects.count -eq 0 -and -not $name) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] 0 Interconnects found. $($interconnects.count)"

        }

        elseif ($interconnects.count -eq 0 -and $name)  {
               
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Interconnect '$name' was not found. Generating error message."       
            $errorRecord = New-ErrorRecord InvalidOperationException InterconnectNotFound ObjectNotFound 'Get-HPOVStorageSystem' -Message "Interconnect '$name' was not found.  Please check the name and try again." #-verbose
            $PsCmdlet.ThrowTerminatingError($errorRecord)
                
        }

        else { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ($($interconnects.count)) Interconnects found."
            $members = $interconnects.members 
            
        }

    }

    end {

        if ($members) {
            
            if($exportFile){ 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Exporting to: $($exportFile)"

                $members | convertto-json -Depth 99 | Set-Content -Path $exportFile -force -encoding UTF8
                
            }
            
            elseif ($report) { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Displaying Interconnect Report"
                
                foreach ($member in $members) {
                
                    $a = @{Expression={$_.name};Label="Name"},
		                 @{Expression={$_.model};Label="Model";width=16},
                         @{Expression={$_.serialNumber};Label="Serial Number"},
                         @{Expression={$_.interconnectIP};Label="IPv4 Address"},
		                 @{Expression={$_.status};Label="Status"},
		                 @{Expression={$_.firmwareVersion};Label="FW Version"}



                    $b = @{Expression={(Send-HPOVRequest $_.logicalInterconnectUri).name};Label="LI Group"},
                         @{Expression={$_.state};Label="State"},
                         @{Expression={"$((Send-HPOVRequest ($_.interconnectLocation.locationEntries | ? { $_.type -match "Enclosure"}).value).name) Bay: $(($_.interconnectLocation.locationEntries | ? { $_.type -match "bay" }).value)"};Label="Location"}


                    $c = @{Expression={$_.snmpConfiguration.enabled};Label="SNMP Enabled"},
                         @{Expression={$_.snmpConfiguration.readCommunity};Label="Read Community"},
                         @{Expression={
                         
                            $i = 0

                            foreach ($entry in $_.snmpConfiguration.snmpAccess) {
    
                                if ($i -eq 0) { "$($i+1): $($entry)" }
                                elseif (($i -gt 0) -and ($i -lt $_.snmpConfiguration.snmpAccess.Length)) { "`n $($i+1): $($entry) " }
                                $i++

                            }                            

                         };Label="SNMP Access"},
                         @{Expression={
                         
                            $i = 0
                            #foreach ($trap in $_.snmpConfiguration.trapDestinations) { "$($i): $($trap.communityString) -> $($trap.trapDestination)"; $i++ }
                            foreach ($trap in $_.snmpConfiguration.trapDestinations) {
    
                                if ($i -eq 0) { "$($i+1): $($trap.communityString) -> $($trap.trapDestination)" }
                                elseif (($i -gt 0) -and ($i -lt $_.snmpConfiguration.trapDestinations.Length)) { "`n $($i+1): $($trap.communityString) -> $($trap.trapDestination)" }
                                $i++

                            }
                            
                          };Label="Trap Destinations"},
                           @{Expression={""};Label=""}
                         

                    $member | format-table $a -wrap
                    $member | format-table $b -autosize
                    $member | format-table $c -wrap

                    Write-host "==================================================================================================="
            
                }
            
            }

            else { $members }

            Write-Host "Done. $($interconnects.count) logical interconnect(s) found."

        }

    }
    
}

function Get-HPOVLogicalInterconnect {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default")]
    Param (
       [parameter (Position = 0, Mandatory = $false, ParameterSetName = "default")]
       [parameter (Position = 0, Mandatory = $false, ParameterSetName = "report")]
       [String]$name = $null,

       [parameter (Position = 1, Mandatory = $false, ParameterSetName = "default")]
       [alias("x", "export")]
       [ValidateScript({split-path $_ | Test-Path})]
       [String]$exportFile,
       
       [parameter (Mandatory = $false, ParameterSetName = "report")]
       [Switch]$Report
    )

    Begin { 
    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Validating user is authenticated"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVLogicalInterconnect" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }    
    
    }

    Process {

        if ($name) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect name provided: '$name'"

            #Search Index to workaround a CRM LI filter bug
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Searching index for Logical Interconnect resource."
            $resp = Send-HPOVRequest ($script:indexUri + "?userQuery='$name'&category=logical-interconnects&sort=name:asc")

            if ($resp.count -eq 1) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect resource found. Getting resource object"
                $lsws = [PsCustomObject]@{members = [array]@(send-hpovrequest $resp.members.uri); total = 1; count = 1; category = "logical-interconnects"}
            }

            #Uncomment when CRM LI filter bug is fixed.
            #$uri = $logicalInterconnectsUri + "?filter=name='$name'"

            #This else statement is to finish the CRM LI filter bug workaround.
            else { $lsws = [PsCustomObject]@{members = @(); total = 0; count = 0; category = "logical-interconnects"} }

        }
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Logical Interconnect name provided. Looking for all Logical Interconnect resources."
            $uri = $logicalInterconnectsUri

            $lsws = Send-HPOVRequest $uri

        }

        if ($lsws.count -eq 0 -and $name) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect Group '$name' resource not found. Generating error"
            $errorRecord = New-ErrorRecord InvalidOperationException LogicalInterconnectGroupNotFound ObjectNotFound 'Get-HPOVEnclosureGroup' -Message "Specified Logical Interconnect Group '$name' was not found.  Please check the name and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)  
            
        }
        elseif ($lsws.count -eq 0) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Logical Interconnect Group resources found."
            $members = $null

        }

        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found $($lsws.count) Logical Interconnect Group resource(s)."
            $members = $lsws.members 
 
        }
   
    }

    end {

        if($exportFile){ $members | convertto-json -Depth 99 | Set-Content -Path $exportFile -force -encoding UTF8 }

        elseif ($report) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating report."
    
            ForEach ($li in $members) {
                #Display Logical Interconnect information (Name, State, Status, Stacking Link Status, LIG Consistency Status)
                $a = @{Expression={$_.name};Label="Name";width=22}, `
		        @{Expression={$_.status};Label="Status";width=20},`
                @{Expression={ switch ($_.stackingHealth) {
        
                               'BiConnected' { "Redundantly Connected" }
                               'NOT_CONSISTENT' { "Inconsistent with group" }
                               default { $_.stackingHealth }
                               }};Label="Stacking health";width=30}, `
                @{Expression={ (send-hpovrequest $_.logicalInterconnectGroupUri).name };Label="LIG";width=20},`
                @{Expression={ switch ($_.consistencyStatus) {
        
                               'CONSISTENT' { "Consistent" }
                               'NOT_CONSISTENT' { "Inconsistent with group" }
                               default { $_.consistencyStatus }
                               }};Label="Consistency state";width=26}
    
                $li | sort-object -Property name | format-Table $a -AutoSize
    
                #Loop through interconnect bays
		        $interconnectsCol = @()
    
		        foreach ($interconnect in $li.interconnects){
			        Write-Verbose "INTERCONNECT:  $($interconnect)"
                    if ($interconnect){
    
                        #Get the Interconnect object to read properties
			            $tempInterconnect = Send-HPOVRequest $interconnect
                        $tempInterconnect | out-string | Write-Verbose
				        $interconnectsCol += $tempInterconnect
		            }
		        }
    
                #Display Interconnect information (Name, Model, Serial Number, FW Ver)
		        $a = @{Expression={'     '};Label="Interconnects"},
                @{Expression={$_.name};Label="Name"},
		        @{Expression={$_.model};Label="Module"},
		        @{Expression={$_.serialNumber};Label="Serial Number"},
		        @{Expression={$_.firmwareVersion};Label="Firmware Version"},
                @{Expression={$_.state};Label="State"}
    
                $interconnectsCol | sort-object -Property name | format-Table $a -AutoSize
    
                if ($members.count -gt 1 ) { Write-Host "==================================================================================================================" }
            }
        }
                
        else { $members }

        Write-Host "Done. $($lsws.count) logical interconnect group(s) found."        

    }

}

function Update-HPOVLogicalInterconnect {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "default", HelpMessage = "Specify the Logical Interconnect to Update.", Position = 0)]
        [parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "Reapply", HelpMessage = "Specify the Logical Interconnect to Update.", Position = 0)]
        [Alias('uri', 'li')]
        [object]$name = $null,

        [parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = "Reapply", HelpMessage = "Reapply the Logical Interconnect configuration. Does not update from parent Logical Interconnect Group.")]
        [switch]$Reapply
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        [array]$returnTask = @()
    }

    Process {

        #if (-not $name) { $name = 

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $($name.count) LI objects."
        foreach ($li in $name) {


            $liUri = $null;
            $liDisplayName = $null;
            
            #Name provided
            if (($li -is [String]) -and (-not $li.StartsWith($script:logicalInterconnectsUri))) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LI Name was provided `"$($li)`""
                $liTemp = Get-HPOVLogicalInterconnect $li
                if ($liTemp) { 
                    if (! $Reapply) { $parentLig = Send-HPOVRequest $liTemp.logicalInterconnectGroupUri }
                    $liUri = $liTemp.uri
                    $liDisplayName = $li
                }

            }
            elseif (($li -is [String]) -and ($li.StartsWith($script:logicalInterconnectsUri))) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LI URI was provided $($li)"
                $liTemp = Send-HPOVRequest $li
                if (! $Reapply) { $parentLig = Send-HPOVRequest $liTemp.logicalInterconnectGroupUri }
                if ($liTemp) { 
                    $liUri = $liTemp.uri
                    $liDisplayName = $i.Name
                }
            }
            elseif (($li -is [PSCustomObject]) -and ($li.category -ieq 'logical-interconnects')) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LI Object was provided $($li | out-string)"
                $liUri = $li.uri
                $liDisplayName = $li.name
                if (! $Reapply) { $parentLig = Send-HPOVRequest $li.logicalInterconnectGroupUri }
            }
            else {
                Write-Host "Invalid logical interconnect parameter: " + $li
                return
            }

            if ($liUri) {
                
                if ($Reapply) { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Reapply LI configuration requested."
                    
                    if ($pscmdlet.ShouldProcess($liDisplayName,"Reapply Logical Interconnect configuration. WARNING: Depending on this action, there might be an outage")){    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
                        $task = Send-HPOVRequest "$liUri/configuration" PUT
                        
                    }

                    else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User cancelled request or passed -WhatIf." }
                
                }
                else {
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Update '$($liDisplayName)' Logical Interconnect from parent $($parentLig.name)."
                    
                    if ($pscmdlet.ShouldProcess($liDisplayName,"Update Logical Interconnect from Group $($ligName). WARNING: Depending on the Update, there might be an outage")){    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
                        $task = Send-HPOVRequest "$liUri/compliance" PUT
                        
                    }

                    else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User cancelled request or passed -WhatIf." }
                }

                $returnTask += $task
            }

        }
    }

    end {

        return $returnTask
    }

}

function Show-HPOVLogicalInterconnectMacTable {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default")]
    Param (
        [parameter (Position = 0, Mandatory = $false, ValueFromPipeline = $True, ParameterSetName = "default")]
        [parameter (Position = 0, Mandatory = $false, ValueFromPipeline = $True, ParameterSetName = "MACAddress")]
        [alias("name","li")]
        [object]$LogicalInterconnect = $null,

        [parameter (Position = 1, Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "default")]
        [string]$network = $null,

        [parameter (Position = 1, Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "MACAddress")]
        [validatescript({if ($_ -match $script:macAddressPattern) {$true} else { throw "The input value '$_' does not match 'aa:bb:cc:dd:ee:ff'. Please correct the value and try again."}})]
        [alias("mac")]
        [string]$MacAddress = $null,

        [parameter (Position = 2, Mandatory = $false, ParameterSetName = "default")]
        [parameter (Position = 2, Mandatory = $false, ParameterSetName = "MACAddress")]
        [alias("x", "export")]
        [ValidateScript({split-path $_ | Test-Path})]
        [String]$exportFile,
       
        [parameter (Mandatory = $false, ParameterSetName = "default")]
        [parameter (Mandatory = $false, ParameterSetName = "MACAddress")]
        [Switch]$List
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord AuthSessionException NoAuthSession AuthenticationError 'Show-HPOVLogicalInterconnectMacTable' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            #$PSCmdlet.ThrowTerminatingError($errorRecord)
            Throw $errorRecord

        }

        if (-not $PSBoundParameters['LogicalInterconnect']) { $PipelineInput = $True }

        [PSCustomObject]$MacTables = @{count = 0; tables = @()}


    }


    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect via PipeLine: $PipelineInput"

        if (-not $LogicalInterconnect) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Logical Interconnects provided via parameter. Getting all LI resources."
            $LogicalInterconnect = Get-HPOVLogicalInterconnect

        }

        foreach ($li in $LogicalInterconnect) {

            if ($li -is [String] -and $li.StartsWith("/rest/logical-interconnects")) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect URI provided via parameter: $li"
                $uri = $li +"/forwarding-information-base"

            }
            elseif ($li -is [String]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect Name provided via parameter: $li"
                $uri = (Get-HPOVLogicalInterconnect $li).uri +"/forwarding-information-base"

            }
            elseif ($li -is [PSCustomObject] -and $li.category -eq "logical-interconnects") {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect object provided: $($li.name)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect object URI: $($li.uri)"
                $uri = $li.uri +"/forwarding-information-base"

            }
            else {

                #Unsupported type
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Show-HPOVLogicalInterconnectMacTable' -Message "The parameter -LogicalInterconnect contains an invalid parameter value type, '$($LogicalInterconnect.gettype().fullname)' is not supported.  Only [System.String] and [PSCustomObject] types are allowed." #-verbose
                $PSCmdlet.WriteError($errorRecord)

            }

            #Filter the request for a specific Network
            if ($Network) {
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering for '$Network' Network Resource"
                
                $internalVlanId = (Get-HPOVNetwork $network).internalVlanId
                $uri += "?filter=internalVlan=$internalVlanId"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $uri"
                $resp = Send-HPOVRequest $uri
            }
            elseif ($MacAddress) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering for MAC Address '$MacAddress'"
                $uri += "?filter=macAddress='$MacAddress'"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $uri"
                $resp = Send-HPOVRequest $uri
            }
            else {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating '$uri' mactable file."
                $macTableFile = Send-HPOVRequest $uri POST 

                if ($macTableFile.state -eq "Success") {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($macTableFile.uri)' mactable file."
                    $resp = Download-MacTable $macTableFile.uri
                
                }
                else {

                    $errorRecord = New-ErrorRecord HPOneView.NetworkResourceException InvalidInterconnectFibDataInfo InvalidResult 'Show-HPOVLogicalInterconnectMacTable' -Message ($macTableFile.state + ": " + $macTableFile.status)
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }

            }

            $MacTables.count += $resp.count
            if ($resp.members) { $MacTables.tables += $resp.members }
            else { $MacTables.tables += $resp }

        }

    }

    End {

        if ($list) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Displaying formatted table."
            if ($name -or $MacAddress) {
                $m = @{Expression={($_.interconnectName -split ",")[0]};Label="Enclosure"},
                     @{Expression={($_.interconnectName -split ",")[1]};Label="Interconnect"},		         
                     @{Expression={$_.networkInterface};Label="Interface"},
                     @{Expression={$_.macAddress};Label="Address"},
                     @{Expression={$_.entryType};Label="Type"},
                     @{Expression={$_.networkName};Label="Network"},
                     @{Expression={$_.externalVlan};Label="VLAN"}
            }
            else {

                $m = @{Expression={$_.Enclosure};Label="Enclosure"},
                     @{Expression={$_.Interconnect};Label="Interconnect"},
                     @{Expression={$_.Interface};Label="Interface"},
                     @{Expression={$_.address};Label="Address"},
                     @{Expression={$_.type};Label="Type"},
                     @{Expression={$_.network};Label="Network"},
                     @{Expression={$_.extVlan};Label="VLAN"},
                     @{Expression={$_.LAGPorts};Label="LAG Ports"}

            }

            $MacTables.tables | sort "Enclosure","Interconnect",macAddress | format-table $m -autosize

        }
        elseif ($exportFile) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Exporting to CSV file: $exportFile"
            $MacTables.tables | sort "Enclosure","Interconnect",macAddress | Export-CSV $exportFile -NoTypeInformation

        }
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Displaying results."
            $MacTables.tables | sort "Enclosure","Interconnect",macAddress

        }
        
        "Done. {0} mac table entry(ies) found." -f $MacTables.count | out-host

    }

}

function Download-MacTable {
    
    <#
        .SYNOPSIS
        Download Logical Interconnect MAC Table CSV.

        .DESCRIPTION
        This internal helper function will download the MAC Table CSV from a provided Logical Interconnect, parse it and return an array of MAC Table entries.

        .PARAMETER Uri
        [System.String] URI of Logical Interconnect.

        .INPUTS
        None.

        .OUTPUTS
        System.Array
        Array of MAC Table entries.

        .LINK
        Get-HPOVLogicalInterconnect

        .EXAMPLE
        PS C:\> $encl1li = Get-HPOVLogicalInterconnect Encl1-LI
        PS C:\> Download-MACTable $encl1li.uri

        Get the Logical Interconnect 'Encl1-LI' and 
            
    #>

    [CmdLetBinding()]
    Param (
        [parameter(Mandatory = $true, HelpMessage = "Specify the URI of the object to download.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({if ($_.startswith('/rest/logical-interconnects/')) { $true } else {throw "-URI must being with a '/rest/logical-interconnects/' in its value. Please correct the value and try again."}})]
        [string]$uri
    ) 

    Begin {

        $enc= [System.Text.Encoding]::UTF8

    }
 
    Process{	

        #if ($uri.StartsWith("https://")) {
        #    $downloadUri = $uri
        #}
        #else {
		#    $downloadUri = "https://" + $global:cimgmtSessionId.appliance + $uri
        #}
        #Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Download URI: $($downloadUri)"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Download URI: $($uri)"

	    [System.Net.httpWebRequest]$fileDownload = RestClient GET $uri
        #[System.Net.httpWebRequest]$fileDownload = [net.webRequest]::create($downloadUri)
	    #$fileDownload.Timeout = 10000
	    #$fileDownload.method = "GET"
	    $fileDownload.accept = "application/zip,application/octet-stream,*/*"
		#$fileDownload.Headers.Item("auth") = $global:cimgmtSessionId.sessionID
	    #$fileDownload.Headers.Item("accept-charset") = "ISO-8859-1,utf-8"
	    #$fileDownload.Headers.Item("accept-encoding") = "gzip,deflate,sdch"
	    #$fileDownload.Headers.Item("accept-language") = "en_US"
        #$fileDownload.AutomaticDecompression = "GZip,Deflate,None"

        $i=0
        foreach ($h in $fileDownload.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request Header $($i): $($h) = $($fileDownload.Headers[$i])"; $i++}
		    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Request: GET $($fileDownload.RequestUri.AbsolutePath | out-string)"
        
        #Get response
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting response"
        [Net.httpWebResponse]$rs = $fileDownload.GetResponse()

        #Display the response status if verbose output is requested
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Status: $([int]$rs.StatusCode) $($rs.StatusDescription)"
        $i=0
        foreach ($h in $rs.Headers) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Response Header $($i): $($h) = $($rs.Headers[$i])"; $i++ }

        #Request is a redirect to download file contained in the response headers
        $fileName = ($rs.headers["Content-Disposition"].Substring(21)) -replace "`"",""

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filename: $($fileName)"
	    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filesize:  $($rs.ContentLength)"
        $responseStream = $rs.GetResponseStream()

        #Define buffer and buffer size
		[int] $bufferSize = ($rs.ContentLength*1024)
	    [byte[]]$Buffer = New-Object byte[] ($rs.ContentLength*1024)
        [int] $bytesRead = 0

		#This is used to keep track of the file upload progress.
	    $totalBytesToRead = $rs.ContentLength
	    $numBytesRead = 0
		$numBytesWrote = 0

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Reading HttpWebRequest file stream."
	    #Read from stream
        $responseStream.Read($Buffer, 0, $bufferSize) | out-Null
        
        #Write to output stream
        $outStream = new-object System.IO.MemoryStream (,$Buffer)

	    #Clean up our work
	    $responseStream.Close()
	    $rs.Close()
	    
        $source = $outStream.ToArray()
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Decompressing HttpWebRequest file."
        $sr = New-Object System.IO.Compression.GZipStream($outStream,[System.IO.Compression.CompressionMode]::Decompress)
        
        #Reset variable to collect uncompressed result
        $byteArray = New-Object byte[]($source.Length*1024)
        
        #Decompress
        [int]$rByte = $sr.Read($byteArray, 0, $source.Length)

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Converting Byte array to String Characters."
        #Transform byte[] unzip data to string
        $sB = New-Object System.Text.StringBuilder($rByte)
        
        #Read the number of bytes GZipStream read and do not a for each bytes in resultByteArray
        for ([int] $i = 0; $i -lt $rByte; $i++) {
            $sB.Append([char]$byteArray[$i]) | Out-Null
        }
        
        $sr.Close()
        $sr.Dispose()

    }

    end {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Building string array in CSV format"
        $macTableArray = $sb.ToString() -split "`n"
        $header = "enclosure","interconnect","interface","address","type","network","extVLAN","intVLAN","serverProfile","uplinkSet","LAGPort1","LAGPort2","LAGPort3","LAGPort4","LAG Port5","LAG Port6","LAG Port7","LAG Port8"
        $macTableArray = $macTableArray[1..($macTableArray.count)]
        $e = @{Expression={
             
                 $lagport = $_
                 1..8 | % { if ($lagport."LAGPort$($_)") { $lagport."LAGPort$($_)" } } 
                           
             };name="LAGPorts"}
        $macTable = $macTableArray | ConvertFrom-Csv -Header $header | select "enclosure","interconnect","interface","address","type","network","extVLAN","intVLAN","serverProfile","uplinkSet",$e

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Returning results."
        $macTable

    }

}

function Install-HPOVLogicalInterconnectFirmware {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        
        [parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "default", HelpMessage = "Specify the Logical Interconnect to Update.", Position = 0)]
        [Alias('name','uri', 'li')]
        [object]$LogicalInterconnect = $null,

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "default", HelpMessage = "Specify the Logical Interconnect to Update.", Position = 1)]
        [ValidateSet('Update','Activate','Stage')]
        [string]$Method = "Update",

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "default", HelpMessage = "Specify the Logical Interconnect to Update.", Position = 1)]
        [ValidateSet('Odd','Even','All')]
        [Alias('Order')]
        [string]$ActivateOrder = "Odd",

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "default", HelpMessage = "Specify the Logical Interconnect to Update.", Position = 2)]
        [Alias('spp')]
        [object]$Baseline = $null,

        [parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "default", HelpMessage = "Specify the Logical Interconnect to Update.")]
        [switch]$Force

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Install-HPOVLogicalInterconnectFirmware' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #Validate Logical Interconnect Object Type
        if ($LogicalInterconnect -is [String] -and (! $LogicalInterconnect.StartsWith('/rest/logical-interconnect'))) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LogicalInterconnect name passed:  $($LogicalInterconnect)"
            $logicalInterconnect = Get-HPOVLogicalInterconnect -Name $LogicalInterconnect            
        
        }

        elseif ($LogicalInterconnect -is [String] -and $LogicalInterconnect.StartsWith('/rest/logical-interconnect')) {
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LogicalInterconnect URI passed:  $($LogicalInterconnect)"
            $logicalInterconnect = Send-HPOVRequest $LogicalInterconnect

        }


        elseif ($LogicalInterconnect -is [String]) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] invalid LogicalInterconnect passed:  $($LogicalInterconnect)"
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'INSTALL-HPOVLOGICALINTERCONNECTFIRMWARE' -Message "The 'LogicalInterconnect' parameter value '$($LogicalInterconnect)' is invalid.  Please check the parameter value and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        
        }

        else {

            if ($PSBoundParameters.ContainsKey("LogicalInterconnect")) {
            
    	        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LogicalInterconnect parameter data type: $($LogicalInterconnectObj.gettype() | out-string)"
                #Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Pipeline object $($LogicalInterconnectObj)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($logicalInterconnect.count)' Logical Interconnects."

            }

            else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LogicalInterconnect parameter passed via pipeline?" }
        
        }

        if ($Baseline -is [String] -and (! $Baseline.StartsWith('/rest/firmware-drivers'))) { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Firmware Baseline name passed:  $($Baseline)"
            $baselineObj = Get-HPOVSppFile -Name $Baseline
        
        }

        elseif ($Baseline -is [String] -and ($Baseline.StartsWith('/rest/firmware-drivers'))) {
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Firmware Baseline URI passed:  $($Baseline)"
            $baselineObj = Send-HPOVRequest $Baseline
        
        }

        $taskResults = @()
        $i = 1
        
    }

    Process {

        $Staging = $False
        $activating = $False

        ForEach ($li in $logicalInterconnect) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing '$($li.name)' Logical Interconnect."

            switch ($Method) {

                "Update" { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] 'Update' Method called."        
                    $request = [PsCustomObject]@{ command = "UPDATE"; sppUri = $baselineObj.uri; force = [bool]$Force }
                
                }

                "Stage" {
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] 'Stage' Method called."
                    $request = [PsCustomObject]@{ command = "UPDATE"; sppUri = $baselineObj.uri; force = [bool]$Force }
                
                }

                "Activate" {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] 'Activate' Method called."
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verifying '$($li.name)' LI is in a Staged state."
                    $firmwareStatus = Send-HPOVRequest ($li.uri + "/firmware")

                    #Validate interconnect firmware update state
                    switch ($firmwareStatus.state) {


                        #ACTIVATED    ACTIVATING    ACTIVATION_FAILED    PARTIALLY_ACTIVATED    PARTIALLY_STAGED    STAGED    STAGING    STAGING_FAILED    so,     UNKNOWN

                     
                        'STAGED' { 
                        
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($li.name)' LI is in the proper '$($firmwareStatus.state)' state."

                            $baselineObj = [pscustomobject] @{ uri = $firmwareStatus.sppUri }

                        }
                        
                        'STAGING' { 
                        
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($li.name)' is currently being staged with firmware. Please wait until the task completes."
                            
                            #Locate and return running task.
                            $task = Get-HPOVTask -State Running -resource $li.name

                            if ($task.count -eq 1) { $taskResults += $task }
                            else { $taskResults += $task | ? { $_.taskStatus.StartsWith('Staging') } }
                            
                            # Flag to skip the command processing IF block below
                            $Staging = $true
                            
                        }

                        'STAGING_FAILED' { 
                        
                            $errorRecord = New-ErrorRecord InvalidOperationException InvalidLogicalInterconnectState InvalidResult 'INSTALL-HPOVLOGICALINTERCONNECTFIRMWARE' -Message "The $($li.name) Logical Interconnect is in an invalid state ($($firmwareStatus.state))in order to issue the Activate command." #-verbose
                            $PSCmdlet.ThrowTerminatingError($errorRecord)
                        
                        }

                        'ACTIVATED' { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($li.name)' is already activated."; Return }

                        'ACTIVATING' {
                            
                            #Logical Interconnect is already processing the Activate command.
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($li.name)' is already activating. Returning task resource."

                            # Flag to skip the command processing IF block below
                            $activating = $True
                            
                            #Locate and return running task.
                            $task = Get-HPOVTask -State Running -resource $li.name

                            if ($task.count -eq 1) { $taskResults += $task }
                            else { $taskResults += $task | ? { $_.taskStatus.StartsWith('Activating') } }

                        }

                        'ACTIVATION_FAILED' { 
                        
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($li.name)' failed a prior activation request.  LI is in a valid state to attempt Activation command."
                            $baselineObj = [pscustomobject] @{ uri = $firmwareStatus.sppUri }
                            
                        }

                        'PARTIALLY_ACTIVATED' { 
                        
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($li.name)' is Partially Activated.  LI is in a valid state to attempt Activation command."
                            $baselineObj = [pscustomobject] @{ uri = $firmwareStatus.sppUri }
                        
                        }

                        'PARTIALLY_STAGED' {
                        
                            $errorRecord = New-ErrorRecord InvalidOperationException InvalidLogicalInterconnectState InvalidResult 'Install-HPOVLogicalInterconnectFirmware' -Message "The $($li.name) Logical Interconnect is in an invalid state ($($firmwareStatus.state))in order to issue the Activate command." #-verbose
                            $PSCmdlet.ThrowTerminatingError($errorRecord)
                        
                        }

                        'UNINITIALIZED' { 
                        
                            <# Generate Error that firmware has not been staged #> 
                            $errorRecord = New-ErrorRecord InvalidOperationException NoStagedFirmwareFound ObjectNotFound  'INSTALL-HPOVLOGICALINTERCONNECTFIRMWARE' -Message "No staged firmware found for '$($li.name)' Logical Interconnect.  Use Install-HPOVLogicalInterconnectFirmware -method Stage to first stage the firmware before attempting to Activate." #-verbose
                            $PSCmdlet.ThrowTerminatingError($errorRecord)
                            
                        }

                    }

                    $interconnectOrderUris = @()

                    #Handle Interconnect Activation order
                    switch ($ActivateOrder) {

                        'Odd' {
                        

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for Odd bay Interconnects."
                            ForEach ($interconnect in $li.interconnectMap.interconnectMapEntries) { 
                            
                                #"found interconnect: " + $interconnect
                                
                                $found = $interconnect.location.locationEntries | ? { $_.type -eq "Bay" -and $_.Value % 2 -eq 1 -and $interconnect.interconnectUri }
                                
                                if($found) {
                                                                
                                    $interconnectOrderUris += $interconnect.interconnectUri
                            
                                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found Odd Interconnect located in Bay $($found.value)"
                            
                                }
                            
                            }

                        }

                        'Even' {
                        
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for Even bay Interconnects."
                            ForEach ($interconnect in $li.interconnectMap.interconnectMapEntries) { 
                            
                              
                                $found = $interconnect.location.locationEntries | ? { $_.type -eq "Bay" -and $_.Value % 2 -eq 0 -and $interconnect.interconnectUri }
                                
                                if($found) {
                                                                
                                    $interconnectOrderUris += $interconnect.interconnectUri
                            
                                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found Even Interconnect located in Bay $($found.value)"
                            
                                }
                            
                            }
                                                    
                        }

                        'All' { $interconnectOrderUris = $li.interconnects }

                    }

                    if (! $activating -and ! $Staging) { $request = [PsCustomObject]@{ command = "ACTIVATE"; sppUri = $baselineObj.uri; interconnects = $interconnectOrderUris } }
                
                }

            }

            #Need to prompt user to update or activate firmware, which could cause an outage.
            if (($Method -eq "Update" -or $Method -eq "Activate") -and ! $activating -and ! $Staging) {

                if ($pscmdlet.ShouldProcess($li.name,'Module activation will cause a network outage. Continue with upgrade?')) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User was prompted warning and accepted. Sending request."

                    $taskResults += (Send-HPOVRequest -method PUT -uri ($li.uri + "/firmware") -body $request)

                }

                else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User was prompted and selected No, cancelling the update for $($li.name)" }

            }

            #User is staging firmware, no need to prompt.
            elseif (! $activating -and ! $Staging) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Beginning to stage firmware to '$($li.name)'."
                
                $taskResults += (Send-HPOVRequest -method PUT -uri ($li.uri + "/firmware") -body $request)

            }

            $i++
        }

    }

    end {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Finished, returning results."
        return $taskResults

    }


}

function Get-HPOVLogicalInterconnectGroup {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
       [parameter (Position = 0, Mandatory = $false)]
       [String]$name = $null,

       [parameter (Mandatory = $false)]
       [alias("x", "export")]
       [ValidateScript({split-path $_ | Test-Path})]
       [String]$exportFile
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        if ($name) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect Group name provided: '$name'"

            $uri = $logicalInterconnectGroupsUri + "?filter=name='$name'"
        }
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Logical Interconnect Group name provided. Looking for all Logical Interconnect Group resources."
            $uri = $logicalInterconnectGroupsUri

        }

        $ligs = Send-HPOVRequest $uri

        if ($ligs.count -eq 0 -and $name) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect Group '$name' resource not found. Generating error"
            $errorRecord = New-ErrorRecord InvalidOperationException LogicalInterconnectGroupNotFound ObjectNotFound 'Get-HPOVEnclosureGroup' -Message "Specified Logical Interconnect Group '$name' was not found.  Please check the name and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)  
            
        }
        elseif ($ligs.count -eq 0) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Logical Interconnect Group resources found."
            $members = $null

        }

        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found $($ligs.count) Logical Interconnect Group resource(s)."
            $members = $ligs.members 
 
        }
   
    }

    end {

        if($exportFile){ $members | convertto-json -Depth 99 | Set-Content -Path $exportFile -force -encoding UTF8 }
                
        else { $members }

        Write-Host "Done. $($ligs.count) logical interconnect group(s) found."        

    }

}

function New-HPOVLogicalInterconnectGroup {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $True, ParameterSetName = "Default",HelpMessage = "Please specify the Logical Interconnect Name", Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ligname')]
        [String]$Name,
        
        [Parameter(Mandatory = $True,ValueFromPipeline = $true, ParameterSetName = "Default",HelpMessage = "Please specify the Interconnect Modules in Hashtable format for all Interconnect Bays", Position = 1)]
        [Hashtable]$Bays,

        [Parameter(Mandatory = $False, ParameterSetName = "Default",HelpMessage = "Enable IGMP Snooping", Position = 2)]
		[Alias("IGMPSnoop")]
        [bool]$enableIgmpSnooping = $False,
		
		[Parameter(Mandatory = $False, ParameterSetName = "Default",HelpMessage = "IGMP Idle Timeout Interval (1-3600 [sec])", Position = 3)]
        [ValidateRange(1,3600)]
		[Alias('IGMPIdle')]
	    [int]$igmpIdleTimeoutInterval = 260,
		
		[Parameter(Mandatory = $False, ParameterSetName = "Default",HelpMessage = "Enable Fast MAC Cache Failover", Position = 4)]
		[Alias('FastMAC')]
	    [bool]$enableFastMacCacheFailover = $True,
		
		[Parameter(Mandatory = $False, ParameterSetName = "Default",HelpMessage = "Fast MAC Cache Failover Interval (1-30 [sec])", Position = 5)]
        [ValidateRange(1,30)]
		[Alias('FastMACRefresh')]
    	[int]$macRefreshInterval = 5,
		
		[Parameter(Mandatory = $False, ParameterSetName = "Default",HelpMessage = "Enable Network Loop Protection on the Downlink Ports)", Position = 6)]
		[Alias('LoopProtect')]
	    [bool]$enableNetworkLoopProtection = $True,

		[Parameter(Mandatory = $False, ParameterSetName = "Default",HelpMessage = "Enable Network Pause Flood Protection on the Downlink Ports)", Position = 7)]
		[Alias('PauseProtect')]
	    [bool]$enablePauseFloodProtection = $True,
		
		[Parameter(Mandatory = $False, ParameterSetName = "Default",HelpMessage = "Enable SNMP Settings", Position = 8)]
	    [hashtable]$SNMP = $null,

        [Parameter(Mandatory = $True, ParameterSetName = "Import",HelpMessage = "Specify JSON source file to great Logical Interconnect Group")]
        [ValidateScript({split-path $_ | Test-Path})]
        [Alias('i')]
	    [object]$Import

    )

    Begin {
        
        #Check to make sure the user is authenticated
        If (!$global:cimgmtSessionId){
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

	    }
    }
	
	Process{

        If ($Import){
            
            write-verbose "Reading input file"

            try {

                #Open input file, join so we can vlidate if the JSON format is correct.
                $lig = [string]::Join("", (gc $import -ErrorAction Stop)) | convertfrom-json -ErrorAction Stop
                $lig | write-debug

                Write-Verbose "Sending request"
                $task = Send-HPOVRequest $logicalInterconnectGroupsUri POST $lig

            }
            
            #If there was a problem with the input file (format, not syntax) throw error
            catch [System.ArgumentException] {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'New-HPOVLogicalInterconnectGroup' -Message "JSON Input File is invalid.  Please check the contents and try again." #-verbose
                $PSCmdLet.ThrowTerminatingError($errorRecord)
            }

        }

        Else {

		    $lig = @{
                name                    =$Name;
	            state                   = "Active";
	            status                  = $null; 
	            uplinkSets              = @(); 
	            interconnectMapTemplate = @{interconnectMapEntryTemplates = @()};
	            ethernetSettings = @{
                    type                        = "EthernetInterconnectSettingsV2";
                    enableIgmpSnooping          = $enableIgmpSnooping;
                    igmpIdleTimeoutInterval     = $igmpIdleTimeoutInterval; 
                    enableFastMacCacheFailover  = $enableFastMacCacheFailover;
                    macRefreshInterval          = $macRefreshInterval;
                    enableNetworkLoopProtection = $enableNetworkLoopProtection;
                    enablePauseFloodProtection  = $enablePauseFloodProtection;
                };
			    snmpConfiguration       = $snmp;
	            stackingMode            = "Enclosure";
	            type                    = "logical-interconnect-groupV2"
	        }
        
            #Make sure the snmpConfiguration type property is set, as the caller might not know about this.
            if ($lig.snmpConfiguration) { $lig.snmpConfiguration.type = "snmp-configuration" }
		
		    #Fill in missing bay locations from the input value if needed.
		    $Secondary = @{ 1 = $null; 2 = $null; 3 = $null; 4 = $null; 5 = $null; 6 = $null; 7 = $null; 8 = $null }

		    #check for any duplicate keys
		    $duplicates = $Bays.keys | where { $Secondary.ContainsKey($_) }
		    if ($duplicates) {
		        foreach ($item in $duplicates) {
		                $Secondary.Remove($item)
		        }
		    }

		    #join the two hash tables
		    $NewBays = $Bays+$Secondary 
		    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Bay configuration: $($NewBays | Sort-Object Key -Descending | Out-String)"
 		
		    #Loop through hashtable
		    $NewBays = $NewBays.GetEnumerator() | Sort-Object Key -Descending
            foreach ($bay in $NewBays){
            
		   	    switch ($bay.value) {
			        "FlexFabric" {            
			            #Get VC FlexFabric interconnect-type URI
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found VC FF in bay $($bay.name | out-string)"
			            $ret = Get-HPOVInterconnectType -partNumber "571956-B21"
			        }
			        "Flex10" {
			            #Get VC Flex-10 interconnect-type URI
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found VC F10 in bay $($bay.name | out-string)"
			            $ret = Get-HPOVInterconnectType -partNumber "455880-B21"
			        }
			        "Flex1010D" {
			            #Get VC Flex-10/10D interconnect-type URI
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found VC F1010D in bay $($bay.name | out-string)"
			            $ret = Get-HPOVInterconnectType -partNumber "638526-B21"
			        }
			        "Flex2040f8" {
			            #Get VC Flex-10/10D interconnect-type URI
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found VC Flex2040f8 in bay $($bay.name | out-string)"
			            $ret = Get-HPOVInterconnectType -partNumber "691367-B21"
			        }
			        "VCFC20" {
			            #Get VC Flex-10/10D interconnect-type URI
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found VC FC 20-port in bay $($bay.name | out-string)"
			            $ret = Get-HPOVInterconnectType -partNumber "572018-B21"
			        }
			        "VCFC24" {
			            #Get VC Flex-10/10D interconnect-type URI
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found VC FC 24-port in bay $($bay.name | out-string)"
			            $ret = Get-HPOVInterconnectType -partNumber "466482-B21"
			        }
			        "FEX" {
			            #Get Cisco Fabric Extender for HP BladeSystem interconnect-type URI
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found Cisco Fabric Extender for HP BladeSystem in bay $($bay.name | out-string)"
			            $ret = Get-HPOVInterconnectType -partNumber "641146-B21"
			        }
				    default {
					    $ret = $null
				    }
				
                }
			
			    $lig.interconnectMapTemplate.interconnectMapEntryTemplates += @{
			    	    logicalDownlinkUri = $null;
	            	    permittedInterconnectTypeUri = $ret.uri;
					    logicalLocation = @{locationEntries = @(@{relativeValue = $bay.name; type = "Bay"}, @{relativeValue = "1"; type = "Enclosure"})}}
		    }

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG: $($lig | out-string)"

	        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to create $Name..."
		
            $task = Send-HPOVRequest $script:logicalInterconnectGroupsUri POST $lig

        }
	}

    End {

        $task

    }
}

function Remove-HPOVLogicalInterconnectGroup {
    
    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [parameter(Mandatory = $true, Position=0, ValueFromPipeline = $true,ParameterSetName = "default", HelpMessage = "Specify the Logical Interconnect Group(s) to remove.")]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        $lig=$null,

	    [parameter(Mandatory = $false)] 
        [switch]$force=$false
    )

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Remove-HPOVLogicalInterconnectGroup' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $($lig.count) objects."

        foreach ($li in $lig) {

            $ligNameOrUri = $null;
            $ligDisplayName = $null;
            if ($li -is [String]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] lig parameter type is String."
                $ligNameOrUri = $li
                $ligDisplayName = $li
            }
            elseif ($li -is [PSCustomObject] -and $li.category -ieq 'logical-interconnect-groups') {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] lig parameter type is PsCustomObject and correct resource Category type."
                $ligNameOrUri = $li.uri;
                $ligDisplayName = $li.name;
            }
            else {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] lig parameter type is invalid or correct resource Category type is wrong."
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVLogicalInterconnectGroup' -Message "The lig parameter '$lig' is invalid.  Check the parameter value and try again." #-verbose

                #If more than 1 object is being processed, generate non-terminating error.
                if ($lig.count -gt 1) { $pscmdlet.WriteError($errorRecord) }

                #If only a single object, generate terminating error.
                else { $pscmdlet.ThrowTerminatingError($errorRecord) }

            }

            if (!$ligNameOrUri) {
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVLogicalInterconnectGroup' -Message "The lig parameter '$lig' is invalid.  Check the parameter value and try again." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)
            }
            elseif ($pscmdlet.ShouldProcess($ligDisplayName,'Remove logical interconnect group from appliance?')){   
            
                if ([bool]$force) { Remove-HPOVResource -nameOrUri $ligNameOrUri -force }
                else { Remove-HPOVResource -nameOrUri $ligNameOrUri }
            }
        }
    }
}

function Get-HPOVUplinkSet {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "Name")]

    Param (

        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Name")]
        [string]$name = $null,

        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = "Name")]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = "Type")]
        [string]$liName = $null,

        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = "Type")]
        [ValidateSet('Ethernet','FibreChannel', IgnoreCase=$False)]
        [string]$type = $null,
	
		[Parameter(Mandatory = $false)]
		[switch]$report
    )
	
	Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVUplinkSet' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }
	
	Process {

        if ($liName) {

            try { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Logical Interconnect '$liName'"
                $liObject = Get-HPOVLogicalInterconnect $liName

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for associated Uplink Sets to Logical Interconnects via Index."
                $associatedUplinksets = (Send-HPOVRequest "/rest/index/associations?parentUri=$($liObject.uri)&name=LOGICAL_SWITCH_TO_LOGICAL_UPLINK").members | % { Send-HPOVRequest $_.childUri }

                if ($name) { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering Uplink Sets for '$name'"
                    $uplinkSets = $associatedUplinksets | ? { $_.name -eq $name }

                }
                elseif ($type) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering Uplink Sets for '$type' type." 
                    $uplinkSets = $associatedUplinksets | ? { $_.networkType -eq $type }

                }
                else  {

                    $uplinkSets = $associatedUplinksets

                }
            }
            catch {

                if ($_.FullyQualifiedErrorId -match "LogicalInterconnectGroupNotFound") {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Logical Interconnect '$name' resource not found. Generating error"
                    $errorRecord = New-ErrorRecord InvalidOperationException LogicalInterconnectNotFound ObjectNotFound 'Get-HPOVUplinkSet' -Message $_.Exception
                    $pscmdlet.ThrowTerminatingError($errorRecord) 

                }
                else {

                    $errorRecord = New-ErrorRecord InvalidOperationException ($_.FullyQualifiedErrorId -split ",")[0] InvalidResult 'Get-HPOVUplinkSet' -Message $_.Exception
                    $pscmdlet.ThrowTerminatingError($errorRecord)

                }

            }

        }
        else {

            if ($name) { 
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Uplink Set name provided: $name"
                    #$uSs = $uSs.members | Where-Object { $_.name -eq $name } 
                    $uri = $script:indexUri + "?userQuery='$name'&category=uplink-sets&sort=name:asc"
                
            }
            elseif ($type) { 
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Uplink Set type provided: $type"
                    #$uSs = $uSs.members | Where-Object { $_.networkType -eq $type } 
                    $uri = $script:indexUri + "?userQuery='networkType EQ $type'&category=uplink-sets&sort=name:asc"
                
            }
            else { $uri = $uplinkSetsUri }
        
            if ($uri.startswith('/rest/index')) {
            
                #Perform an index search
                $indexSearch = Send-HPOVRequest $uri

                if ($indexSearch.count -eq 0 -and (-not $name -and -not $type)) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Uplink Set resources found."
                    Return $Null

                }
                elseif ($indexSearch.count -eq 0 -and $name) {

                    #No Uplink Sets with $name were found. Generate error
                    $errorRecord = New-ErrorRecord InvalidOperationException UplinkSetResourceNameNotFound ObjectNotFound 'Get-HPOVUplinkSet' -Message "No Uplink Set resources with Name '$name' were found. Please check the name parameter value and try again." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }
                elseif ($indexSearch.count -eq 0 -and $type) {

                    #No Uplink Sets with $name were found. Generate error
                    $errorRecord = New-ErrorRecord InvalidOperationException UplinkSetResourceTypeNotFound ObjectNotFound 'Get-HPOVUplinkSet' -Message "No Uplink Set resources with Type '$type' were found. Please check the type parameter value and try again." #-verbose
                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }
                
                #Should have found valid Uplink Set resources via index, now get Uplink Set resources
                [Array]$uplinkSets = $indexSearch.members | % { Send-HPOVRequest $_.uri }

            }
            else {

                #retrieve all Uplink Set resources
                [Array]$uplinkSets = (Send-HPOVRequest $uri).members
                
                if ($uplinkSets.count -eq 0) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No Uplink Set resources found."
                    Return $Null

                }

            }

        }

    }

    end {

		if ($report) {

           [Array]$uplinkSetReport = @()

		    foreach($us in ($uplinkSets | sort-object -Property name)) {

                $uplinkSet = [PsCustomObject]@{ name = $Null; liName = $Null; type = $Null; reachability = $Null; state = $Null; networks = @(); ports = @() }

                $uplinkSet.name = $us.name
                $uplinkSet.liName = (Send-HPOVRequest $us.logicalInterconnectUri).name
                $uplinkSet.reachability = $us.reachability
                $uplinkSet.state = "$($us.status)($($us.state))"

                if ($us.type -eq "Ethernet") { $uplinkSet | Add-Member -NotePropertyName ethernetNetworkType -NotePropertyValue $us.ethernetNetworkType }

		    	if ($us.networkType -eq "Ethernet"){

                    $uplinkSet.type = $us.ethernetNetworkType
		    	
                    #$ethNetwork = [PsCustomObject]@{ name = $Null }			
		    		
		    		foreach ($net in $us.networkUris){
		    		
                        $ethNetwork = [PsCustomObject]@{ name = $Null }	
                        	
                        $network = Send-HPOVRequest $net
	                    
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found Ethernet Network name: $($network.name)"
		    			
                        #Compare if the net URI is the same as the native URI
		    			if ($network.uri -eq $us.nativeNetworkUri){ 
                            
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Ethernet Network $($net.name) is the Native/PVID for uplink set."
                            $ethNetwork.name = "$($network.name) [NATIVE]"
                            
                        }
		    			else { $ethNetwork.name = $network.name }

                        if ($network.vlanID) { $ethNetwork | Add-Member -NotePropertyName vlanId -NotePropertyValue $network.vlanId -force }

                        $uplinkSet.networks += $ethNetwork
		    		}

		    	}
		    	elseif ($us.networkType -eq "FibreChannel") {

                    $uplinkSet.type = $us.networkType

		    		foreach ($net in $us.fcNetworkUris){
		    		    
                        $fcNetwork = [PsCustomObject]@{ name = $Null; fabricType = $Null }				
		    			
                        #Send the request
		    			$fcNet = Send-HPOVRequest $net

	                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found FC Network name: $($fcNet.name)"
                        $fcNetwork.name = $fcNet.name
                        $fcNetwork.fabricType = $fcNet.fabricType
		    			$uplinkSet.networks += $fcNetwork

		    		}
		    	}
	                   
	            #Get Uplink Port Assignment.
		    	foreach ($p in $us.portConfigInfos){

                    $tempPort = $Null                    
                    
                    $port = [PsCustomObject]@{ name = $Null; speed = $Null; opSpeed = $Null; status = $Null; neighbor = $Null }
                    
                    $tempPort = Send-HPOVRequest $p.portUri
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Retrieved port info for '$($tempPort.interconnectName), $($tempPort.portName)'"

                    $port.name = "$($tempPort.interconnectName), $($tempPort.portName)"
                    $port.speed = $p.desiredSpeed
                    $port.opSpeed = $script:getUplinkSetPortSpeeds["$($tempPort.operationalSpeed)"]
                    $port.status = "$($tempPort.portStatus)/$($tempPort.status)"

                    if ($us.networkType -eq "Ethernet") { 
                    
                        $port.neighbor = "$($tempPort.neighbor.remoteSystemName) [$(if (-not $tempPort.neighbor.remoteMgmtAddress) { $tempPort.neighbor.remoteChassisId } else {$tempPort.neighbor.remoteMgmtAddress})] $($tempPort.neighbor.remotePortDescription) $($tempPort.neighbor.remotePortId)"
                        if ($tempPort.lagId) { $port | add-member -NotePropertyName lagid -NotePropertyValue $tempPort.lagId }
                        else { $port | add-member -NotePropertyName lagid -NotePropertyValue "N/A" }
                    
                    }
                    elseif ($us.networkType -eq "FibreChannel") { 
                        $port.neighbor = $tempPort.fcPortProperties.wwpn 
                        $port | add-member -NotePropertyName fabric -NotePropertyValue $tempPort.fcPortProperties.opOnlineReason
                    }

                    $uplinkSet.ports += $port

		    	}

                $u = @{Expression={$_.name};Label="Uplink Set Name"},
                     @{Expression={$_.liName};Label="LI Name"},
                     @{Expression={$_.type};Label="Type"},
                     @{Expression={$_.reachability};Label="Reachability"},
                     @{Expression={$_.state};Label="State"}

                $uplinkSet | format-table $u -AutoSize -Wrap

                if ($us.networkType -eq "Ethernet") { 
                
                    $n = @{Expression={$_.name};Label="Network Name"},
                         @{Expression={$_.vlanId};Label="VLAN ID"}

                }
                else { $n = @{Expression={$_.name};Label="Network Name"},
                         @{Expression={$_.fabricType};Label="Type"}
                }

                $uplinkSet.networks | sort-object -Property name | format-table $n -AutoSize -Wrap

                if ($us.networkType -eq "Ethernet") { 
                
                    $p = @{Expression={$_.name};Label="Port Name"},
                         @{Expression={$_.speed};Label="Configured Speed"},
                         @{Expression={$_.opSpeed};Label="Connected Speed"},
                         @{Expression={$_.status};Label="Status"},
                         @{Expression={$_.lagid};Label="LAG ID"},
                         @{Expression={$_.neighbor};Label="(LLDP) Connected To"}

                }
                else {

                    $p = @{Expression={$_.name};Label="Port Name"},
                         @{Expression={$_.speed};Label="Configured Speed"},
                         @{Expression={$_.opSpeed};Label="Connected Speed"},
                         @{Expression={$_.status};Label="Status"},
                         @{Expression={$_.fabric};Label="Fabric Connection"},
                         @{Expression={$_.neighbor};Label="WWPN Connected To"}
                
                }

                $uplinkSet.ports | sort-object -Property name | format-table $p -AutoSize -Wrap
                write-host "------------------------------------------------------------------------------------------------------------------"
		    }
            Write-Host "=================================================================================================================="
            write-host
            write-host "Done. $($uplinkSets.count) uplink set(s) found."

		}
		else {
            
            $uplinkSets | sort-object -Property name
            
            write-host
            write-host "Done. $($uplinkSets.count) uplink set(s) found."
		    
		}

    }

}

function New-HPOVUplinkSet {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
        [parameter(Mandatory = $true, ValueFromPipeline = $True, Position = 0)]
        [alias('ligName')]
        [object]$lig,

        [parameter(Mandatory = $true)]
        [alias('usName')]
        [string]$Name,

        [parameter(Mandatory = $true)]
        [alias('usType')]
        [ValidateSet("Ethernet", "FibreChannel","Untagged","Tunnel", IgnoreCase=$false)]
        [string]$Type=$Null,

        [parameter(Mandatory = $false)]
        [alias('usNetworks')]
        [array]$Networks=@(),

        [parameter(Mandatory = $false)]
        [Alias ('usNativeEthNetwork','Native','PVID')]
        [string]$nativeEthNetwork=$Null,

        [parameter(Mandatory = $false)]
        [Alias ('usUplinkPorts')]
        [ValidateScript({($_.Split(","))[0].contains(":")})]
        [array]$UplinkPorts=@(),

        [parameter(Mandatory = $false)]
        [alias('usEthMode')]
        [ValidateSet("Auto", "Failover", IgnoreCase=$false)]
        [string]$EthMode="Auto",
        
        [parameter(Mandatory = $false)]
        [ValidateSet("Short", "Long", IgnoreCase=$false)]
        [string]$lacpTimer = "Long",

        [parameter(Mandatory = $false)]
        [ValidateSet("Auto", "2", "4", "8", IgnoreCase=$false)]
        [string]$fcUplinkSpeed = "Auto"

    )


	Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'New-HPOVUplinkSet' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }
	
	Process {

        #Init Uplink Set Objects
        $ethUplinkSetObject = [PSCustomObject]@{

            logicalPortConfigInfos = @();
            networkUris            = @();
            name                   = $Name; 
            mode                   = $EthMode; 
            networkType            = "Ethernet"; 
            ethernetNetworkType    = $Null; 
            lacpTimer              = $lacpTimer

        }

        $fcUplinkSetObject = [PSCustomObject]@{

            logicalPortConfigInfos = @(); 
            networkUris            = @();
            name                   = $Name; 
            mode                   = "Auto"; 
            networkType            = $Type

        }

        #Check the LIG type, and handle accordingly
        switch ($lig.gettype().Name) {

            "String" {
            
                if ($lig.startswith("/rest/logical-interconnect-groups")) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG Resource URI provided: $($lig)"
                    $ligObject = Send-HPOVRequest $lig

                }

                else {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] LIG Resource URI provided: $($lig)"
                    $ligObject = Get-HPOVLogicalInterconnectGroup $ligName

                }
                
                #If LIG is not found, throw error
                if (-not $ligObject) { 
                    
                    $errorRecord = New-ErrorRecord ArgumentException InvalidParameter InvalidArgument 'New-HPOVUplinkSet' -Message "The -lig parameter value provided ($lig) is invalid.  Please check the value and try again." #-verbose
                    $pscmdlet.ThrowTerminatingError($errorRecord)
                }

            
            }
            "PSCustomObject" { 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Provided LIG Resource Name: $($lig.name)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Provided LIG Resource Category: $($lig.category)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Provided LIG Resource URI: $($lig.uri)"
            
                if ($lig.category -ne "logical-interconnect-groups" ) {

                    $errorRecord = New-ErrorRecord ArgumentException InvalidParameter InvalidArgument 'New-HPOVUplinkSet' -Message "The -lig parameter value provided is not the correct resource category type.  Category provided '$($lig.category)'.  Expected category 'logical-interconnect-groups'.  Please check the value and try again." #-verbose
                    $pscmdlet.ThrowTerminatingError($errorRecord)

                }

                $ligObject = $lig
            
            }

            default {

                $errorRecord = New-ErrorRecord ArgumentException InvalidParameter InvalidArgument 'New-HPOVUplinkSet' -Message "The -lig parameter value provided ($lig) is invalid.  Please check the value and try again." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)

            }

        }

        #Get list of interconnects in LIG definition
        $ligInterconnects = $ligObject.interconnectmaptemplate.interconnectmapentrytemplates

        #Get list of all supported 
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting supported Interconnect Types from appliance."
        $supportedInterconnects = (Send-HPOVRequest "/rest/interconnect-types").members
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Uplink Ports: $($UplinkPorts | out-string)"
        $UplinkPorts = $UplinkPorts.Split(',')

        #Loop through requested Uplink Ports
        $port = @()
        $uslogicalLocation = @()

        foreach ($port in $UplinkPorts){

            $rem="bayBAY"
            $port = $port.Split(':')
            $bay = $port[0].TrimStart($rem)
            $uplinkPort = $port[1]
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing Port Bay$($bay):$($uplinkPort)"

            #Retrieve the interconnect type based on the bay number that was passed in in the ports parameter

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for Interconnect URI for Bay $($bay)"
            ForEach ($l in $ligInterconnects) { 

                $found = $l.logicalLocation.locationEntries | ? {$_.type -eq "Bay" -and $_.relativeValue -eq $bay}
                    
                if($found) {
                        
                    $permittedIcUri = $l.permittedInterconnectTypeUri

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found permitted Interconnect Type URI $($permittedIcUri) for Bay $($bay)"

                }

            } 

            $ic = $supportedInterconnects | ? {$_.uri -eq $permittedIcUri}

            #Translate the port number
            $portRelativeValue = $ic.portInfos | ? {$_.portName -eq $uplinkPort} | % {$_.portNumber}

            #Didn't find relative port number, so generate terminating error
            if (-not $portRelativeValue) {

                $errorRecord = New-ErrorRecord HPOneView.UplinkSetResourceException InvalidUplinkPortID InvalidArgument 'New-HPOVUplinkSet' -Message "The provided uplink port 'BAY$($bay):$($uplinkPort)' is an invalid port ID.  Did you mean 'X$($uplinkPort)'?  Please check the value and try again." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)

            }

            #Add uplink ports
            $logicalLocation = [PSCustomObject]@{
                    
                logicalLocation = @{
                        
                    locationEntries = @{
                            
                        type          = "Enclosure";
                        relativeValue = 1
                    },
                    @{
                        type          = "Bay";
                        relativeValue = [int]$bay
                    },
                    @{
                        type          = "Port";
                        relativeValue = [int]$portRelativeValue
                    }
                };
                desiredSpeed          = $null
            }
                
            #Set FC Uplink Port Speed
            if ($Type -eq "FibreChannel") { $logicalLocation.desiredSpeed = $script:SetUplinkSetPortSpeeds[$fcUplinkSpeed] }
            else { $logicalLocation.desiredSpeed = "Auto" }

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Adding Uplink Set to LIG: $($logicalLocation | out-string)"
                
            $uslogicalLocation += @($logicalLocation)

        }

        #Loop through each specified Network object to get the URI and put into array
        if($Networks) {$Networks = $Networks.Split(',')}

        $usNetworkUris = @()

        foreach ($network in $Networks){

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting `"$($network)`" URI"
                
            if ($Type -eq "Tunnel" -or $Type -eq "Untagged") { $netType = "Ethernet" }
            else { $netType = $Type } 

            $ret = Get-HPOVNetwork $network -type $NetType
                
            #Check to see if the Network Specified is the same as the Native Network, and set the URI
            if ($network -eq $nativeEthNetwork) { 
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found Native Ethernet network $($network)"
                $nativeEthNetworkUri = $ret.uri 
            }

            $usNetworkUris += $ret.uri
        }

        #Validate Uplink Network Type.            
        switch ($Type) {
            
            "Ethernet" { 
            
                $ethUplinkSetObject.ethernetNetworkType = "Tagged"
                $ethUplinkSetObject.logicalPortConfigInfos = $uslogicalLocation
                $ethUplinkSetObject.networkUris = @($usNetworkUris)
                
                #IF the UplinkType is ETHERNET, we likely have to set the Native VLAN on the uplink port(s)
                if ($nativeEthNetworkUri) { $ethUplinkSetObject | Add-Member -NotePropertyName nativeNetworkUri -NotePropertyValue $nativeEthNetworkUri }
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] $($ligObject.name) Uplink Set object: $($ethUplinkSetObject | convertto-json -depth 99)"

                $ligObject.uplinkSets += $ethUplinkSetObject
                
            }
            "Tunnel" { 
            
                $ethUplinkSetObject.ethernetNetworkType = "Tunnel"
                $ethUplinkSetObject.logicalPortConfigInfos = $uslogicalLocation
                $ethUplinkSetObject.networkUris = @($usNetworkUris)
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] $($ligObject.name) Uplink Set object: $($ethUplinkSetObject | convertto-json -depth 99)"

                $ligObject.uplinkSets += $ethUplinkSetObject
                
            }
            "Untagged" { 
            
                $ethUplinkSetObject.ethernetNetworkType = "Untagged"
                $ethUplinkSetObject.logicalPortConfigInfos = $uslogicalLocation
                $ethUplinkSetObject.networkUris = @($usNetworkUris)
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] $($ligObject.name) Uplink Set object: $($ethUplinkSetObject | convertto-json -depth 99)"
                
                $ligObject.uplinkSets += $ethUplinkSetObject
                
            }

            "FibreChannel" { 

                $fcUplinkSetObject.networkUris = @($usNetworkUris)
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] $($ligObject.name) Uplink Set object: $($fcUplinkSetObject | convertto-json -depth 99)"
                
                $fcUplinkSetObject.logicalPortConfigInfos = $uslogicalLocation
                $ligObject.uplinkSets += $fcUplinkSetObject 

            }

        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request..."
        $resp = Send-HPOVRequest $ligObject.uri PUT $ligObject

        If ($resp.errorCode) {

            $errorRecord = New-ErrorRecord HPOneView.UplinkSetResourceException InvalidOperationState InvalidResult 'New-HPOVUplinkSet' -Message "$resp.message $resp.errorCode" #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)

        }

        else { return $resp }

    }

}

#######################################################
# Server Profiles: 
#

function Get-HPOVProfile {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdLetBinding(DefaultParameterSetName = "Default")]
    Param (
        [parameter(ValueFromPipeline = $false, ParameterSetName = "Default", Mandatory = $false, position=0)]
        [parameter(ValueFromPipeline = $false, ParameterSetName = "List", Mandatory = $false, position=0)]
        [parameter(ValueFromPipeline = $false, ParameterSetName = "Detailed", Mandatory = $false, position=0)]
        [parameter(ValueFromPipeline = $false, ParameterSetName = "Export", Mandatory = $false, position=0)]
        [Alias('profile')]
        [string]$name = $null,

        [parameter(ValueFromPipeline = $false, ParameterSetName = "List", Mandatory = $true)]
        [alias('report')]
        [switch]$List,

        [parameter(ValueFromPipeline = $false, ParameterSetName = "Detailed", Mandatory = $true)]
        [switch]$detailed,

        [parameter(ValueFromPipeline = $false, ParameterSetName = "Default", Mandatory = $false)]
        [parameter(ValueFromPipeline = $false, ParameterSetName = "List", Mandatory = $false)]
        [parameter(ValueFromPipeline = $false, ParameterSetName = "Export", Mandatory = $false)]
        [switch]$Unassigned,
        
        [parameter(ValueFromPipeline = $false, ParameterSetName = "Export", Mandatory = $true)]
        [alias("x")]
        [switch]$export,

        [parameter(ValueFromPipeline = $false, ParameterSetName = "Export", Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [alias("save")]
        [string]$location
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVProfile" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #Validate the path exists.  If not, create it.
		if (($Export) -and !(Test-Path $Location)){ 
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Directory does not exist.  Creating directory..."
            New-Item -path $Location -ItemType Directory
        }

	}

	Process {

        $uri = $script:profilesUri

		#if ($name -and $Unassigned) { 
        #    
        #    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved name: $($name)"
        #    $uri += "?filter=name matches '$name'&filter=serverHardwareUri=null&sort=name:asc" -replace ("[*]","%25")
        #
        #}
        #elseif ($name) { 
        if ($name) { 
           
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved name: $($name)"
            $uri += "?filter=name matches '$name'&sort=name:asc" -replace ("[*]","%25")
        
        }
        #elseif ($Unassigned) { 
        #   
        #    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved name: $($name)"
        #    $uri += "?filter=serverHardwareUri=null&sort=name:asc"
        #
        #}

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
	    $profiles = Send-HPOVRequest $uri

        if ($profiles.total -eq 0 -and $name) {
				
            $errorRecord = New-ErrorRecord InvalidOperationException ServerProfileResourceNotFound ObjectNotFound 'Get-HPOVProfile' -Message "Server Profile '$name' not found. Please check the name again, and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)

		}

        elseif ($profiles.total -eq 0) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No server profile resources found."
            Return
            
        }

        if ($Unassigned) {

            $profiles.members = $profiles.members | ? { $_.serverHardwareUri.length -eq 0 }
            $profiles.total = $profiles.members.count
            $profiles.count = $profiles.members.count

        }
        
	}

    end {

        if ($list.IsPresent) {

            #Display Pertinant Server Profile data in Table format
            $a = @{Expression={$_.name};Label="Profile Name"}, 
                 @{Expression={$_.bios.manageBios};Label="Managing BIOS"},
                 @{Expression={$_.firmware.manageFirmware};Label="Managing Firmware"},
                 @{Expression={(send-hpovrequest $_.serverHardwareTypeUri).name};Label="Server Hardware Type"},
                 @{Expression={(send-hpovrequest $_.enclosureGroupUri).name};Label="Enclosure Group"},
                 @{Expression={	if ($_.serverHardwareUri){ (Send-HPOVRequest $_.serverHardwareUri).name }
						        else { "Unassigned" }
				                };Label="Assigned"},
                 @{Expression={
                 
                        switch ($_.affinity) {

                            "Bay" { "Device bay" }
                            "BayAndServer" { "Device bay + Server Hardware" }


                        }
                 
                 };Label="Server Affinity"},
                 @{Expression={$_.state};Label="State"},
                 @{Expression={$_.status};Label="Status"}

		    #Display List
            $profiles.members | sort-object -property name | format-table $a -AutoSize

        }

        elseif ($detailed.IsPresent) {

            #Display Pertinant Server Profile data in Table format
            $a1 = @{Expression={$_.name};Label="Name"},
                  @{Expression={$profileCache[$serverHardwareTypeUri].name};Label="Server Hardware Type"},
                  @{Expression={$profileCache[$enclosureGroupUri]};Label="Enclosure Group"},
                  @{Expression={	if ($_.serverHardwareUri){ (Send-HPOVRequest $_.serverHardwareUri).name }
				 		        else { "Unassigned" }
				                 };Label="Assigned"},
                  @{Expression={
                  
                         switch ($_.affinity) {
                  
                             "Bay" { "Device bay" }
                             "BayAndServer" { "Device bay + Server Hardware" }
                  
                  
                         }
                  
                  };Label="Server Affinity"},
                  @{Expression={$_.state};Label="State"},
                  @{Expression={$_.status};Label="Status"}

            $a2 = @{Expression={$_.bios.manageBios};Label="Manage BIOS";align="Left"},
                  @{Expression={$_.boot.manageBoot};Label="Manage Boot Order";align="Left"},
                  @{Expression={$_.firmware.manageFirmware};Label="Manage Firmware";align="Left"},
                  @{Expression={if ($_.serialNumberType -eq "Virtual") { $_.serialNumber + " (v)" } else { $_.serialNumber + " (p)" }};Label="Serial Number"},
                  @{Expression={if ($_.serialNumberType -eq "Virtual") { $_.uuid + " (v)" } else { $_.uuid + " (p)" }};Label="UUID"}


            #Firmware Details
            $f = @{Expression={
                if ($_.firmware.manageFirmware) {

                    $baseline = Send-HPOVRequest $_.firmware.firmwareBaselineUri
                    "$($baseline.name) version $($baseline.version)"

                }
                else { "none" }
            
            };Label="Firmware Baseline"}

            $c = @{Expression={$_.id};Label="ID";width=2},
                 @{Expression={$_.functionType};Label="Type";width=12},
                 @{Expression={
                   
                   $address = @()
                 
                   #Mac Address
                   if ($_.macType -eq "Virtual" -and $_.mac) { $address += "MAC $($_.mac) (V)" }
                   elseif ($_.macType -eq "Physical" -and $_.mac) { $address += "MAC $($_.mac) (p)" }
                   
                   #WWNN
                   if ($_.wwpnType -eq "Virtual" -and $_.wwnn) { $address += "WWNN $($_.wwnn) (v)"} 
                   elseif ($_.wwpnType -eq "Physical" -and $_.wwnn) { $address += "WWNN $($_.wwnn) (p)" }
                   
                   #WWPN
                   if ($_.wwpnType -eq "Virtual" -and $_.wwpn) { $address += "WWPN $($_.wwpn) (v)"} 
                   elseif ($_.wwpnType -eq "Physical" -and $_.wwpn) { $address += "WWPN $($_.wwpn) (p)" }

                   $addressCol = $address | Out-String | % { $_ -replace '^\s+|\s+$' }
                   $addressCol
                   
                 };Label="Address";width=32},
                 @{Expression={$profileCache[$_.networkUri]};Label="Network"},
                 @{Expression={$_.portId};Label="Port Id";width=10},
                 @{Expression={[string]$_.requestedMbps};Label="Requested BW";width=12},
                 @{Expression={[string]$_.maximumMbps};Label="Maximum BW";width=10},
                 @{Expression={
                 
                      $bootSetting = @()
                      $bootSetting += $_.boot.priority
                      if ($_.boot.targets) {
                 
                           for ($i=0; $i -eq $boot.targets.count; $i++) { $bootSetting += "WWN $($_.boot.targets[$i].arrayWwpn)`nLUN $($_.boot.targets[$i].lun)" }
                 
                      }
                      $bootSettingString = $bootSetting | Out-String | % { $_ -replace '^\s+|\s+$' }
                      $bootSettingString
                 
                   
                  };Label="Boot";width=20},
                 @{Expression={
                 
                    if ($_.functionType -eq "FibreChannel" -and -not ($_.boot.targets)) { "Yes" } 
                    elseif ($_.functionType -eq "FibreChannel" -and $_.boot.targets) { "No" }
                    else { $Null }
                 
                  };Label="Use Boot BIOS";width=13}
                               
            #Display extended BIOS settings
            $b = @{Expression={$_.category};Label="BIOS Category"},
                 @{Expression={$_.settingName};Label="Setting Name"},
                 @{Expression={$_.valueName};Label="Configured Value"}

            $ls = @{Expression={$_.localStorage.manageLocalStorage};Label="Manage Local Storage";align="Left"},
                  @{Expression={$_.localStorage.initialize};Label="Initialize Disk";align="Left"},
                  @{Expression={
                  
                        $logicalDriveCol = @()
                        $d=0

                        while ($d -lt $sp.localStorage.logicalDrives.count) {

                            if ($_.localStorage.logicalDrives[$d].bootable) { $logicalDriveCol += "Drive {$d} $($sp.localStorage.logicalDrives[$d].raidLevel) (Bootable)" }
                            else { $logicalDriveCol += "Drive {$d} $($sp.localStorage.logicalDrives[$d].raidLevel)" }
                            $d++
                        }

                        $logicalDriveString = $logicalDriveCol | Out-String | % { $_ -replace '^\s+|\s+$' }
                        $logicalDriveString
                    
                   };Label="Logical Disk"}

            $ss = @{Expression={$_.manageSanStorage};Label="Manage SAN Storage";align="Left"},
                  @{Expression={$_.hostOSType};Label="Host OS Type";align="Left"}

            $p = @{Expression={[int]$_.connectionId};Label="Connection ID";align="Left"},
                 @{Expression={[string]$_.network};Label="Fabric";align="Left"},
                 @{Expression={[string]$_.initiator};Label="Initiator";align="Left"},
                 @{Expression={[string]$_.target};Label="Target";align="Left"},
                 @{Expression={[bool]$_.isEnabled};Label="Enabled";align="Left"}

            #Server Profile cache
            $profileCache = @{}
            
            #loop through all Server Profile objects and display details
            ForEach ($profile in ($profiles.members | sort-object -property name)) {

                $serverHardwareTypeUri = $profile.serverHardwareTypeUri
                $enclosureGroupUri = $profile.enclosureGroupUri

                #Cache resources during runtime to reduce API calls to appliance.
                if (-not ($profileCache[$serverHardwareTypeUri])) { $profileCache.Add($serverHardwareTypeUri,(Send-HPOVRequest $serverHardwareTypeUri)) }
                if (-not ($profileCache[$enclosureGroupUri])) { $profileCache.Add($enclosureGroupUri,(Send-HPOVRequest $enclosureGroupUri).name) }
                foreach ($connection in $profile.connections) {
                
                    $connection | % { $_.psobject.typenames.Insert(0,”HPOneView.Profile.Connection”) }

                    if (-not ($profileCache[$connection.networkUri])) { $profileCache.Add($connection.networkUri,(Send-HPOVRequest $connection.networkUri).name) } 
                
                }

                foreach ($volume in $profile.sanStorage.volumeAttachments) {

                    #insert HPOneView.Profile.SanVolume TypeName
                    $volume | % { $_.psobject.typenames.Insert(0,”HPOneView.Profile.SanVolume") }
	
                    #Cache Storage System, Storage Pool and Storage Volume Resources
                    if (-not ($profileCache[$volume.volumeStorageSystemUri])) { $profileCache.Add($volume.volumeStorageSystemUri,(Send-HPOVRequest $volume.volumeStorageSystemUri)) }
                    if (-not ($profileCache[$volume.volumeStoragePoolUri])) { $profileCache.Add($volume.volumeStoragePoolUri,(Send-HPOVRequest $volume.volumeStoragePoolUri)) }
                    if (-not ($profileCache[$volume.volumeUri])) { $profileCache.Add($volume.volumeUri,(Send-HPOVRequest $volume.volumeUri)) }

                }

                #$profileCache

                #Initial Server Profile information
                $profile | format-table $a1 -AutoSize -wrap
                $profile | format-table $a2 -AutoSize -wrap

                #Firmware Baseline
                $profile | format-table $f

                #Server Profile Connection details
                $profile.connections | format-table -wrap
                
                #Local Storage
                $profile | format-table $ls -wrap -auto

                #SAN Storage
                $profile.sanStorage | Format-Table $ss -auto
                #$profile.sanStorage.volumeAttachments | format-table -auto

                $profile.sanStorage.volumeAttachments | % {

                    $_ | format-table -auto

                    $pathConnectionCol = @()

                    foreach ($path in $_.storagePaths) {

                        $pathObject = [PSCustomObject]@{
							connectionId = $Null; 
							network      = $Null; 
							initiator    = $Null; 
							target       = $Null; 
							isEnabled    = $Null
						}

                        $pathConnection = $profile.connections | where { $path.connectionId -eq $_.id }

                        $pathObject.connectionId = $pathConnection.id
                        $pathObject.network      = $profileCache[$pathConnection.networkUri]
                        $pathObject.initiator    = $pathConnection.wwpn
                        $pathObject.target       = if ($path.storageTargets) { $path.storageTargets }
												   else { "Pending" }
                        $pathObject.isEnabled    = [bool]$path.isEnabled
                        $pathConnectionCol += $pathObject

                    }

                    #
                    #Display path details with a left padded view. Format-Table doesn't have the ability to pad the display
                    $capture = ($pathConnectionCol | sort connectionId | format-table $p -AutoSize -wrap | out-string) -split "`n"
                    $capture | % { ($_).PadLeft($_.length + 5) }

                }

                #Boot Order
                $bootOrder = @()
                if ($profile.boot.manageBoot) {

                    $i = 0
                    while ($i -lt $profile.boot.order.count) {
                        $bootOrder += "$($i+1) $($profile.boot.order[$i])"
                        $i++
                    }
                    write-host "Boot Order"
                    write-host "----------"
                    $bootOrder

                }
                else { "No Boot Management" }

                #Display configured BIOS Settings from profile
                $configedBiosSettings = @()

                foreach ($setting in $profile.bios.overriddenSettings) {

                    $shtBiosSettingDetails = $profileCache[$serverHardwareTypeUri].biosSettings | ? { $setting.id -eq $_.id }

                    $biosSetting = [PSCustomObject]@{

                        Category = $shtBiosSettingDetails.category;
                        settingName = $shtBiosSettingDetails.name;
                        valueName = ($shtBiosSettingDetails.options | ? { $_.id -eq $setting.value } ).name;

                    }

                    $configedBiosSettings += $biosSetting
                
                }            
            
                $configedBiosSettings | sort category,settingName | format-list $b

                "----------------------------------------------------------------------"
            
            }

        }

        #If user wants to export the profile configuration
        elseif ($export) {

            #Loop through all profiles
            foreach ($profile in $profiles.members) {

                #trim out appliance unique properties

                $profile = $profile | select-object -Property * -excludeproperty uri,etag,created,modified,status,state,inprogress,enclosureUri,enclosureBay,serverHardwareUri,taskUri
                $profile.serialNumberType = "UserDefined"

                #Loop through the connections to save the assigned address
                $i = 0
                foreach ($connection in $profile.connections) {

                    if ($profile.connections[$i].mac) { $profile.connections[$i].macType = "UserDefined" }
                    if ($profile.connections[$i].wwpn) { $profile.connections[$i].wwpnType = "UserDefined" }
                    $i++

                }

                #save profile to JSON file
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Saving $($profile.name) to $($location)\$($profile.name).json"
                convertto-json -InputObject $profile -depth 99 | new-item "$location\$($profile.name).json" -itemtype file
                
            }

        }

        else {

            $profiles.members

        }

        "Done. {0} server profile resource(s) found." -f $profiles.total | out-host 

    }

 }

function New-HPOVProfile {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdLetBinding(DefaultParameterSetName = "Default")]
    Param (
        [parameter(Mandatory = $true, ParameterSetName = "Default", Position = 0)]
        [parameter(Mandatory = $true, ParameterSetName = "EmptyBayAssign", Position = 0)]
        [parameter(Mandatory = $true, ParameterSetName = "SANStorageAttach", Position = 0)]
		[ValidateNotNullOrEmpty()]
        [string]$name,

        [parameter(Mandatory = $false, valuefrompipeline = $True, ParameterSetName = "Default", Position = 1)]
        [parameter(Mandatory = $false, valuefrompipeline = $True, ParameterSetName = "SANStorageAttach", Position = 1)]
        [ValidateNotNullOrEmpty()]
        [object]$server="unassigned",

        [parameter(Mandatory = $false, ParameterSetName = "Default", position = 2)] 
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign", position = 1)] 
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach", position = 2)]
		[string]$description=$null,

        [parameter(Mandatory = $false, ParameterSetName = "Default", position = 3)]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign", position = 2)]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach", position = 3)]
		[ValidateNotNullOrEmpty()]
        [array]$connections=@(),

        [parameter(Mandatory = $false, ParameterSetName = "Default",position = 4)]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach", position = 4)]
		[ValidateNotNullOrEmpty()]
		[Alias('eg')]
        [object]$enclosureGroup=$Null,

        [parameter(Mandatory = $false, ParameterSetName = "Default", position = 5)]
        [parameter(Mandatory = $true, ParameterSetName = "EmptyBayAssign", position = 3)]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach", position = 5)]
        [ValidateNotNullOrEmpty()]
		[Alias('sht')]
        [object]$serverHardwareType=$null,

        [parameter(Mandatory = $true, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateNotNullOrEmpty()]
		[Alias('encl')]
        [object]$enclosure=$null,
        
        [parameter(Mandatory = $true, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateNotNullOrEmpty()]
		[Alias('bay')]
        [object]$enclosureBay=$null,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateNotNullOrEmpty()]
        [switch]$firmware,
	
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateNotNullOrEmpty()]
        [object]$baseline = $null,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [switch]$forceInstallFirmware,
	
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateNotNullOrEmpty()]
        [switch]$bios = $false,

	    [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateNotNullOrEmpty()]
        [array]$biosSettings=@(),

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [Alias('boot')]
        [ValidateNotNullOrEmpty()]
        [bool]$manageBoot = $true,

	    [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [array]$bootOrder = @(‘CD’,’Floppy’,’USB’,’HardDisk’,’PXE’),

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [switch]$localstorage,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [switch]$Initialize,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]        
        [switch]$Bootable,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateSet("RAID1","RAID0","NONE", IgnoreCase=$true)]
        [string]$RaidLevel = $Null,

        [parameter(Mandatory = $True, ParameterSetName = "SANStorageAttach")]
        [switch]$SANStorage,

        [parameter(Mandatory = $true, ParameterSetName = "SANStorageAttach")]
        [ValidateSet('CitrixXen','AIX','IBMVIO','RHEL4','RHEL3','RHEL','RHEV','VMware','Win2k3','Win2k8','Win2k12','OpenVMS','Egenera','Exanet','Solaris9','Solaris10','Solaris11','ONTAP','OEL','HPUX11iv1','HPUX11iv2','HPUX11iv3','SUSE','SUSE9','Inform', IgnoreCase=$true)]
        [Alias('OS')]
        [string]$HostOStype = $Null,

        [parameter(Mandatory = $true, ParameterSetName = "SANStorageAttach")]
        [object]$StorageVolume = $Null,

        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [Alias('Even')]
        [switch]$EvenPathDisabled,

        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [Alias('Odd')]
        [switch]$OddPathDisabled,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateSet("Bay","BayAndServer", IgnoreCase=$false)]
        [string]$Affinity = "Bay",
	
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateSet("Virtual", "Physical", "UserDefined", IgnoreCase=$true)]
        [string]$macAssignment = "Virtual",

        [parameter(Mandatory = $false,ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateSet("Virtual", "Physical", "'UserDefined", IgnoreCase=$true)]
        [string]$wwnAssignment = "Virtual",

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "EmptyBayAssign")]
        [parameter(Mandatory = $false, ParameterSetName = "SANStorageAttach")]
        [ValidateSet("Virtual", "Physical", IgnoreCase=$true)]
        [string]$snAssignment = "Virtual",

        [parameter(Mandatory = $true, ParameterSetName = "Import")]
        [switch]$Import,
        
        [parameter(Mandatory = $true, ParameterSetName = "Import", ValueFromPipeline = $true)]
        [alias("location","file")]
        [Object]$ProfileObj

    )
	
    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVProfile" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #New Server Resource Object
        $serverProfile = [pscustomobject]@{

            type                  = "ServerProfileV3"; 
            name                  = $name; 
            description           = $description; 
            affinity              = $Affinity;
            bios                  = @{manageBios = [bool]$bios; overriddenSettings = $biosSettings}; 
            firmware              = @{manageFirmware = [bool]$firmware; firmwareBaselineUri = $baseline; forceInstallFirmware = [bool]$forceInstallFirmware};
            boot                  = @{manageBoot = [bool]$manageBoot; order=$bootOrder};
            localStorage          = $null
            serialNumberType      = $snAssignment; 
            macType               = $macAssignment;
            wwnType               = $wwnAssignment;
            connections           = $connections; 
            serverHardwareUri     = $null;
            serverHardwareTypeUri = $null;
            enclosureGroupUri     = $null;
            enclosureUri          = $null;
            enclosureBay          = $null;
            sanStorage            = $null
        }

        #If either enclosure or enclosureBay are provided, but not the other, generate terminating error
        if ($enclosure -and -not ($enclosureBay)) { 

            $errorRecord = New-ErrorRecord HPOneview.ServerProfileResourceException ParameterNotSpecified InvalidArgument "New-HPOVProfile" -Message "The '-Enclosure' parameter was provided, but not '-EnclosureBay'. Please provide an Enclosure Bay value and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)        
            
        }

        if (-not ($enclosure) -and $enclosureBay) {             
            
            $errorRecord = New-ErrorRecord HPOneview.ServerProfileResourceException ParameterNotSpecified InvalidArgument "New-HPOVProfile" -Message "The '-EnclosureBay' parameter was provided, but not '-Enclosure'. Please provide an Enclosure Bay value and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)        
        
        }

    }
	
	Process {

        #Import Server Profile JSON to appliance
        if ($import) {

            if (($ProfileObj -is [System.String]) -and (Test-Path $ProfileObj)) {

                #Recieved file location
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received JSON file as input $($ProfileObj)"
                $serverProfile = (get-content $ProfileObj) -join "`n" | convertfrom-json

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
                $resp = Send-HPOVRequest $script:profilesUri POST $serverProfile

            }

            #Input object could be the JSON object, which is type [System.String]
            elseif ($ProfileObj -is [System.String]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received JSON resource object as input $($ProfileObj | out-string)"
                $serverProfile = $ProfileObj -join "`n" | convertfrom-json

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
                $resp = Send-HPOVRequest $script:profilesUri POST $serverProfile

            }

            #Input object is PsCustomObject of a Server Profile
            elseif ($ProfileObj -is [PsCustomObject]) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Received JSON PsCustomObject as input $($ProfileObj | out-string)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
                $resp = Send-HPOVRequest $script:profilesUri POST $ProfileObj

            }

            #Inavlid input type for $ProfileObj and Generate Terminating Error
            else { 

                $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidImportObject InvalidArgument 'New-HPOVPropfile' -Message "Invalid `$Import input object.  Please check the object you provided for ProfileObj parameter and try again" #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            
            }
        }

        #We are not going to import a Server Profile
        else {
		
		    # We are creating an unassigned server profile
	        if ($server -eq 'unassigned') {
			
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Creating an Unassigned Server Profile"
			    #$serverHardwareUri = $null
			
			    #Check to see if the serverHardwareType or enclosureGroup is null, and generate error(s) then break.
			    if ((!$serverHardwareType) -or (!$enclosureGroup)) {

				    if (!$serverHardwareType){

                        $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidServerHardwareTypeObject InvalidArgument 'New-HPOVPropfile' -Message "Server Hardware Type is missing.  Please provide a Server Hardware Type using the -sht parameter and try again." #-verbose
                
				    }

				    elseif (!$enclosureGroup){
					    
                        $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidEnclosureGroupObject InvalidArgument 'New-HPOVPropfile' -Message "Enclosure Group is missing.  Please provide an Enclosure Group using the -eg parameter and try again." #-verbose
				    
                    }
                    
                    #Generate Terminating Error
				    $PSCmdlet.ThrowTerminatingError($errorRecord)
			    }
			
			    #If the URI is passed as the Server Hardware Type, then set the serverHardwareTypeUri variable
			    If ($serverHardwareType -is [string]){

				    if ($serverHardwareType.StartsWith($script:serverHardwareTypesUri)){ 
                        
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SHT URI Provided: $serverHardwareType" 

                        $serverProfile.serverHardwareTypeUri = $serverHardwareType
                        $serverHardwareType = Send-HPOVRequest $serverHardwareType
                        
                    }
				
				    #Otherwise, perform a lookup ofthe SHT based on the name
				    else {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SHT Name Provided: $serverHardwareType"

					    $serverHardwareType = Get-HPOVServerHardwareType -name $serverHardwareType

                        if ($serverHardwareType) {

					        $serverProfile.serverHardwareTypeUri = $serverHardwareType.uri
					        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SHT URI: $serverHardwareTypeUri"
                        }

                        else {

                            $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidServerHardwareTypeParameter InvalidArgument 'New-HPOVPropfile' -Message "" #-verbose
                            $PSCmdlet.ThrowTerminatingError($errorRecord)

                        }

				    }

			    }
			
			    #Else the SHT object is passed
			    else { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ServerHardwareType object provided"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ServerHardwareType Name: $($serverHardwareType.name)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ServerHardwareType Uri: $($serverHardwareType.uri)"

                    $serverProfile.serverHardwareTypeUri = $serverHardwareType.uri
                    
                }
			
			    if ($enclosureGroup -is [string]){

				    #If the URI is passed as the Enclosure Group, then set the enclosureGroupUri variable
				    if ($enclosureGroup.StartsWith('/rest')){ $serverProfile.enclosureGroupUri = $enclosureGroup}

				    #Otherwise, perform a lookup ofthe Enclosure Group
				    else{

					    $enclosureGroup = Get-HPOVEnclosureGroup -name $enclosureGroup

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] EG URI: $enclosureGroupUri"					    
                        $serverProfile.enclosureGroupUri = $enclosureGroup.uri
					    
				    }

			    }
						
			    #Else the EG object is passed
			    elseif (($enclosureGroup -is [PSCustomObject]) -and ($enclosureGroup.category -eq "enclosure-groups")) { 

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Group object provided"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Group Name: $($enclosureGroup.name)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Group Uri: $($enclosureGroup.uri)"

                    $serverProfile.enclosureGroupUri = $enclosureGroup.uri 

                }

                elseif (-not $enclosureGroup -and $serverHardwareType.model -match "DL") {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server is a ProLiant DL model. Enclosure Group not required."

                }

                else { 
                
                    #write-error "The Enclosure Group object was invalid." -Category SyntaxError -RecommendedAction "Specify a correct Enclosure Group name, URI or object." -CategorytargetName "New-HPOVProfile" 
                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidEnclosureGroupObject InvalidArgument 'New-HPOVPropfile' -Message "Enclosure Group is invalid.  Please specify a correct Enclosure Group name, URI or object and try again." #-verbose

                    #Generate Terminating Error
				    $PSCmdlet.ThrowTerminatingError($errorRecord)
                    
                }

	        }
	
		    # Creating an assigned profile
		    else {
			
                #Assign profile to specific Server resource
                if ($server) {

			        #Looking for the $server DTO to be string
			        if ($server -is [string]) {
				
				        #If the server URI is passed, look up the server object
				        if ($server.StartsWith($script:serversUri)) {

					        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server URI passed: $server"
					        [object]$server = Send-HPOVRequest $server

				        }
				
				        #Else the name is passed and need to look it up.
				        else{

					        [object]$server = Get-HPOVServer -name $server
                    
                            #An error should have been displayed if the server object wasn't found.
                            if (-not ($server)){ break }

				        }

			        }
			
			        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server Object: $($server | out-string)"

			        #Check to make sure the server NoProfileApplied is true
			        if (-not ($server.serverProfileUri)) {

				        $serverProfile.serverHardwareUri = $server.uri
				        $serverProfile.serverHardwareTypeUri = $server.serverHardwareTypeUri
                    
                        #Handle Blade Server objects
                        if ($server.serverGroupUri) { $serverProfile.enclosureGroupUri = $server.serverGroupUri }

			        }
			        else {

                        $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException ServerProfileAlreadyAssigned ResourceExists 'New-HPOVProfile' -Message "$((Send-HPOVRequest $server.serverProfileUri).name) already has a profile assigned, '$($serverProfile.name)'.  Please specify a different Server Hardware object." #-verbose
				        $pscmdlet.ThrowTerminatingError($errorRecord)

			        }

                    #Get the SHT of the SH that we are going to assign.
                    $serverHardwareType = Send-HPOVRequest $server.serverHardwareTypeUri
                
                }

                #Assign Profile to specific empty device bay
                elseif ($enclosure -and $enclosureBay) {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] creating server profile for empty device bay assignment."

                    #Check to see what $enclosure is
                    switch ($enclosure.gettype().name) {

                        "String" { 
                        
                            #Correct URI
                            if ($enclosure.StartsWith('/rest/enclosures')) {
                                
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved Enclosure URI: $enclosure"

                                $enclosure = Send-HPOVRequest $enclosure

                            }

                            #Wrong URI and generate error
                            elseif ($enclosure.StartsWith('/rest/')) {

                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved incorrect Enclosure URI: '$enclosure'.  Generating terminating error."

                                $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidEnclosureResourceUri InvalidArgument 'New-HPOVProfile' -Message "The -enclosure parameter value '$enclosure' is not the correct URI.  Enclosure URI must begin with '/rest/enclosures'. Please correct this value and try again." #-verbose
				                $pscmdlet.ThrowTerminatingError($errorRecord)

                            }

                            #Value is Enclosure Name
                            else {

                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved Enclosure Name: $enclosure"

                                $enclousre = Get-HPOVEnclosure $enclosure

                            }
                        
                        }
                        "PSCustomObject" { 

                            if ($enclosure.category -eq 'enclosures') {
                        
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure object provided"
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Object Name: $($enclosure.name)"
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Enclosure Object URI: $($enclosure.uri)"

                            }
                            else {

                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved incorrect Enclosure Object. Recieved category: $($enclosure.category)"

                                $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidEnclosureResourceObject InvalidArgument 'New-HPOVProfile' -Message "The -enclosure parameter object category '$($enclosure.category)' provided is not the correct value.  The resource category value should be 'enclosures'.  Please correct this value and try again." #-verbose
				                $pscmdlet.ThrowTerminatingError($errorRecord)

                            }
                        
                        }

                    }

                    #Validate no server hardware is present within the requested device bay
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Checking $enclosureBay if it is empty."

                    #generate terminating error if bay devicePresent is not "absent"
                    if (($enclosure | ? { $_.bayNumber -eq $enclosureBay }).devicePresence -ne 'absent') {

                        

                    }

                    $serverProfile.enclosureUri      = $enclosure.uri
                    $serverProfile.enclosureGroupUri = $enclosure.enclosureGroupUri

                    #Check ServerHardwareType value
			        switch ($serverHardwareType.GetType().name) {

                        "String" {

				            if ($serverHardwareType.StartsWith($script:serverHardwareTypesUri)){ 
                        
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SHT URI Provided: $serverHardwareType" 

                                $serverProfile.serverHardwareTypeUri = $serverHardwareType
                                $serverHardwareType = Send-HPOVRequest $serverHardwareType
                        
                            }
				
				            #Otherwise, perform a lookup ofthe SHT based on the name
				            else {

                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SHT Name Provided: $serverHardwareType"

					            $serverHardwareType = Get-HPOVServerHardwareType -name $serverHardwareType

                                if ($serverHardwareType) {

					                $serverProfile.serverHardwareTypeUri = $serverHardwareType.uri
					                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SHT URI: $serverHardwareTypeUri"
                                }

                                else {

                                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidServerHardwareTypeParameter InvalidArgument 'New-HPOVPropfile' -Message "" #-verbose
                                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                                }

				            }

			            }
                        
                        #SHT object is passed
                        "PSCustomObject" {

                            if($serverHardwareType.category -eq 'server-hardware-types') {
                                
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ServerHardwareType object provided"
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ServerHardwareType Name: $($serverHardwareType.name)"
                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ServerHardwareType Uri: $($serverHardwareType.uri)"

                                $serverProfile.serverHardwareTypeUri = $serverHardwareType.uri

                            }
                            else {

                                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Recieved incorrect Server Hardware Type Object. Recieved category: $($serverHardwareType.category)"

                                $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidEnclosureResourceObject InvalidArgument 'New-HPOVProfile' -Message "The -enclosure parameter object category '$($enclosure.category)' provided is not the correct value.  The resource category value should be 'enclosures'.  Please correct this value and try again." #-verbose
				                $pscmdlet.ThrowTerminatingError($errorRecord)

                            }
                    
                        }

                    }

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Creating Server Profile for empty device bay: '$enclosureBay' in '$($enclosure.name)' with Server Hardware Type: $($serverHardwareType.name)"

                }

		    }

            #Check to make sure Server Hardware Type supports Firmware Management (OneView supported G7 blade would not support this feature)
            if ($firmware) {
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Firmware Baseline $($baseline)"

                if ($serverHardwareType.capabilities -match "firmwareUpdate" ) {

                    #Validating that the baseline value is a string type and that it is an SPP name.
		            if (($baseline -is [string]) -and (! $baseline.StartsWith('/rest'))) {

			            $baseline = Get-HPOVSppFile $baseline
			            $serverProfile.firmware.firmwareBaselineUri = $baseline.uri

		            }
            
                    #Validating that the baseline value is a string type and that it is the Basline URI
		            elseif (($baseline -is [string]) -and ($baseline.StartsWith('/rest'))) {
			    
			            $baselineObj = Send-HPOVRequest $baseline

                        if ($baselineObj.category -eq "firmware-drivers") {
			            
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Valid Firmware Baseline provided: $($baselineObj.baselineShortName)"
                            $serverProfile.firmware.firmwareBaselineUri = $baselineObj.uri 
                        
                        }
                        else {

                            $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException InvalidSppBaseline ObjectNotFound  'New-HPOVProfile' -Message "The provided SPP Baseline URI '$($baseline)' is not valid or the correct resource category (expected 'firware-drivers', recieved '$($baselineObj.category)'.  Please check the -baseline parameter value and try again." #-verbose
				            $pscmdlet.ThrowTerminatingError($errorRecord)

                        }

		            }

                    #Else we are expecting the SPP object that contains the URI.
                    elseif (($baseline) -and ($baseline -is [object])) {

                        $serverProfile.firmware.firmwareBaselineUri = $baseline.uri
                    
                    }

                }

                else {

                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException ServerHardwareMgmtFeatureNotSupported NotImplemented 'New-HPOVProfile' -Message "`"$($serverHardwareType.name)`" Server Hardware Type does not support Firmware Management." #-verbose
				    $pscmdlet.ThrowTerminatingError($errorRecord)
                    
                }

            }

            #Check to make sure Server Hardware Type supports Bios Management (OneView supported G7 blade would not support this feature)
            if ($bios) {

                if ($serverHardwareType.capabilities -match "ManageBIOS" ) { 

                	#check for any duplicate keys
                    $biosFlag = $false
                    $hash = @{}
                    $biosSettings.id | % { $hash[$_] = $hash[$_] + 1 }

                    foreach ($biosItem in ($hash.GetEnumerator() | ? {$_.value -gt 1} | % {$_.key} )) {
                         
                        $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException BiosSettingsNotUnique InvalidOperation 'New-HPOVProfile' -Message "'$(($serverHardwareType.biosSettings | where { $_.id -eq $biosItem }).name)' is being set more than once. Please check your BIOS Settings are unique.  This setting might be a dependancy of another BIOS setting/option.  Please check your BIOS Settings are unique.  This setting might be a dependancy of another BIOS setting/option." #-verbose
				        $pscmdlet.ThrowTerminatingError($errorRecord)

                    }

                }

                else { 

                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException ServerHardwareMgmtFeatureNotSupported NotImplemented 'New-HPOVProfile' -Message "`"$($serverHardwareType.name)`" Server Hardware Type does not support BIOS Management." #-verbose
				    $pscmdlet.ThrowTerminatingError($errorRecord)                
                
                }

           }

            #Set Local Storage Management and Check to make sure Server Hardware Type supports it (OneView supported G7 blade would not support this feature)
            if (($localstorage) -and ($serverHardwareType.capabilities -match "ManageLocalStorage" )) {
            
                 $serverProfile.localStorage = [PSCustomObject]@{ 
                     initialize         = [bool]$Initialize;
                     manageLocalStorage = [bool]$localstorage;
                     logicalDrives      = @(
                         @{ 
                             bootable  = [bool]$Bootable;
                             raidLevel = $RaidLevel.ToUpper() 
                         }
                     )
                 }
                 
            }
		    
            #StRM Support
            if ([bool]$SANStorage -and $serverHardwareType.model -match "BL") { 

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SAN Storage being requested"
            
                #Get list of available storage system targets and the associated Volumes based on the EG and SHT provided
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of available storage systems"
                $availStorageSystems = (Send-HPOVRequest ($script:profileAvailStorageSystemsUri + "?enclosureGroupUri=$($serverProfile.enclosureGroupUri)&serverHardwareTypeUri=$($serverHardwareType.uri)")).members
                
                #Get list of attacable Volumes (i.e. they are not assigned private or are shareable volumes)
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of attachable volumes"
                $attachableVolumes = (Send-HPOVRequest $script:attachableVolumesUri).members
                
                $serverProfile.sanStorage = [pscustomobject]@{
                    hostOSType        = $script:profileSanManageOSType.($HostOsType);
                    manageSanStorage  = [bool]$SANStorage;
                    volumeAttachments = @()
                }
                
                #Copy the parameter array into a new object
                [Array]$volumesToAttach = $StorageVolume | % { $_ }
                
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Volumes to process $($volumesToAttach | out-string)"
                
                $i = 0
                
                #Process volumes being passed
                foreach ($volume in $volumesToAttach) {  

                    #If the storage paths array is null, process connections to add mapping
                    if (!$volume.storagePaths) {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Storage Paths value is Null" -Verbose
                        
                        #Get storage volume name for reporting purposes
                        $volumeName = (send-hpovrequest $volume.volumeUri).name

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing Volume ID: $($volume.id)"
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking to see if volume '$($volume.volumeUri) ($($volumeName))' is attachable"
                
                        #validate volume is attachable
                        $attachableVolFound = $attachableVolumes | ? { $_.uri -eq $volume.volumeUri }
                
                        #If it is available, continue processing
                        if ($attachableVolFound) {
                
                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] '$($attachableVolFound.uri) ($($attachableVolFound.name))' volume is attachable"
                
                            #validate the volume that is available, is also avialable to the server hardware type and enclosure group
                            $volumeToStorageSystem = $availStorageSystems | ? { $_.storageSystemUri -eq $attachableVolFound.storageSystemUri }
                
                            #If available, process the volume networks
                            if ($volumeToStorageSystem) { 
                                
                                #Check to make sure profile connections exist.
                                if ($serverProfile.connections) {
                                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Profile has connections"
                                    
                                    #loop through profile connections
                                    $found = 0

                                    foreach ($volConnection in $attachableVolFound.availableNetworks) {

                                        #write-verbose "Looking for $volConnection"
                                        $profileConnection = $serverProfile.connections | ? { $_.networkUri -eq $volConnection }

                                        if ($profileConnection) {
                                            #write-verbose "Profile Connection: $profileConnection"
                                            #Keep track of the connections found for error reporting later
                                            $found++
                                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Mapping connection ID '$($profileConnection.id)' -> volume ID '$($volumesToAttach[$i].id)'"
                                            
                                            $volumesToAttach[$i].storagePaths += @([pscustomobject]@{
                                                connectionId = $profileConnection.id;
                                                isEnabled = $True
                                            })

                                        }

                                    }

                                    if (!$found) {
                                    
                                        $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException NoProfileConnectionsMapToVolume ObjectNotFound 'New-HPOVProfile' -Message "Unable to find a Profile Connection that will map to '$($volumeName)'. Please check the volume and profile connections and try again."  #-verbose
                                        $PSCmdlet.ThrowTerminatingError($errorRecord)

                                    }
                                    
                                }

                                #Else, generate an error that at least one FC connection must exist in the profile in order to attach volumes.
                                else {

                                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileResourceException NoProfileConnections ObjectNotFound 'New-HPOVProfile' -Message "The profile does not contain any Network Connections.  The Profile must contain at least 1 FC Connection to attach Storage Volumes.  Use the New-HPOVProfileConnection helper cmdlet to create 1 or more connections and try again."  #-verbose
                                    $PSCmdlet.ThrowTerminatingError($errorRecord)

                                }
                
                            }
                
                            #If not, then error
                            elseif (!$volumeToStorageSystem) { 
                            
                                $errorRecord = New-ErrorRecord InvalidOperationException StorageVolumeDoesNotExistOnStorageArray ObjectNotFound 'New-HPOVProfile' -Message "'$($volumeName)' Volume is not available on the '$($volumeToStorageSystem.storageSystemName)' storage system" #-verbose
                                $PSCmdlet.ThrowTerminatingError($errorRecord)                      
                            
                            }
                
                        }
                
                        elseif (!$attachableVolFound) { 
                        
                            $errorRecord = New-ErrorRecord InvalidOperationException StorageVolumeUnavailableForAttach ResourceUnavailable 'New-HPOVProfile' -Message "'$($volumeName)' Volume is not available to be attached to the profile. Please check the volume and try again."  #-verbose
                            $PSCmdlet.ThrowTerminatingError($errorRecord)

                        }
                        
                    }
                    
                    $i++
                }

                $serverProfile.sanStorage.volumeAttachments = $volumesToAttach
                
                #Check to see if user passed -EvenPathDisable and/or -OddPathDisable parameter switches
                if ($EvenPathDisabled.IsPresent -or $OddPathDisabled.IsPresent) {
                    
                    if ($EvenPathDisabledd.IsPresent) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Disable Even Path: $([bool]$EvenPathDisable)" }
                    if ($OddPathDisable.IsPresent) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Disable Odd Path: $([bool]$OddPathDisable)" }

                    #Keep track of Volume Array index
                    $v = 0
                    foreach ($vol in $serverProfile.sanStorage.volumeAttachments) {
                        
                        #Keep track of Volume Path Array index
                        $p = 0
                        foreach ($path in $vol.storagePaths) {

                            if ([bool]$OddPathDisabled -and [bool]($path.connectionID % 2)) { $isEnabled = $false }
                            elseif ([bool]$EvenPathDisabled -and [bool]!($path.connectionID % 2)) { $isEnabled = $false }
                            else { $isEnabled = $true }

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting Connection ID '$($path.connectionID)' path enabled:  $($isEnabled)"

                            $serverProfile.sanStorage.volumeAttachments[$v].storagePaths[$p].isEnabled = $isEnabled
                            $p++
                        }

                        $v++

                    }
                    
                }

            }

		    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Profile: $($serverProfile | out-string)"
	        $resp = Send-HPOVRequest $profilesUri POST $serverProfile

	    }

    }

    End {

        return $resp
        
    }
}

function Copy-HPOVProfile {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdLetBinding()]
    Param(
        [parameter(Mandatory = $True, ValueFromPipeline = $true, position = 0)]
        [Alias('sname')]
        [ValidateNotNullOrEmpty()]
        [object]$SourceName = $null,
        
        [parameter(Mandatory = $false, position = 1)]
        [alias('dname')]
        [string]$DestinationName = $null,
        
        [parameter(Mandatory = $false, position = 2)]
        [object]$assign = "unassigned"


    )
    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Copy-HPOVProfile' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }


    }

    Process {

        if (!$SourceName) { 
        
            $errorRecord = New-ErrorRecord ArgumentNullException ParametersNotSpecified InvalidArgument 'Copy-HPOVProfile' -Message "The input parameter 'SourceName' was Null. Please provide a value and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)
            #Write-Error "The input parameter SourceName was Null. Please provide a value and try again." -Category InvalidArgument -CategoryTargetName "Copy-HPOVProfile"
            #break
            
        }

        #Validate input object type
        #Checking if the input is System.String and is NOT a URI
        if (($SourceName -is [string]) -and (!$SourceName.StartsWith($script:profilesUri))) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SourceName is a Server Profile Name: $($SourceName)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Server Profile URI"
            $profile = Get-HPOVProfile $SourceName
            $profileSourceSHT = $profile.serverHardwareTypeUri

        }

        #Checking if the input is System.String and IS a URI
        elseif (($SourceName -is [string]) -and ($SourceName.StartsWith($script:profilesUri))) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SourceName is a Server Profile URI: $($SourceName)"
            $profile = Send-HPOVRequest $SourceName
            $profileSourceSHT = $profile.serverHardwareTypeUri
        
        }

        #Checking if the input is PSCustomObject, and the category type is server-profiles, which would be passed via pipeline input
        elseif (($SourceName -is [System.Management.Automation.PSCustomObject]) -and ($SourceName.category -ieq "server-profiles")) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SourceName is a Server Profile object: $($SourceName.name)"
            $profile = $SourceName
            $profileSourceSHT = $SourceName.serverHardwareTypeUri
        
        }

        #Checking if the input is PSCustomObject, and the category type is server-hardware, which would be passed via pipeline input
        elseif (($SourceName -is [System.Management.Automation.PSCustomObject]) -and ($SourceName.category -ieq "server-hardware") -and ($SourceName.serverProfileUri)) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] SourceName is a Server Hardware object: $($SourceName.name)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Server Profile object that is assigned to $($SourceName.name)"
            $profile = Send-HPOVRequest $SourceName.serverProfileUri
            $profileSourceSHT = $profile.serverHardwareTypeUri
        
        }

        else {

            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Copy-HPOVProfile' -Message "Invalid parameter valuesThe parameter SourceName value is invalid.  Please validate the SourceName parameter value you passed and try again." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)
            #Write-Error "The parameter SourceName value is invalid.  Please validate the SourceName parameter value you passed and try again." -Category InvalidArgument -CategoryTargetName "Copy-HPOVProfile" -RecommendedAction "Validate the SourceName parameter value you passed and try again."
            #Break

        }

        #If Assign not equal null, validate SH provided matches SHT of the source profile.
        if ($assign -ine 'unassigned') {

             Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server will be assigned"

            #Target Server is the server device name
            if (($assign -is [string]) -and (!$assign.StartsWith($script:serversUri))) {
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Assign to the follwing server hardware: $($assign)"
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting Server URI"
                $serverDevice = Get-HPOVServer $assign
                $profileDestSHT = $serverDevice.serverHardwareTypeUri

            }

            #Checking if the input is System.String and IS a URI
            elseif (($assign -is [string]) -and ($assign.StartsWith($script:serversUri))) {
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Assign to the Server hardware URI: $($assign)"
                $serverDevice = Send-HPOVRequest $assign
                $profileDestSHT = $serverDevice.serverHardwareTypeUri
        
            }

            #Checking if the input is PSCustomObject, and the category type is server-profiles, which would be passed via pipeline input
            elseif (($assign -is [System.Management.Automation.PSCustomObject]) -and ($assign.category -ieq "server-hardware")) {

                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Assign to the Server object: $($assign.name)"
                $serverDevice = $assign
                $profileDestSHT = $serverDevice.serverHardwareTypeUri
        
            }
            
            else {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Copy-HPOVProfile' -Message "The parameter Assign value is invalid.  Please validate the Assign parameter value you passed and try again." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)
                #Write-Error "The parameter Assign value is invalid.  Please validate the Assign parameter value you passed and try again." -Category InvalidArgument -CategoryTargetName "Copy-HPOVProfile" -RecommendedAction "Validate the Assign parameter value you passed and try again."
                #Break

            }

            #Checking if the input is PSCustomObject, and the category type is server-hardware, which would be passed via pipeline input
            if ($serverDevice.serverProfileUri) {
                $errorRecord = New-ErrorRecord InvalidOperationException ServerPropfileResourceAlreadyExists ResourceExists 'Copy-HPOVProfile' -Message "A server profile is already assigned to $($serverDevice.name) ($(Get-HPOVProfile $serverDevice.serverProfileUri).name). Please try specify another server." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)                
                #Write-Error "A server profile is already assigned to $($serverDevice.name) ($(Get-HPOVProfile $serverDevice.serverProfileUri).name). Please try specify another server." -Category ResourceExists -CategoryTargetName "Copy-HPOVProfile"
                #Break
        
            }
        }

        elseif ($assign -ieq "unassigned") {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Server will be unassigned"

        }

        #Check to see if the SHT is different from the Profile and Target Assign Server
        if (($profileDestSHT -ine $profileSourceSHT) -and ($assign -ine "unassigned")){ 
            $errorRecord = New-ErrorRecord InvalidOperationException ServerHardwareTypeMismatch InvalidOperation 'Copy-HPOVProfile' -Message "The Target Server Hardware Type does not match the source Profile Server Hardware Type. Please specify a different Server Hardware Device to assign." #-verbose
            $pscmdlet.ThrowTerminatingError($errorRecord)          
            #Write-Error "The Target Server Hardware Type does not match the source Profile Server Hardware Type. Please specify a different Server Hardware Device to assign." -Category InvalidArgument -CategoryTargetName "Copy-HPOVProfile" -RecommendedAction "Please specify a different Server Hardware Device to assign." 
            #Break
                
        }

        if ($profile.sanStorage) { Write-Warning "SAN Storage Volumes found in the source profile. SAN Volumes will not be copied or assigned to the destination profile." }

        #Need to offer the ability to copy private san volume details in a future library release.

        #Remove Profile Specifics:
        $profile = $profile | select-object -Property * -excludeproperty uri,etag,created,modified,uuid,status,state,inprogress,serialNumber,enclosureUri,enclosureBay,serverHardwareUri,taskUri,sanStorage
        $profile.connections = $profile.connections | select-object -property * -excludeproperty mac,wwnn,wwpn,deploymentstatus,interconnectUri

        #If DestinationName is provided, change to the profile name to value
        if ($DestinationName) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New Server Profile name provided $($DestinationName)"
            $profile.name = $destinationName
        
        }
        
        #If no DestinationName is provided, add "Copy Of " prefix.
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No new Server Profile name provided. Setting to `"Copy of $($profile.name)`""
            $profile.name = "Copy of " + $profile.name

        }

        #If the server hardware device is present, add the property to the object
        if ($serverDevice) {

            $profile | Add-Member @{ serverHardwareUri = $serverDevice.Uri }
        
        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] New Server Profile object: $($profile | out-string)"
        
        #Send request to create new copied profile
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request"
        $resp = Send-HPOVRequest $script:profilesUri POST $profile

        $task = Wait-HPOVTaskStart $resp

    }

    end {

        if ($task.taskState -eq "Error" -and $task.stateReason -eq "ValidationError") {

            switch ($task.taskErrors.errorCode) {

                "DUPLICATED_PROFILE_NAME" { $errorRecord = New-ErrorRecord HPOneview.Appliance.TaskValidationError $task.taskErrors.errorCode ResourceExists  'Copy-HPOVProfile' -Message ($task.taskStatus + " " + $task.taskErrors.message) }
                default { $errorRecord = New-ErrorRecord HPOneview.Appliance.TaskValidationError $task.taskErrors.errorCode InvalidOperation 'Copy-HPOVProfile' -Message ($task.taskStatus + ".  " + $task.taskErrors.message) -InnerException $task.taskErrors.recommendedActions } 

            }

            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
        else { $task }

	}

 }

function Remove-HPOVProfile {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default", SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [parameter (Mandatory = $true,ValueFromPipeline=$true, ParameterSetName = "default", HelpMessage = "Specify the profile(s) to remove.", Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("uri")]
        [Alias("name")]
        [System.Object]$profile = $null,

        [parameter (Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "default", HelpMessage = "Specify to force-remove the profile.")]
        [Switch]$force
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVProfile" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }


    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Profile input type:  $($profile.gettype())"

        foreach ($prof in $profile) {

            $profileNameOrUri = $null
            $profileDisplayName = $null

            if ($prof -is [String]) {

                $profileNameOrUri = $prof
                $profileDisplayName = $prof
        	}
            elseif ($prof -is [PSCustomObject] -and $prof.category -ieq 'server-profiles') {

                $profileNameOrUri = $prof.uri
                $profileDisplayName = $prof.name

            }

		    else {

                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVProfile' -Message "Invalid profile parameter: $prof" #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)
            }

            if (!$profileNameOrUri) {
                $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Remove-HPOVProfile' -Message "Invalid profile parameter: $prof" #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)

            }
            elseif ($pscmdlet.ShouldProcess($profileDisplayName,'Remove profile from appliance?')){   

                if ([bool]$force) { Remove-HPOVResource -nameOrUri $profileNameOrUri -force }
                else { Remove-HPOVResource -nameOrUri $profileNameOrUri }

            }
	    }
    }
}

function Get-HPOVProfileConnectionList {

    # .ExternalHelp HPOneView.110.psm1-help.xml
	
	[CmdLetBinding()]
    Param (
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$name=$null
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {
	
        $profiles = @();
    
        #get profiles
        if ($name)
        {
            $uri = $profilesUri + "?filter=`"name='$name'`"";
            $profile = (Send-HPOVRequest $uri).members;
            if(!$profile){
                $errorRecord = New-ErrorRecord InvalidOperationException ProfileResourceNotFound ObjectNotFound 'Get-HPOVProfileConnectionList' -Message "Server Profile '$name' was not found." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)
                #write-host "no results" -ForegroundColor Red
                #return
                
            }
            #$profile = $col.members;
            #if(!$profile){write-host $name "not found" -ForegroundColor Red; return;}
            $profiles += $profile;
    
        } else {
            $index = Send-HPOVRequest $profileIndexListUri;
            if($index.count -eq 0) {
                $errorRecord = New-ErrorRecord InvalidOperationException ProfileResourceNotFound ObjectNotFound 'Get-HPOVProfileConnectionList' -Message "No Server Profile resources found.  Use New-HPOVProfile to create one." #-verbose
                $pscmdlet.ThrowTerminatingError($errorRecord)            
                #write-host "no profiles found" -ForegroundColor Red; return;
                
            }
    
            foreach($entry in $index.members)
            {
                $profile = Send-HPOVRequest $entry.uri;
                if(!$profile){write-host "profile not found: " $entry.uri -ForegroundColor Red; continue;}
    
                $profiles += $profile;
            }            
        }
    
        #get connections
        $conns = @();
        foreach($p in $profiles)
        {
    
            foreach($c in $p.connections) 
            { 
                $c | add-member -membertype noteproperty -name cid -value $c.id;
                $c | add-member -membertype noteproperty -name serverProfile -value $p.name;
                $c | add-member -membertype NoteProperty -name Network -value (Send-HPOVRequest $c.networkUri).Name
                if($c.wwpn) { $c.wwpn = $c.wwpn.Replace(":",""); } else {$c.wwpn = "-" }
                if($c.wwnn) { $c.wwnn = $c.wwnn.Replace(":",""); } else {$c.wwnn = "-" } 
                if($c.boot.targets) 
                {
                    $c | add-member -membertype noteproperty -name arrayTarget -value $c.boot.targets[0].arrayWwpn;
                    $c | add-member -membertype noteproperty -name lun -value $c.boot.targets[0].lun;
                }
    
                if($c.portId) { 
                    $c.portId = $c.portId.Replace("Flexible", ""); 
                } else { 
                    $name = "Dev:" + $c.deviceNumber + '-' + $c.physicalPortNumber;
                    $c | add-member -membertype noteproperty -name portId -value $name; 
                }
    
               if($c.boot) { $c.boot = $c.boot.priority; }
               if($c.boot -eq "NotBootable") { $c.boot = "-"; }      
               
               $conns += $c;
            }
        }
        #output
        $conns | Sort-Object serverProfile, cid | format-table -Property serverProfile, cid, portId, functionType, Network, mac, wwpn, boot, arrayTarget, lun  -AutoSize   
    } 
}

function New-HPOVProfileConnection {

    # .ExternalHelp HPOneView.110.psm1-help.xml
	
	[CmdLetBinding(DefaultParameterSetName = "Ethernet")]
    Param (

        [parameter(Mandatory = $true, ParameterSetName = "Ethernet")]
		[parameter(Mandatory = $true, ParameterSetName = "FC")]
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
		[ValidateNotNullOrEmpty()]
	    [parameter(Position=0)]
		[Alias('id')]
        [int]$connectionID = 1,

        [parameter(Mandatory = $true, ParameterSetName = "Ethernet")]
		[parameter(Mandatory = $true, ParameterSetName = "FC")]
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
		[ValidateNotNullOrEmpty()]
	    [ValidateSet("Ethernet", "FibreChannel","Eth","FC", IgnoreCase=$true)]
        [parameter(Position=1)]   
		[Alias('type')]
		[string]$connectionType = "Ethernet",

        [parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName = "Ethernet")]
	    [parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName = "FC")]
        [parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName = "UserDefinedEthernet")]
		[parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName = "UserDefinedFC")]
	    [parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName = "bootEthernet")]
		[parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName = "bootUserDefinedFC")]
		[ValidateNotNullOrEmpty()]
	    [parameter(Position=2)]
        [object]$network,

        [parameter(Mandatory = $false, ParameterSetName = "Ethernet")]
		[parameter(Mandatory = $false, ParameterSetName = "FC")]
        [parameter(Mandatory = $false, ParameterSetName = "UserDefinedEthernet")]
		[parameter(Mandatory = $false, ParameterSetName = "UserDefinedFC")]
		[parameter(Mandatory = $false, ParameterSetName = "bootEthernet")]
		[parameter(Mandatory = $false, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $false, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $false, ParameterSetName = "bootUserDefinedFC")]
		[ValidateNotNullOrEmpty()]
	    [parameter(Position=3)]
        [string]$portId = "Auto",

	    [parameter(Mandatory = $false, ParameterSetName = "Ethernet")]
		[parameter(Mandatory = $false, ParameterSetName = "FC")]
        [parameter(Mandatory = $false, ParameterSetName = "UserDefinedEthernet")]
		[parameter(Mandatory = $false, ParameterSetName = "UserDefinedFC")]
		[parameter(Mandatory = $false, ParameterSetName = "bootEthernet")]
		[parameter(Mandatory = $false, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $false, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $false, ParameterSetName = "bootUserDefinedFC")]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(100,10000)]
        [int]$requestedBW = 2500,
	
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
        [ValidateNotNullOrEmpty()]
        [switch]$userDefined = $false,

        [parameter(Mandatory = $true, ParameterSetName = "UserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
        [ValidateScript({$_ -match $script:macAddressPattern})]
        [string]$mac = $Null,
	
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
        [ValidateScript({$_ -match $script:wwnAddressPattern})]
        [string]$wwnn = $Null,
		
		[parameter(Mandatory = $true, ParameterSetName = "UserDefinedFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
        [ValidateScript({$_ -match $script:wwnAddressPattern})]
        [string]$wwpn = $Null,
	
	    [parameter(Mandatory = $true, ParameterSetName = "bootEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
        [ValidateNotNullOrEmpty()]
        [switch]$bootable,
	
		[parameter(Mandatory = $true, ParameterSetName = "bootEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedEthernet")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
		[ValidateNotNullOrEmpty()]
	    [ValidateSet("UseBIOS", "Primary","Secondary", IgnoreCase=$true)]
		[string]$priority = "NotBootable",
	
		[parameter(Mandatory = $true, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
		[ValidateScript({$_ -match $script:wwnAddressPattern})]
		[string]$arrayWwpn = $null,
	
		[parameter(Mandatory = $true, ParameterSetName = "bootFC")]
		[parameter(Mandatory = $true, ParameterSetName = "bootUserDefinedFC")]
		[ValidateRange(0,254)]
		[int]$lun = 0
	
	)
	
	Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'New-HPOVProfileConnection' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        $connection = $Null
    
		#########################
		#Need to validate the requested network(s) from the connection(s) is(are) valid for the Server Hardware Type and Enclosure Group.
		#########################

		
		Write-Verbose -message ("ParameterSet: " + $PsCmdLet.ParameterSetName)
				
        $connection = [pscustomobject]@{
            
            id            = $connectionId;
			functionType  = $connectionType;
		    portId        = $portId; 
		    networkUri    = $null; 
		    requestedMbps = $requestedBW; 
		    boot          = @{

                priority = $priority

            }

		}

	}

	Process {

        switch ($network.Gettype().Name) {


            "String" {

                #Ethernet Network URI
                if ($network.startswith($script:ethNetworksUri)) { 
            
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Locating Ethernet Resource via its URI"

		    	    $net = Send-HPOVRequest $network

                    $connection.functionType = "Ethernet"
            
                }

                #Network Set URI
                elseif ($network.startswith($script:networkSetsUri)) {
            
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Locating Network Set Resource via its URI"

		    	    $net = Send-HPOVRequest $network
                
                    $connection.functionType = "Ethernet"
            
                }

                #FC Network URI
                elseif ($network.startswith($script:ethNetworksUri)) {
            
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Locating FibreChannel Resource via its URI"

		    	    $net = Send-HPOVRequest $network

                    $connection.functionType = "FibreChannel"
                            
                }
                
                #Generate Error due to incorrect URI value
                elseif ($network.startswith('/rest/')) {
                    
                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileConnectionException InvalidNetworkUri InvalidArgument 'New-HPOVProfileConnection' -Message "The -Network value URI '$($Network)' does not begin with either '/rest/ethernet-networks', '/rest/fc-networks' or '/rest/network-sets'.  Please check the value and try again." #-verbose
		    	    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }

                #Network Name
                else {

                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User provided Network Name: $($network)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User provided ConnectionType: $($connectionType)"

		    	    #need to search by the connection type specified by the parameter
		    	    switch ($connectionType) {

                        { @("eth", "ethernet") -contains $_ } {

                            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Locating Ethernet Resource"
		    			
                            $net = Send-HPOVRequest ($script:indexUri + "?category=ethernet-networks&query=name='$network'")
		    			
		    			    #If no results were found, let's check for the Network Set
		    			    If ($net.count -eq 0) {

		    				    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Ethernet Network resource not found.  Looking for Network Set resource."
                            
                                $net = Send-HPOVRequest ($script:indexUri + "?category=network-sets&query=name='$network'")
		    			    }

                            $connection.functionType = "Ethernet"

		    		    }
		    		    
                        { @("FC", "fibre","fibrechannel") -contains $_ } {

		    			    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Locating FibreChannel Resource"

                            $net = Send-HPOVRequest ($script:indexUri + "?category=fc-networks&query=name='$network'")

                            $connection.functionType = "FibreChannel"

		    		    }

		    	    }

                }
		    	
		        If ($net.count -eq 0) {

		    	    ConvertTo-Json -InputObject $net -Depth 99 | Write-Verbose

                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileConnectionException NetworkResourceNotFound ObjectNotFound 'New-HPOVProfileConnection' -Message "$Network was not found.  Please check the name and try again." #-verbose
		    	    $PSCmdlet.ThrowTerminatingError($errorRecord)

		        }
		        elseif ($resp.count -gt 1) {

		    	    ConvertTo-Json -InputObject $net -Depth 99 | Write-Verbose

                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileConnectionException NonUniqueResultFound InvalidResult 'New-HPOVProfileConnection' -Message "$Network is not unique.  Found $($net.count) objects with the same name.  Use either Get-HPOVNetwork or Get-HPOVNetworkSet to return the specific Ethernet object." #-verbose
		    	    $PSCmdlet.ThrowTerminatingError($errorRecord)

		        }
		    
		        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] NETWORK URI: $($net.members.uri)"

		        If ($resp.members.category -eq "ethernet-networks"){

		    	    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ETHERNET VLAN ID: $($net.members.attributes.vlan_id)"

		        }
		    
		        $connection.networkUri = $net.members.uri

            }

            "PSCustomObject" {

                if ($network.category -eq "fc-networks" -or $network.category -eq "ethernet-networks" -or $network.category -eq "network-sets") {
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network resource provided via parameter"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Name:  $($network.name)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Category:  $($network.category)"
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User specified '$($connectionType)' ConnectionType"

			        $connection.networkUri = $network.uri
			
			        #If the object type is "network-set", we need to set the networkType to Ethernet as Network-Set is not a valid Connection Type.
			        if (($network.type -eq "network-set") -or ($network.type -eq "ethernet-networkV2")){

                        $connection.functionType = "Ethernet"
                        
			        }

			        elseif($network.type -eq "fc-networkV2"){

                        $connection.functionType = "FibreChannel"
			        }
                
                }

                #Generate Error due to incorrect cagtegory
                else {

                    $errorRecord = New-ErrorRecord HPOneView.ServerProfileConnectionException InvalidNetworkCategory InvalidArgument 'New-HPOVProfileConnection' -Message "The -Network value category '$($Network.category)' is not 'ethernet-networks', 'fc-networks' or 'network-sets'.  Please check the value and try again." #-verbose
		    	    $PSCmdlet.ThrowTerminatingError($errorRecord)

                }

            }

        }
	
		#write an error and break if the network category does not match the connection type requested
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Network Type: $($connection.functionType)"

		If ($connection.functionType -ne $connectionType){

            $errorRecord = New-ErrorRecord InvalidOperationException NetworkTypeMismatch InvalidOperation 'New-HPOVProfileConnection' -Message "$Network type '$($connection.functionType)' is a mismatch to the requested connection type $connectionType. Please provide a valid connection type that matches the network." #-verbose
			$PSCmdlet.ThrowTerminatingError($errorRecord)

		}
		
		#Set conneciton boot settings
        if ($bootable) {

            $connection.boot.priority = $priority

            if ($connectionType -eq 'fibrechannel') {

                
			    If(!$arrayWwpn){
				
                    $errorRecord = New-ErrorRecord ArgumentNullException InvalidFcBootParameters InvalidArgument 'New-HPOVProfileConnection' -Message "FC Boot specified, and no array target WWPN is provided." #-verbose
			        $PSCmdlet.ThrowTerminatingError($errorRecord)

			    }

                $bootTagets = @(
                    
                    @{
                        arrayWwpn = $arrayWwpn;
                        lun       = ($lun.ToString())

                    }

                )

            }

        }

		if ($userDefined){

			if ($connectionType -eq "Ethernet"){

    			$connection | Add-Member -type NoteProperty -Name macType -Value "UserDefined" -force
				$connection | Add-Member -type NoteProperty -Name mac -Value $mac -force

			}

			if ($connectionType -eq "FibreChannel"){

				$connection | Add-Member -type NoteProperty -Name macType -Value "UserDefined" -force
				$connection | Add-Member -type NoteProperty -Name mac -Value $mac -force
                $connection | Add-Member -type NoteProperty -Name wwpnType -Value "UserDefined" -force
				$connection | Add-Member -type NoteProperty -Name wwnn -Value $wwnn -force
                $connection | Add-Member -type NoteProperty -Name wwpn -Value $wwpn -force

			}
			
			return $connection

		}

		else{

			return $connection

		}

	}

}

function New-HPOVProfileAttachVolume {

    # .ExternalHelp HPOneView.110.psm1-help.xml
	
	[CmdLetBinding(DefaultParameterSetName = "Default")]
    Param (

        [parameter(Mandatory = $true, ParameterSetName = "Default")]
        [parameter(Mandatory = $True, ParameterSetName = "ManualLunIdType")]
		[ValidateNotNullOrEmpty()]
	    [parameter(Position=0)]
		[Alias('id')]
        [int]$VolumeID = 1,

        [parameter(Mandatory = $true, ValueFromPipeline = $True, ParameterSetName="Default")]
        [parameter(Mandatory = $True, ValueFromPipeline = $True, ParameterSetName="ManualLunIdType")]
		[ValidateNotNullOrEmpty()]
	    [parameter(Position=1)]
        [object]$Volume = $Null,

        [parameter(Mandatory = $False, ParameterSetName = "Default")]
        [parameter(Mandatory = $True, ParameterSetName = "ManualLunIdType")]	
        [ValidateNotNullOrEmpty()]
	    [ValidateSet("Auto","Manual", IgnoreCase=$False)]
        [parameter(Position=2)]   
		[Alias('type')]
        [string]$LunIdType="Auto",

        [parameter(Mandatory = $True, ParameterSetName = "ManualLunIdType")]
		[ValidateRange(0,254)]
	    [parameter(Position=3)]
        [int]$LunID,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "ManualLunIdType")]
		[ValidateRange(1,32)]
	    [parameter(Position=4)]
        [int]$ProfileConnectionID

	)
	
	Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'New-HPOVProfileAttachVolume' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
		
		Write-Verbose -message ("ParameterSet: " + $PsCmdLet.ParameterSetName)

        if ($LunIdType -eq "Manual" -and -not $PSBoundParameters.ContainsKey("LunId")) { 
        
            $errorRecord = New-ErrorRecord ArgumentNullException ParametersNotSpecified InvalidArgument 'New-HPOVProfileAttachVolume' -Message "'Manual' LunIdType was specified, but no LUN ID value was provided.  Please include the -LunId parameter or a value in the parameters position and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if ($LunIdType -eq "Auto" -and $PSBoundParameters.ContainsKey("LunId")) { 
        
            $errorRecord = New-ErrorRecord ArgumentException ParametersSpecifiedCollision InvalidArgument 'New-HPOVProfileAttachVolume' -Message "'Auto' LunIdType was and a specific LUN ID were provided.  Please either specify -LunIdType 'Manual' or omit the -LunId parameter and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

	Process {

        $volumeAttachment = [PsCustomObject]@{
            id = $VolumeID;
            lunType = $LunIdType;
            volumeUri = $null;
            #volumeStoragePoolUri = $Null;
            #volumeStorageSystemUri = $Null;
            storagePaths = @()

        }

        if ($volume -is [String] -and -not $volume.StartsWith($script:storageVolumeUri)) {
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Volume Name was provided."
            $tmpVolumeName = $volume
            $volume = Get-HPOVStorageVolume $volume

            if (! $volume) {

                $errorRecord = New-ErrorRecord InvalidOperationException StorageVolumeResourceNotFound ObjectNotFound 'New-HPOVProfileAttachVolume' -Message "Storage Volume name '$tmpVolumeName' was not found. Check the name and try again." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }
            		
        }

        elseif ($volume -is [String] -and $volume.StartsWith($script:storageVolumeUri)) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Volume URI was provided."
            $tmpVolumeUri = $volume
            $volume = Send-HPOVRequest $volume

            if ($volume.errorCode -and [int]$volume.statusCode -eq 404) {

                $errorRecord = New-ErrorRecord InvalidOperationException StorageVolumeResourceNotFound ObjectNotFound 'New-HPOVProfileAttachVolume' -Message "Storage Volume URI '$tmpVolumeUri' was not found. Check the value and try again." #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }
            elseif ($volume.errorCode) {

                $errorRecord = New-ErrorRecord InvalidOperationException $volume.errorCode InvalidResult 'New-HPOVProfileAttachVolume' -Message $volume.message #-verbose
                $PSCmdlet.ThrowTerminatingError($errorRecord)

            }

        }

        elseif ($volume -is [String]) {

            #Volume parameter value is not valid, generate error.
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'New-HPOVProfileAttachVolume' -Message "The Volume parameter contains an invalid value.  Please check it and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        $volumeAttachment.volumeUri = $volume.uri
        #$volumeAttachment.volumeStoragePoolUri = $volume.storagePoolUri
        #$volumeAttachment.volumeStorageSystemUri = $volume.storageSystemUri

        if ($LunIdType -eq "Manual") { $volumeAttachment | Add-Member -type NoteProperty -Name "lun" -value $LunID }

	}

    end {

        return $volumeAttachment
    }

}

#######################################################
# Index: 
#

function Search-HPOVIndex  {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
       [parameter (Mandatory = $false)]
       [string]$search=$null,

       [parameter (Mandatory = $false)]
       [string]$category=$null,

       [parameter (Mandatory = $false)]
       [int]$count=50,

       [parameter (Mandatory = $false)]
       [int]$start=0
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Search-HPOVIndex' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        #"/rest/index/resources?category=fc-networks=&count=50&start=0&query=name:%22fabric%20a%22"

        $uri = $indexuri + '?start=' + $start.ToString() + '&count=' + $count.ToString()
        
        if ($search) { $uri = $uri + "&userQuery=" + $search }
        
        if ($category) { $uri = $uri + "&category=" + $category }
        
        $uri = $uri.Replace(" ", "%20")
        
        $r = Send-HPOVRequest $uri
        
        if ($r.count -eq 0) {

            $errorRecord = New-ErrorRecord InvalidOperationException NoIndexResults ObjectNotFound 'Search-HPOVIndex' -Message "No Index results found." #-verbose
            $pscmdlet.WriteError($errorRecord)
        }

        else {
            #Set-DefaultDisplay $r.members -defProps 'name', 'category', 'attributes'
            
            $r.members
            "Done. {0} index resource(s) found." -f $r.count | out-host

        }
    }

}

function Search-HPOVAssociations {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
       [parameter (Mandatory = $false,Position=0)]
       [string]$associationName=$null,

       [parameter (Mandatory = $false,Position=1)]
       [string]$startObjUri=$null,

       [parameter (Mandatory = $false,Position=2)]
       [string]$endObjUri=$null,

       [parameter (Mandatory = $false,Position=3)]
       [int]$count=50,

       [parameter (Mandatory = $false,Position=4)]
       [int]$start=0
    )    

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Search-HPOVIndex' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $uri = $associationsUri + '?start=' + $start.ToString() + '&count=' + $count.ToString()

        if ($associationName) { $uri = $uri + "&name=" + $associationName }
        
        if ($startObjUri) {$uri = $uri + "&startObjUri=" + $startObjUri }
        
        if ($endObjUri) {$uri = $uri + "&endObjUri=" + $endObjUri }
        
        $uri = $uri.Replace(" ", "%20")
        
        $r = Send-HPOVRequest $uri
        
        return $r
    }

}

#######################################################
# Tasks:
#

function Get-HPOVTask {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = "Default")]
	Param (
		[parameter(Mandatory = $false, HelpMessage = "Enter the name of the Task", ParameterSetName = "Default")]
        [parameter(Mandatory = $false, HelpMessage = "Enter the name of the Task", ParameterSetName = "ResourceCategory")]
        [Alias("name")]
		[string]$TaskName = $Null,

        [parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Enter the resource you want to find tasks associated with.", ParameterSetName = "Default")]
        [Object]$Resource = $Null,

        [parameter(Mandatory = $false, HelpMessage = "Please specify the Resource Category the task (i.e. 'ethernet-networks', 'fc-networks', 'server-profiles', etc..)", ParameterSetName = "ResourceCategory")]
        [Alias("Category")]
        [String]$ResourceCategory = $Null,

        [parameter(Mandatory = $false, HelpMessage = "Please specify the State of the task (i.e. Completed.)", ParameterSetName = "Default")]
        [parameter(Mandatory = $false, HelpMessage = "Please specify the State of the task (i.e. Completed.)", ParameterSetName = "ResourceCategory")]
        [ValidateSet("Unknown","New","Running","Suspended","Terminated","Killed","Completed","Error","Warning")]
        [string]$State = $Null,

        [parameter(Mandatory = $false, HelpMessage = "Please specify the amount of task objects to return.", ParameterSetName = "Default")]
        [parameter(Mandatory = $false, HelpMessage = "Please specify the amount of task objects to return.", ParameterSetName = "ResourceCategory")]
        [ValidateScript({ if ([int]$_ -gt -1) {$true}
                          else {Throw "The Count Parameter value '$_' is invalid."}})]
        [Int]$Count = 0,

        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [parameter(Mandatory = $false, ParameterSetName = "ResourceCategory")]
        [switch]$List
	)

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Called from: $($pscmdlet.CommandOrigin)"
    
        #Check to make sure the user is authenticated
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVTask" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }
	
    Process {

        $uri = $allNonHiddenTaskUri

        if ($TaskName) { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Name parameter value: $($TaskName)"
            $Uri += "?filter=name='$TaskName'" 
        
        }

        if ($State) { 
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] State parameter value: $($State)"
            if ($Uri) { $Uri += "&filter=taskState='$State'" }
            else { $Uri = "?filter=taskState='$State'" }
        }
        if ($count) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Count parameter value: $($Count)"
            if ($Uri) { $Uri += "&count=$Count&sort=created:descending" }
            else { $Uri = "?count=$Count&sort=created:descending" }

        }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Parameter Set Name resolved to: $($PSCmdlet.ParameterSetName)"

        switch ($PSCmdlet.ParameterSetName) {

            "Default" {
				Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource value:  $Resource"
                if ($Resource) {

                    #If the Resource value is a Name
                    if (($Resource -is [string]) -and (-not $Resource.StartsWith("/rest/"))) {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource parameter Name: $($Resource)"
                        if ($Uri) { $Uri += "&filter=associatedResource.resourceName='$Resource'" }
                        else { $Uri = "?filter=associatedResource.resourceName='$Resource'" }

                    }

                    #Checking if the input is System.String and IS a URI
                    elseif (($Resource -is [string]) -and ($Resource.StartsWith("/rest/"))) {
            
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource parameter URI: $($Resource)"
                        if ($Uri) { $Uri += "&filter=associatedResource.resourceUri='$Resource'" }
                        else { $Uri = "?filter=associatedResource.resourceUri='$Resource'" }
        
                    }

                    #Checking if the input is PSCustomObject, and the category type is not null, which would be passed via pipeline input
                    elseif (($Resource -is [System.Management.Automation.PSCustomObject]) -and ($Resource.category)) {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource is an object: '$($Resource.name)' of type '$($Resource.Category)'"
                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Using URI value ($($Resource.Uri)) from input object."
                        if ($Uri) { $Uri += "&filter=associatedResource.resourceUri='$($Resource.Uri)'" }
                        else { $Uri = "?filter=associatedResource.resourceUri='$($Resource.Uri)'" }
                    }

					else { 
                        $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Get-HPOVTask' -Message "The Resource input parameter was not recognized as a valid type or format." #-verbose
                        $pscmdlet.ThrowTerminatingError($errorRecord)
						#Write-Error "The Resource input parameter was not recognized as a valid type or format." -Category InvalidArgument -CategoryTargetName "Get-HPOVTask"
						#Break
					}
					
                }

            } #End Default
            
            "ResourceCategory" { 
            
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource Category was specified:  $($ResourceCategory)"
                if ($Uri) { $Uri += "&filter=associatedResource.resourceCategory='$($ResourceCategory)'" }
                else { $Uri = "?filter=associatedResource.resourceCategory='$($ResourceCategory)'" }

            } #End ResourceCategory

        } #End switch

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] URI: $($Uri)"

        if ($Count -gt 0 ) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting $($Count) task objects." }
        else { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] ($($Count)) Returning all available task objects." }

        try {
        
            $tasks = Send-HPOVRequest $Uri

            if ($tasks.statusCode) {
            
                switch ($tasks.message) {

                    #Write-Error "$($tasks.details)  $($tasks.recommendedActions)" -Category ObjectNotFound -RecommendedAction $($tasks.recommendedActions) -CategoryTargetName "Get-HPOVTask" }
                    "Not Found" { $errorRecord = New-ErrorRecord InvalidOperationException TaskNotFound ObjectNotFound 'Get-HPOVTask' -Message "$($tasks.details)  $($tasks.recommendedActions)" }
                    default { $errorRecord = New-ErrorRecord InvalidOperationException InvalidResult InvalidResult 'Get-HPOVTask' -Message "$($tasks.details)  $($tasks.recommendedActions)" }

                }

                $pscmdlet.ThrowTerminatingError($errorRecord)
            }

            else {

                if ($tasks.count -eq 0) { 
                
                    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No tasks found."
                    #$errorRecord = New-ErrorRecord InvalidOperationException TaskNotFound ObjectNotFound 'Get-HPOVTask'0 -Message "No tasks found "
                    #$pscmdlet.ThrowTerminatingError($errorRecord)
                    #Write-Error "No task objects found." -Category ObjectNotFound -CategoryTargetName "Get-HPOVTask" -RecommendedAction "No task objects found.  Please verify the parameters you chose, and try again." 
                    
                }
                else { 
                
                    if ($list) {

                        $t = @{Expression={$_.name};Label="Name"},
                             @{Expression={$_.taskState};Label="State"},
                             @{Expression={
                                if ($_.associatedResource.resourceName) { $_.associatedResource.resourceName }
                                else { 
                                    if ($_.progressUpdates.statusUpdate) { $_.progressUpdates.statusUpdate }
                                    elseif ($_.taskState -eq "Error") { $_.taskStatus }
                                
                                }
                                  
                             };Label="Resource"},
                             @{Expression={$_.computedPercentComplete};Label="% Complete"},
                             @{Expression={(get-date $_.created -f G) };Label="Started"},
                             @{Expression={(get-date $_.modified -f G) };Label="Last Updated"}
                        
                        $tasks.members | format-table $t -wrap
                        

                    }
                    else { $tasks.members }

                    "Done. {0} task resource(s) found." -f $tasks.count | out-host
                    
                }

            }

        }

        catch {

            write-error "well, that didn't work"
        }

    }

}

#DEPRECATED CMDLET
function Wait-HPOVTaskAccepted  {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param(
		[parameter(Mandatory = $true, ValueFromPipeline = $True, HelpMessage = "Enter the task URI or task object")]
		[Alias('taskuri')]
        [object]$task,

        [parameter(Mandatory = $false,HelpMessage = "Enter the new value for the global parameter")]
        [timespan]$timeout=$script:defaultTimeout
	)

    Begin {
        
        Write-Warning "The 'Wait-HPOVTaskAccepted' CMDLET has been deprecated.  Task Acceptance is now handlded via HTTP Response 202, which Send-HPOVRequest handles. Please use Wait-HPOVTaskStart to monitor a task progression into the Running state without waiting for the task to fully complete execution."

    }

    Process {

    }

}

function Wait-HPOVTaskStart  {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param (
		[parameter(Mandatory = $true,ValueFromPipeline = $True, HelpMessage = "Enter the task URI or task object")]
		[Alias('taskuri')]
        [object]$task,

        [parameter(Mandatory = $false,HelpMessage = "Provide the resource name the task is for, which is displayed in the Write-Progress output.")]
        [string]$resourceName,

        [parameter(Mandatory = $false,HelpMessage = "Enter the new value for the global parameter")]
        [timespan]$timeout=$script:defaultTimeout
	) 

    Begin {
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Called from: $($pscmdlet.CommandOrigin)"

        if (-not $PSBoundParameters['task']) { $PipelineInput = $True }
    
        #Check to make sure the user is authenticated
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Verify auth"
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Wait-HPOVTaskStart" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        if ($PipelineInput -and $task) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task resource passed via pipeline input." }

        #Validate the task object
        if (($task -is [String]) -and ($task.StartsWith($script:taskUri))) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task is System.String $($task)"
        }
        elseif (($task -is [PSCustomObject]) -and ($task.category -ieq 'tasks')) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task is $($task.GetType()). Task URI: $($task.uri)"
            $task = $task.uri
        }
        else {

            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Wait-HPOVTaskStart' -Message "Invalid task.  Please verify the task object you are passing and try again." #-verbose
            $PSCmdLet.ThrowTerminatingError($errorRecord)

        }

        $sw = [diagnostics.stopwatch]::StartNew()
        $taskObj = Send-HPOVRequest $task

        $i = 0

        #If there is an error retrieving the task resource (anything that is not HTTP 200, 201 or 202), generate error.
        if ([int]$taskObj.statusCode -ge 300) { 

            switch ($taskObj.statusCode) {

                #Task Not Found via HTTP 404
                404 { $errorRecord = New-ErrorRecord InvalidOperationException TaskResourceNotFound ObjectNotFound 'Wait-HPOVTaskComplete' -Message "$($taskObj.message)" }
                
                #Default handler for 
                default { $errorRecord = New-ErrorRecord InvalidOperationException $taskObj.errorCode InvalidResult 'Wait-HPOVTaskComplete' -Message "$($taskObj.message)"  }

            }

            $pscmdlet.ThrowTerminatingError($errorRecord)
            
        }


        if ($resourceName) { $taskname = "Waiting for '$($taskObj.name) $resourceName' task to start"}
        else { $taskName = "Waiting for '$($taskObj.name)' task to start" }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Waiting for $taskName to start..."
        while($taskObj.taskState -and ($taskObj.taskState -ieq "Adding" -or $taskObj.taskState -ieq "New" -or $taskObj.taskState -ieq "Starting")) {
            
            if ($sw.Elapsed -gt $timeout) {
                
                $errorRecord = New-ErrorRecord InvalidOperationException TaskWaitExceededTimeout OperationTimeout  'Wait-HPOVTaskStart' -Message "The time-out period expired before waiting for task '$taskName' to start." #-verbos
                $PsCmdlet.ThrowTerminatingError($errorRecord)

            }

            #Display Progress Bar
            
            #Handle the call from -Verbose so Write-Progress does not get borked on display.
            if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Skipping Write-Progress display."  }
             
            else {

                #Display the task status
                
                if ($taskObj.expectedDuration) { Write-Progress -activity $taskName -status $taskObj.taskStatus -percentComplete ($i / $taskObj.expectedDuration * 100) }
                else { Write-Progress -activity $taskName -status $taskObj.taskStatus -percentComplete $taskObj.percentComplete }
                
            }

            Start-Sleep 1
            $i++

            $taskObj = Send-HPOVRequest $task
        }

    }

    End {
    
        Write-Progress -activity $taskName -Completed

        $taskObj
    }

}

function Wait-HPOVTaskComplete {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param(
		[parameter(ValueFromPipeline = $true, Mandatory = $true, HelpMessage = "Enter the task URI or task object")]
		[Alias('taskuri')]
        [object]$task,

        [parameter(Mandatory = $false, HelpMessage = "Enter the new value for the global parameter")]
        [timespan]$timeout = $script:defaultTimeout
	)

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Called from: $($pscmdlet.CommandOrigin)"

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Wait-HPOVTaskComplete" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if (-not $PSBoundParameters['task']) { $PipelineInput = $True }

    }

    Process {

        if ($PipelineInput -and $task) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task resource passed via pipeline input." }
        
        #Validate the task object 
        if (($task -is [String]) -and ($task.StartsWith($script:taskUri))) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task is System.String $($task)"
        }
        elseif (($task -is [PSCustomObject] -or $task -is [Hashtable]) -and ($task.category -ieq 'tasks')) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Task is $($task.GetType()). Task URI: $($task.uri)"
            $task = $task.uri
        }
        else {
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Wait-HPOVTaskStart' -Message "Invalid task.  Please verify the task object you are passing and try again." #-verbose
            $PSCmdLet.ThrowTerminatingError($errorRecord)
            #Write-Error "Invalid task.  Please verify the task object you are passing and try again." -Category InvalidType -CategoryTargetName "Wait-HPOVTaskComplete" -ErrorAction Stop
        }
        
        $sw = [diagnostics.stopwatch]::StartNew()
        $taskObj = Send-HPOVRequest $task

        #If there is an error retrieving the task resource (anything that is not HTTP 200, 201 or 202), generate error.
        if ([int]$taskObj.statusCode -ge 300) { 

            switch ($taskObj.statusCode) {

                #Task Not Found via HTTP 404
                404 { $errorRecord = New-ErrorRecord InvalidOperationException TaskResourceNotFound ObjectNotFound 'Wait-HPOVTaskComplete' -Message "$($taskObj.message)" }
                
                #Default handler for 
                default { $errorRecord = New-ErrorRecord InvalidOperationException $taskObj.errorCode InvalidResult 'Wait-HPOVTaskComplete' -Message "$($taskObj.message)"  }

            }

            $pscmdlet.ThrowTerminatingError($errorRecord)
            
        }

        write-host "Waiting for $($taskObj.name) ($($taskObj.associatedResource.resourceName)) to complete..."
        while($taskObj.taskState -and $taskObj.taskState -ine "Error" -and 
              $taskObj.taskState -ine "Warning" -and $taskObj.taskState -ine "Completed" -and 
              $taskObj.taskState -ine "Terminated" -and $taskObj.taskState -ine "Killed") {

            if ($sw.Elapsed -gt $timeout) {
                
                $errorRecord = New-ErrorRecord InvalidOperationException TaskWaitExceededTimeout OperationTimeout  'Wait-HPOVTaskComplet' -Message "The time-out period expired before waiting for task '$taskName' to start." #-verbos
                $PsCmdlet.ThrowTerminatingError($errorRecord)

            }

            #Display Progress Bar
            
            #Handle the call from -Verbose so Write-Progress does not get borked on display.
            if ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Skipping Write-Progress display."  }
             
            else {

                #Display the task status, and associated child tasks
                if ($taskObj.progressUpdates) { 

                    #Child task is executing, display reported status
                    If ($taskObj.progressUpdates[-1].statusUpdate) {
                        Write-Progress -activity "$($taskObj.name) ($($taskObj.associatedResource.resourceName))" -status $taskObj.progressUpdates[-1].statusUpdate -percentComplete $taskObj.computedPercentComplete
                    }

                    #There is a child task, but it's statusUpdate value is NULL, so just display the parent task status
                    else {
                     
                        Write-Progress -activity "$($taskObj.name) ($($taskObj.associatedResource.resourceName))" -status $taskObj.taskStatus -percentComplete $taskObj.percentComplete
                    }
                }

                #Just display the task status, as it has no child tasks
                elseif ($taskObj.taskStatus) { Write-Progress -activity $taskObj.name -status $taskObj.taskStatus -percentComplete $taskObj.percentComplete }
                else { Write-Progress -activity $taskObj.name -status $taskObj.taskState -percentComplete $taskObj.percentComplete }
            }

            $taskObj = Send-HPOVRequest $task
        }
        
    }

    End {
    
        Write-Progress -activity $taskObj.name -Completed

        $taskObj
    }

}

#######################################################
# Securty and LDAP Functions
#

function Get-HPOVUser {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdLetBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [string]$Name=$null,

        [Parameter(Mandatory = $false)]
        [Alias('list')]
        [switch]$Report
    )
	
    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

	    [array]$req = Send-HPOVRequest ($usersUri+"?sort=username:asc")

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Found $($req.count) user resources."

        $users = $req.members | select-object -Property * -excludeproperty uri,etag,created,modified,status,state,Uri,type,name,category

        if ($Name) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Filtering for '$name' user."
        
            $users = $users | Where-Object {$_.userName -eq $Name} 
            
            if (! $users) {
            
                #Generate terminating error
                $errorRecord = New-ErrorRecord InvalidOperationException UserNotFound ObjectNotFound 'Get-HPOVUser' -Message "Username `'$Name`' was not found. Please check the spelling, or create the user and try again."
                $pscmdlet.ThrowTerminatingError($errorRecord)
            }    
        }
        
        if ($report) {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Displaying report."
            $a = @{Expression={$_.userName};Label="Username"}, `
                 @{Expression={$_.fullName};Label="Full Name"}, `
                 @{Expression={$_.description};Label="Description"}, `
                 @{Expression={ 
                    
                     if ($_.roles.count -gt 0) { 

                         [array]::sort($_.roles)
                         $_.roles
                     }
                
                     else { "None" }
                    
                 };Label="Roles"}, `
                 @{Expression={$_.emailAddress};Label="Email Address"}, `
                 @{Expression={$_.officePhone};Label="Office Phone"}, `
                 @{Expression={$_.mobilePhone};Label="Mobile Phone"}, `
                 @{Expression={$_.enabled};Label="Enabled"}

            $users | Sort-Object -property userName | format-table $a -wrap #-autosize

        }

        else {
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] returning account resource objects."
            if ($users.length -eq 1 ) { $users[0] }
            else { $users }

        }

        "Done. {0} user(s) found." -f $req.count | out-host 

    }
}

function New-HPOVUser {
	 
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param (
        [parameter(Mandatory = $true)]
        [string]$userName, 

        [parameter(Mandatory = $true)]
        [string]$password, 

        [parameter(Mandatory = $false)]
        [string]$fullName, 

        [parameter(Mandatory = $true)]
        [array]$roles=@(),

        [parameter(Mandatory = $false)]
        [validatescript({$_ -as [Net.Mail.MailAddress]})]
        [string]$emailAddress=$null,

        [parameter(Mandatory = $false)] 
        [string]$officePhone=$null,
     
        [parameter(Mandatory = $false)]
        [string]$mobilePhone=$null,
     
        [parameter(Mandatory = $false)]
        [switch]$enabled
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #Validate roles provided are allowed.
        [Array]$unsupportedRoles = @()

        foreach ($role in $roles) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $role"
            $script:applSecurityRoles -contains $role
            if (-not ($script:applSecurityRoles -contains $role)) { [array]$unsupportedRoles += $role }

        }

        if ($unsupportedRoles.count -eq 1) { 
        
            $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "New-HPOVUser" -Message "The '$($unsupportedRoles -join ", ")' role is not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
            $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
        }
        elseif ($unsupportedRoles.count -gt 1) { 
        
            $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "New-HPOVUser" -Message "The '$($unsupportedRoles -join ", ")' roles are not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
            $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
        }

        #Need to make sure role name is first letter capitalized only.
        $i = 0

        foreach ($role in $roles) {

            $roles[$i] = $role.substring(0,1).ToUpper()+$role.substring(1).tolower()
            $i++

        }

        $user = [PsCustomObject]@{
            type = "UserAndRoles";
            userName = $userName; 
            fullName = $fullName; 
            password = $password; 
            emailAddress = $emailAddress; 
            officePhone = $officePhone; 
            mobilePhone = $mobilePhone; 
            enabled = [bool]$enabled; #Needs to be changed to [bool] data type
            roles = $roles}
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User requested to create:  $($user | out-string )"
    }

    Process {

        #$user = New-HPOVResource $usersUri $user
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to create $($user.userName) user"
        Send-HPOVRequest $usersUri POST $user

    }

}

function Set-HPOVUser {
	 
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param (
        [parameter(Position = 0, Mandatory = $true)]
        [string]$userName, 

        [parameter(Position = 1, Mandatory = $false)]
        [string]$password, 

        [parameter(Position = 2, Mandatory = $false)]
        [string]$fullName, 

        [parameter(Position = 3, Mandatory = $false)]
        [array]$roles=@(),

        [parameter(Position = 4, Mandatory = $false)]
        [validatescript({$_ -as [Net.Mail.MailAddress]})]
        [string]$emailAddress=$null,

        [parameter(Position = 5, Mandatory = $false)] 
        [string]$officePhone=$null,
     
        [parameter(Position = 6, Mandatory = $false)]
        [string]$mobilePhone=$null,
     
        [parameter(Position = 7, Mandatory = $false)]
        [alias('enable')]
        [switch]$enabled,

        [parameter(Position = 8, Mandatory = $false)]
        [alias('disable')]
        [switch]$disabled
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Set-HPOVResource" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #try to locate the user object to update
        try { $updateUser = Get-HPOVUser $userName }
        
        #If not found, throw error
        catch [InvalidOperationException] {
        
            #Generate terminating error
            $errorRecord = New-ErrorRecord InvalidOperationException UserNotFound ObjectNotFound 'Set-HPOVUser' -Message "Username `'$userName`' was not found. Please check the spelling, or create the user and try again."
            $pscmdlet.ThrowTerminatingError($errorRecord)
        
        }

        #Use to control if we use another API call to pass no changes to the user object.
        $ProcessFlag = $False
        
        switch ($PSBoundParameters.keys) {

            "password" { 

                if ($userName -eq $global:cimgmtSessionId.UserName -and $password) {

                    write-warning "This CMDLET will not modify the password for your account.  Please use the Set-HPOVUserPassword CMDLET to update your user account password.  Password update will not be processed."
                    $password = $Null

                }            
                else { $updateUser | Add-Member -NotePropertyName password -NotePropertyValue $password; $ProcessFlag = $true } 
                
            }
            "fullName" { $updateUser.fullName = $fullName; $ProcessFlag = $true }
            "roles" {

                if ($userName -eq $global:cimgmtSessionId.UserName -and $roles) {

                    write-warning "Unable to modify roles for your account, as you must be authenticated to the appliance with a different administrator account.  Roles will not be processed."

                }
                else {
                
                    $updateUser | add-member -NotePropertyName replaceRoles -NotePropertyValue $True

                    #Validate roles provided are allowed.
                    [Array]$unsupportedRoles = @()

                    foreach ($role in $roles) {

                        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $role"
                        $script:applSecurityRoles -contains $role
                        if (-not ($script:applSecurityRoles -contains $role)) { [array]$unsupportedRoles += $role }

                    }

                    if ($unsupportedRoles.count -eq 1) { 
        
                        $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "Set-HPOVUser" -Message "The '$($unsupportedRoles -join ", ")' role is not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
                        $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
                    }
                    elseif ($unsupportedRoles.count -gt 1) { 
        
                        $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "Set-HPOVUser" -Message "The '$($unsupportedRoles -join ", ")' roles are not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
                        $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
                    }

                    #Need to make sure role name is first letter capitalized only.
                    $i = 0

                    foreach ($role in $roles) {
                        $roles[$i] = $role.substring(0,1).ToUpper()+$role.substring(1).tolower()
                        $i++
                    }

                }

            }
            "emailAddress" { $updateUser.emailAddress = $emailAddress; $ProcessFlag = $true }
            "officePhone" { $updateUser.officePhone = $officePhone; $ProcessFlag = $true }
            "mobilePhone" { $updateUser.mobilePhone = $mobilePhone; $ProcessFlag = $true }
            "enabled" { 
                
                if ($userName -eq $global:cimgmtSessionId.UserName -and [bool]$enabled) {

                    write-warning "This CMDLET will not modify the state for your account.  Please authenticate to the appliance with a different administrator account.  Account state will not be processed."

                }
                else { $updateUser.enabled = $true; $ProcessFlag = $true }

            }
            "disabled" { 

                if ($userName -eq $global:cimgmtSessionId.UserName -and [bool]$disabled) {

                    write-warning "This CMDLET will not modify the state for your account.  Please authenticate to the appliance with a different administrator account.  Account state will not be processed."

                }
                else { $updateUser.enabled = $false; $ProcessFlag = $true }

            }

        }

    }

    Process {

        #Process account update request
        if ($ProcessFlag) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] User requested to update:  $($updateUser | out-string)"

            $updateUser | Add-Member -NotePropertyName type -NotePropertyValue 'UserAndRoles'
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Sending request to update `'$($updateUser.userName)`' user at '$($script:usersUri)'"
            $resp = Send-HPOVRequest $script:usersUri PUT $updateUser 

        }

        #Do nothing
        else {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] No work to be done."

        }

    }

    end {

        $resp

    }

}

function Set-HPOVUserPassword {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	Param (

        [parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $false)]
        [String]$currentPassword,

        [parameter(Position = 1, Mandatory = $false, ValueFromPipeline = $False)]
        [String]$newPassword

    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Set-HPOVResource" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if (-not ($PSBoundParameters['currentPassword'])) { $ValueFromPipeline = $True }
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting password for user: $($global:cimgmtSessionId.UserName)"

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Current Password was provided via pipeline: $([bool]$ValueFromPipeline)"

        #Prompt user for current password if not provided
        if (-not ($currentPassword)) { 
        
            $currentPassword = Read-Host -AsSecureString "Current Password"
            $decryptCurrentPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($currentPassword))

        }
        else { $decryptCurrentPassword = $currentPassword }

        #Prompt user for new password if not provided
        if (-not ($newPassword)) { 
        
            Do {

                $newPassword = Read-Host -AsSecureString "New Password"
                $compareNewPassword = Read-Host -AsSecureString "Re-type New Password"
                
                #Compare provided password matches
                $decryptNewPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword))
                $decryptcompareNewPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($compareNewPassword))

                if (-not ($decryptNewPassword -eq $decryptcompareNewPassword)) {

                    $errorRecord = New-ErrorRecord HPOneview.Appliance.PasswordMismatch NewPasswordsDoNotMatch InvalidResult 'Set-HPOVUserPassword' -Message "The new password values do not match. Please try again." #-verbose
                    $PSCmdlet.WriteError($errorRecord)

                }

                if (-not ($decryptNewPassword.length -ge 8) -or -not ($decryptcompareNewPassword -ge 8)) {
                
                    $errorRecord = New-ErrorRecord HPOneview.Appliance.PasswordMismatch NewPasswordLengthTooShort InvalidResult 'Set-HPOVUserPassword' -Message "The new password value do not meet the minimum character length of 8. Please try again." #-verbose
                    $PSCmdlet.WriteError($errorRecord)

                }

            } Until ( $decryptNewPassword -eq $decryptcompareNewPassword -and $decryptNewPassword.length -ge 8 -and $decryptNewPassword -ne $decryptCurrentPassword)
        }
        else {

            $decryptNewPassword = $newPassword

        }

        #Get current user object
        $currentUserObj = Get-HPOVUser $global:cimgmtSessionId.UserName

        $currentUserObj | add-member -notepropertyname currentPassword -NotePropertyValue $decryptCurrentPassword
        $currentUserObj | add-member -notepropertyname password -NotePropertyValue $decryptNewPassword
        $currentUserObj | add-member -notepropertyname replaceRoles -NotePropertyValue $false
        $currentUserObj | add-member -notepropertyname type -NotePropertyValue UserAndRoles

    }

    End {

        $resp = Send-HPOVRequest /rest/users PUT $currentUserObj

        $resp

    }

}

function Remove-HPOVUser {
	 
    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
	param(
         [parameter(Mandatory = $true,ValueFromPipeline=$false,HelpMessage = "Enter the User Account Name to delete from the appliance",Position=0, ParameterSetName = "default")]
         [ValidateNotNullOrEmpty()]
         [alias("u","user")]
         [string]$userName
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        write-verbose "[REMOVE-HPOVUSER: Attempting to remove $($userName)"
    
        if ($pscmdlet.ShouldProcess($script:HPOneViewAppliance,"Remove User `'$userName`'")) {   

            $response = Remove-HPOVResource -nameOrUri "$($usersUri)/$($userName)"
            
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] STATUS CODE RETURN: $([int]$script:lastWebResponse.statuscode)"
        
            if ([int]$script:lastWebResponse.statuscode -eq 204) {
                Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] $($userName) successfully deleted"
                write-warning "$($userName) successfully deleted"
            }
            elseif ([int]$script:lastWebResponse.statuscode -eq 404) {

                $errorRecord = New-ErrorRecord InvalidOperationException $response.errorCode ObjectNotFound 'Remove-HPOVUser' -Message "'$userName' was not found. Please check the value and try again." #-verbose
                $PsCmdlet.WriteError($errorRecord)
                
            }
        }
    }
}

function Show-HPOVUserSession {


    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default")]
    Param ()

    Begin {
    
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Show-HPOVUserSession" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }
    
    }

    Process { 
    
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Getting list of authenticated users and their sessions to the appliance."
        $resp = Send-HPOVRequest $script:activeUserSessionsUri
    }

    End {
    
        $u = @{Expression={if ($_.userName -eq $script:applianceConnectedTo.User -and ($_.loginDomain -eq $env:computername -or $_.loginDomain -eq 
(Get-WmiObject Win32_NetworkAdapterConfiguration | ? { $_.IPEnabled -eq $True })[0].IPAddress -match $script:ip4regex)) { "$($_.userName)*"} else { $_.userName } };Label="Username"},
             @{Expression={$_.loginDomain};Label="Auth Domain"},
             @{Expression={$_.clientHost};Label="Client Host"}
    
        $resp.members | sort-object -Property userName | format-table $u -AutoSize -Wrap
    
    }

}

function Get-HPOVRole {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default")]
    Param (
        [parameter (Position = 0, Mandatory = $true, ParameterSetName = "default", HelpMessage = "Specify the username.")]
        [ValidateNotNullOrEmpty()]
        [Alias("user")]
        [String]$Name = $null
	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError $($MyInvocation.InvocationName.ToString().ToUpper()) -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $uri = $userRoleUri + '/' + $Name
        $roles = Send-HPOVRequest $uri
        
        if ($name -and -not ($roles.members)) {

            $errorRecord = New-ErrorRecord HPOneView.Appliance.UserResourceException UserObjectNotFound ObjectNotFound "Name" -Message "The specified '$name' User resource not found.  Please check the name and try again." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        $roles.members | % { $_.psobject.typenames.Insert(0,”HPOneView.Appliance.UserRole") }

    }

    end {

        $roles.members

    }

}

function Set-HPOVUserRole {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param (
        [parameter (Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("user")]
        [String]$userName=$null,

        [parameter (Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [alias('roleName')]
        [array]$roles
	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Set-HPOVUserRole" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #Validate roles provided are allowed.
        [Array]$unsupportedRoles = @()

        foreach ($role in $roles) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $role"
            $script:applSecurityRoles -contains $role
            if (-not ($script:applSecurityRoles -contains $role)) { [array]$unsupportedRoles += $role }

        }

        if ($unsupportedRoles.count -eq 1) { 
        
            $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "Set-HPOVUserRole" -Message "The '$($unsupportedRoles -join ", ")' role is not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
            $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
        }
        elseif ($unsupportedRoles.count -gt 1) { 
        
            $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "Set-HPOVUserRole" -Message "The '$($unsupportedRoles -join ", ")' roles are not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
            $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
        }

        #Need to make sure role name is first letter capitalized only.
        $i = 0

        foreach ($role in $roles) {

            $roles[$i] = $role.substring(0,1).ToUpper()+$role.substring(1).tolower()
            $i++

        }

    }

    Process {

        $setUserRolesUri = "/rest/users/" + $userName + "/roles?multiResource=true"
            
        foreach ($role in $roles) {
                
            $roleObject = [PsCustomObject]@{
                roleName = $role;
                type = "RoleNameDtoV2"
            }

            [Array]$userRole += @($roleObject)

        }

        $resp = Send-HPOVRequest $setUserRolesUri PUT $userRole
    
    }

    end {

        $resp

    }

}

function Set-HPOVInitialPassword  {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = 'Default')]
    Param (

        [parameter (Position = 0, Mandatory = $true, ParameterSetName = 'Appliance')]
        [parameter (Position = 0, Mandatory = $true, ParameterSetName = 'password')]
        [ValidateNotNullOrEmpty()]
        [Alias("user")]
        [String]$userName = "Administrator",

        [parameter (Position = 1, Mandatory = $true, ParameterSetName = 'Appliance')]
        [parameter (Position = 1, Mandatory = $true, ParameterSetName = 'password')]
        [ValidateNotNullOrEmpty()]
        [string]$oldPassword,

        [parameter (Position = 2, Mandatory = $true, ParameterSetName = 'Appliance')]
        [parameter (Position = 2, Mandatory = $true, ParameterSetName = 'password')]
        [ValidateNotNullOrEmpty()]
        [string]$newPassword
	)


    Begin { }

    Process {
        
        $body = [pscustomobject]@{userName=$userName; oldPassword=$oldPassword; newPassword=$newPassword;}
        $uri = $usersUri + "/changePassword"
        $resp = Send-HPOVRequest $uri POST $body

    }

    End {

        return $resp

    }

}

function Get-HPOVLdap {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = 'Default')]
	param (
		[Parameter(Position=0, Mandatory = $false, ParameterSetName='Default')]
        [Alias('directory','domain')]
		[String]$Name,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [switch]$Report,

        [Parameter(Mandatory = $true, ParameterSetName = 'Export')]
        [Alias('x')]
        [switch]$Export,

        [Parameter(Position=1,Mandatory = $true, ParameterSetName = 'Export')]
        [Alias('location')]
        [ValidateScript({split-path $_ | Test-Path})]
        [string]$Save
	)

    begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVLdap" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

	process {
        
        #Send request to get array of global settings and directories (which contain name and URI)
        $directorySettings = Send-HPOVRequest $script:authnSettingsUri

        #Export directory settings (raw JSON) to file
        if ($export){
            Write-Verbose 'EXPORTING DIRECTORY CONFIGURATION'
            
            #Loop through each directory and get all configured settings
            ForEach ($directory in $directorySettings.configuredLoginDomains){
                $directory = Send-HPOVRequest $directory.uri
                write-verbose "SAVING TO: $($save)\$($directory.name).json"
                $directory | convertto-json > $save\$($directory.name).json
            }
        }
        
        else{
            
            "DIRECTORY SETTINGS: $($directorySettings)" | out-string | Write-Verbose

            #Build collection to reduce the number of API calls
            $colDirectories = @()
            ForEach ($directory in $directorySettings.configuredLoginDomains){
                $colDirectories += Send-HPOVRequest $directory.uri
            }

            #Display the specific Directory as a PsCustomObject
            if (($Name) -and (-not $Report)) { $colDirectories | Where-Object {$_.name -eq $name} } 
            
            #Will either display all directories or a specific directory in table format. Does not display URI and is System.Array
            elseif ((($List) -and ($Name)) -or ($Report)) {

                $dispDirSettings = @{Expression={if (($_.name) -eq $directorySettings.defaultLoginDomain.Name) { "$($_.Name) (default)"} Else {$_.name}};label='Directory Name'},@{Expression={$_.authProtocol};label='Directory Type'},@{Expression={$_.top};label='Root'},@{Expression={$_.org};label='Search Context'}
                $dispDirServer = @{Expression={$_.directoryServers.directoryServerIpAddress};label='Server Hostname\IP'},@{Expression={$_.directoryServers.directoryServerSSLPortNumber};label='SSL Port'}
                
                #Filter directory name and display in table, and does not display global directory settings
                If ($Name) {
                    $colDirectories | Where-Object {$_.name -eq $name} | Format-Table $dispDirSettings -AutoSize
                    $colDirectories | Where-Object {$_.name -eq $name} | Format-Table $dispDirServer -AutoSize
                }

                #Display all directories in their own tables. Also displays global settings.
                Else {
                    $directoryGlobalSettings = @{Expression={If ($_.allowLocalLogin){'Enabled'}
                                                                else{'Disabled'}};label='Local Login'},
                                                   @{Expression={$_.defaultLoginDomain.Name};label='Default Directory'},
                                                   @{Expression={(% {$_.configuredLoginDomains}).name};label='Configured Directories'}
                    
                    $directorySettings | Format-Table $directoryGlobalSettings -AutoSize
                    ForEach ($dir in $colDirectories) {
                        $dir | Format-Table $dispDirSettings -AutoSize
                        $dir | Format-Table $dispDirServer -AutoSize
                    }
                }
            }

            #Display 
            else { $colDirectories }
        }
	}
}

function New-HPOVLdap {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = 'AD')]
	param(
		[Parameter(Position=0, Mandatory = $true, ParameterSetName = "AD")]
        [Parameter(Position=0, Mandatory = $true, ParameterSetName = "LDAP")]
        [ValidateNotNullOrEmpty()]
		[String]$Name,

		[Parameter(Mandatory = $true, ParameterSetName = "AD")]
		[Switch]$AD,

		[Parameter(Mandatory = $true, ParameterSetName = "LDAP")]
		[Switch]$LDAP,

		[Parameter(Position=2,Mandatory = $true, ParameterSetName = "AD")]
        [Parameter(Position=2,Mandatory = $true, ParameterSetName = "LDAP")]
		[Alias('root')]
        [String]$RootDN,

        [Parameter(Position=3,Mandatory = $true, ParameterSetName = "AD")]
        [Parameter(Position=3,Mandatory = $true, ParameterSetName = "LDAP")]
        [ValidateNotNullOrEmpty()]
		[String]$SearchContext,

        [Parameter(Position=4,Mandatory = $true, ParameterSetName = "AD")]
        [Parameter(Position=4,Mandatory = $true, ParameterSetName = "LDAP")]
        [ValidateNotNullOrEmpty()]
		[Array]$Servers,

        [Parameter(Position=5,Mandatory = $true, ParameterSetName = "AD")]
        [Parameter(Position=5,Mandatory = $true, ParameterSetName = "LDAP")]
        [ValidateNotNullOrEmpty()]
		[Alias('u','user')]
        [String]$Username,

        [Parameter(Position=6,ValueFromPipeline=$true,Mandatory = $true, ParameterSetName = "AD")]
        [Parameter(Position=6,ValueFromPipeline=$true,Mandatory = $true, ParameterSetName = "LDAP")]
        [ValidateNotNullOrEmpty()]
		[Alias('p','pass')]
        [SecureString]$Password

	)

    #Perform validation.
	begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "New-HPOVLdap" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }


	}

	process {

        if ($AD) { 
            $authProtocol = "AD"
            $userNameField = "CN"
        }
        if ($LDAP) {
            $authProtocol = "LDAP" 
            $userNameField = "UID"
        }

        $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

        $newDirectoryObj = @{
                            type = "LoginDomainConfigVersion2Dto";
                            name = $Name;
                            userNameField = $userNameField;
                            org = $SearchContext;
                            top = $RootDN;
                            useSsl = $true;
                            authProtocol = $authProtocol;
                            credential = @{ userName = $Username; password = $decryptPassword };
                            directoryServers = @($Servers);}

        #convertto-json -depth 99 $newDirectoryObj
        $resp = Send-HPOVRequest $script:authnProviderValidator POST
        $resp
        [int]$script:lastWebResponse.StatusCode

        #$resp = Send-HPOVRequest $script:authnProvidersUri 
        #$resp
        #[int]$script:lastWebResponse.StatusCode
	}
}

function Remove-HPOVLdap {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
	param(
         [parameter(Mandatory = $true,ValueFromPipeline=$true,HelpMessage = "Enter the Directory name",Position=0, ParameterSetName = "default")]
         [ValidateNotNullOrEmpty()]
         [alias("d")]
         [Object]$Directory
    )

	begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Remove-HPOVLdap" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)


        }

    }
    
    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Directory DTO: $($Directory.GetType().FullName)"
        if (($Directory.GetType().FullName -eq "System.String") -and ($Directory.StartsWith("/rest/"))) {
            $directoryToDeleteUri = $Directory
            $directoryToDeleteName = $Directory
        }

        elseif ($Directory.GetType().FullName -eq "System.String") {
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Looking for directory `'$($Directory)`'"
            $Directories = Send-HPOVRequest $script:authnSettingsUri
            $directoryToDelete = $Directories.configuredLoginDomains | Where-Object { ($_.name -eq $Directory) }
            $directoryToDeleteUri = $directoryToDelete.uri
            $directoryToDeleteName = $directoryToDelete.name

        }

        elseif (($Directory.GetType().FullName -eq "System.Management.Automation.PSCustomObject") -or ($Directory.GetType() -eq "System.Object[]")) {
            $directoryToDeleteUri = $Directory.uri
            $directoryToDeleteName = $Directory.name
        }
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] directoryToDeleteUri: $($directoryToDeleteUri)"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] directoryToDeleteName: $($directoryToDeleteName)"

        if ($pscmdlet.ShouldProcess($script:HPOneViewAppliance,"Remove Directroy `'$directoryToDeleteName`'")) {   

            Remove-HPOVResource -nameOrUri $directoryToDeleteUri 
            
            write-verbose "STATUS CODE RETURN: $([int]$script:lastWebResponse.statuscode)"
        
            if ([int]$script:lastWebResponse.statuscode -eq 204) {
                Write-Verbose "$($directoryToDeleteName) successfully deleted"
            }
        }

	}

}

function New-HPOVLdapServer {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	param(
		[Parameter(Position=0, Mandatory = $true)]
		[String]$Name = $Null,

		[Parameter(Position=1, Mandatory = $false)]
		[Alias('port')]
        [ValidateRange(1,65535)]
        [Int32]$SSLPort = 636,

        [Parameter(Position=2, Mandatory = $true)]
        [Alias('cert')]
        [Object]$Certificate = $Null
	)

	begin {

        if (-not $PSBoundParameters['Certificate']) { $Pipelineinput = $True }


    }

    Process {

        
        if (Test-Path $Certificate) { 

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Certificate file found."

            $cert = get-content $Certificate 

            #Convert from System.Array to multi-line String
            $certificate = $cert | out-string
        }

        else {

            $errorRecord = New-ErrorRecord FileNotFoundException CertificateNotFound ObjectNotFound 'New-HPOVLdapServer' -Message "No Storage System" #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        $ldapServer = @{Type = "LoginDomainDirectoryServerInfoDto";
                        directoryServerIpAddress = $Name;
                        directoryServerCertificateBase64Data = $Certificate;
                        directoryServerSSLPortNumber = [string]$sslport }

	}

    End {

        Return $ldapServer

    }
}

function Show-HPOVLdapGroups {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	param(
         [parameter(Mandatory = $true,HelpMessage = "Enter the user name",Position=0)]
         [ValidateNotNullOrEmpty()]
         [alias("u")]
         [string]$UserName,

         [parameter(Mandatory = $true,ValueFromPipeline=$true,HelpMessage = "Enter the password",Position=1)]
         [alias("p")]
         [ValidateNotNullOrEmpty()]
         [SecureString]$password,

         [parameter(Mandatory = $true,HelpMessage = "Enter the Directory name",Position=2)]
         [ValidateNotNullOrEmpty()]
         [alias("d","domain","directory")]
         [string]$authProvider
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Show-HPOVLdapGroups' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }


	process {
 
        $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        $body = @{userName=$username; password=$decryptPassword; authLoginDomain=$authProvider}

		$groups = Send-HPOVRequest $script:authnDirectoryGroups POST -body $body

        if ($groups.count -eq 0){ Write-Warning "No groups found."}
        else {
            $output = foreach ($grp in $groups){
                $obj = new-object psobject
                $obj | add-member noteproperty 'Directory Groups'($grp)
                
            }
        }

	}

    end {
    
        return $obj
    }

}

function Get-HPOVLdapGroup {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	param(
        [parameter(Mandatory = $false,HelpMessage = "Enter the Directroy Group Name",Position=0)]
        [alias("group","name")]
        [string]$GroupName,

        [parameter(Mandatory = $false,HelpMessage = "Provide the filename to export to",Position=1)]
        [alias("e","x")]
        [ValidateScript({split-path $_ | Test-Path})]
        [string]$Export,

        [parameter(Mandatory = $false)]
        [Alias('Report')]
        [switch]$List
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVLdapGroup' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)


        }

    }

	process {

        $groups = Send-HPOVRequest $script:authnEgroupRoleMappingUri

        if ($GroupName) { $members = $groups.members | Where-Object {$_.egroup -eq $GroupName} }
        else { $members = $groups.members }

        if ($Export){ $members | convertto-json > $Export }
        elseif ($List) {
            $displayGroup = @{Expression={$_.egroup};label="Group Name"},
                            @{Expression={$_.loginDomain};label='Directory Name'},
                            @{Expression={(% {$_.roles})};label='Roles'}
            $members | format-table $displayGroup -AutoSize
        }
 
        else{ 
            $members
        }
	}
}

function New-HPOVLdapGroup {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	param(
         [parameter(Mandatory = $true,HelpMessage = "Enter the Directory name",Position=0)]
         [ValidateNotNullOrEmpty()]
         [alias("d","domain","directory")]
         [string]$authProvider,

         [parameter(Mandatory = $true,HelpMessage = "Enter the Directroy Group name",Position=1)]
         [ValidateNotNullOrEmpty()]
         [alias("g","group","name")]
         [string]$GroupName,

         [parameter(Mandatory = $true,HelpMessage = "Enter the Directroy Group roles in System.Array format",Position=2)]
         [ValidateNotNullOrEmpty()]
         [alias("r","role")]
         [Array]$Roles,

         [parameter(Mandatory = $true,HelpMessage = "Enter the user name",Position=3)]
         [ValidateNotNullOrEmpty()]
         [alias("u")]
         [string]$UserName,

         [parameter(Mandatory = $true,ValueFromPipeline=$true,HelpMessage = "Enter the password",Position=4)]
         [alias("p")]
         [ValidateNotNullOrEmpty()]
         [SecureString]$Password
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'New-HPOVLdapGroup' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #Validate roles provided are allowed.
        [Array]$unsupportedRoles = @()

        foreach ($role in $roles) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $role"

            if (-not ($script:applSecurityRoles -contains $role)) { [array]$unsupportedRoles += $role }

        }

        if ($unsupportedRoles.count -eq 1) { 
        
            $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "Set-HPOVUserRole" -Message "The '$($unsupportedRoles -join ", ")' role is not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
            $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
        }
        elseif ($unsupportedRoles.count -gt 1) { 
        
            $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "Set-HPOVUserRole" -Message "The '$($unsupportedRoles -join ", ")' roles are not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
            $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
        }

        #Need to make sure role name is first letter capitalized only.
        $i = 0
        foreach ($role in $roles) {
            $roles[$i] = $role.substring(0,1).ToUpper()+$role.substring(1).tolower()
            $i++
        }

    }

	process {
 
        #Decrypt the password
        $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

		$group = @{ type = "Group2RolesMappingPerGroupValidationDto";
                    group2rolesPerGroup = @{ type = "Group2RolesMappingPerGroupDto";
                                             loginDomain = $authProvider;
                                             egroup = $GroupName;
                                             roles = $roles};
                    credentials = @{userName = $UserName;password = $decryptPassword}
                   }
        
        #Send the request to create the Directory Group
        Send-HPOVRequest $script:authnEgroupRoleMappingUri POST $group

	}

}

function Set-HPOVLdapGroupRole {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding()]
	param(
         [parameter(Mandatory = $true,HelpMessage = "Enter the Directory name",Position=0)]
         [ValidateNotNullOrEmpty()]
         [alias("d","domain","directory")]
         [string]$authProvider,

         [parameter(Mandatory = $true,HelpMessage = "Enter the Directroy Group name",Position=1)]
         [ValidateNotNullOrEmpty()]
         [alias("g","group","name")]
         [string]$GroupName,

         [parameter(Mandatory = $true,HelpMessage = "Enter the Directroy Group roles in System.Array format",Position=2)]
         [ValidateNotNullOrEmpty()]
         [alias("r","role")]
         [Array]$Roles,

         [parameter(Mandatory = $true,HelpMessage = "Enter the user name",Position=3)]
         [ValidateNotNullOrEmpty()]
         [alias("u")]
         [string]$UserName,

         [parameter(Mandatory = $true,ValueFromPipeline=$true,HelpMessage = "Enter the password",Position=4)]
         [alias("p")]
         [ValidateNotNullOrEmpty()]
         [SecureString]$Password
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'New-HPOVLdapGroup' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        #Validate roles provided are allowed.
        [Array]$unsupportedRoles = @()

        foreach ($role in $roles) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Processing $role"

            if (-not ($script:applSecurityRoles -contains $role)) { [array]$unsupportedRoles += $role }

        }

        if ($unsupportedRoles.count -eq 1) { 
        
            $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "Set-HPOVUserRole" -Message "The '$($unsupportedRoles -join ", ")' role is not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
            $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
        }
        elseif ($unsupportedRoles.count -gt 1) { 
        
            $errorRecord = New-ErrorRecord ArgumentException UnsupportedRolesFound InvalidArgument "Set-HPOVUserRole" -Message "The '$($unsupportedRoles -join ", ")' roles are not supported or the correct names.  Please validate the -roles parameter contains one or more valid roles.  Allowed roles are: $($script:applSecurityRoles -join ", ")"
            $PSCmdlet.ThrowTerminatingError($errorRecord)            
            
        }

        #Need to make sure role name is first letter capitalized only.
        $i = 0
        foreach ($role in $roles) {
            $roles[$i] = $role.substring(0,1).ToUpper()+$role.substring(1).tolower()
            $i++
        }

    }

	process {
 
        #Decrypt the password
        $decryptPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

		$group = @{ type = "Group2RolesMappingPerGroupValidationDto";
                    group2rolesPerGroup = @{ type = "Group2RolesMappingPerGroupDto";
                                             loginDomain = $authProvider;
                                             egroup = $GroupName;
                                             roles = $roles};
                    credentials = @{userName = $UserName;password = $decryptPassword}
                   }
        
        #Send the request to create the Directory Group
        Send-HPOVRequest $script:authnEgroupRoleMappingUri PUT $group

	}

}

function Remove-HPOVLdapGroup {

    # .ExternalHelp HPOneView.110.psm1-help.xml

	[CmdletBinding(DefaultParameterSetName = "default",SupportsShouldProcess = $True, ConfirmImpact = 'High')]
	param (
         [parameter(Mandatory = $true,ValueFromPipeline=$true,HelpMessage = "Enter the Directory Group name",Position=0, ParameterSetName = "default")]
         [ValidateNotNullOrEmpty()]
         [alias("g")]
         [Object]$Group
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Remove-HPOVLdapGroup' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)


        }

    }

	process {
 
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] GroupName DTO: $($Group.GetType().FullName)"
        if (($Group.GetType().FullName -eq "System.String") -and ($Group.StartsWith("/rest/"))) {
            $groupToDeleteUri = $Group
            $GroupToDeleteName = $Group
        }

        elseif ($Group.GetType().FullName -eq "System.String") {
            $groups = Send-HPOVRequest $script:authnEgroupRoleMappingUri
            $groupToDelete = $groups.members | Where-Object {$_.egroup -eq $Group}
            $groupToDeleteUri = $groupToDelete.uri
            $groupToDeleteName = $groupToDelete.egroup

        }

        elseif (($Group.GetType().FullName -eq "System.Management.Automation.PSCustomObject") -or ($Group.GetType() -eq "System.Object[]")) {
            $groupToDeleteName = $Group.egroup
            $groupToDeleteUri = $Group.uri
        }
        
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] groupToDeleteUri: $($groupToDeleteUri)"
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] groupToDeleteName: $($groupToDeleteName)"

        if ($pscmdlet.ShouldProcess($script:HPOneViewAppliance,"Remove Directroy Group `'$groupToDeleteName`'")) {   

            Remove-HPOVResource -nameOrUri $groupToDeleteUri 
        
            if ([int]$script:lastWebResponse.statuscode -eq 204) {
                Write-Verbose "$($groupToDeleteName) successfully deleted"
            }
        }
	}
}

Function Get-HPOVAuditLog {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding(DefaultParameterSetName = "default")]
    Param (
        [parameter(Mandatory = $false,ValueFromPipeline=$false, ParameterSetName = "default",HelpMessage = "Specify the folder location to save the audit log file.")]
        [Alias("save")]
        [string]$Location = (get-location).Path
    )

    Begin {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Validating user is authenticated"
        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'Get-HPOVAuditLog' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }


        #Validate the path exists.  If not, create it.
		if (!(Test-Path $Location)){ 
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Directory does not exist.  Creating directory..."
            New-Item $Location -itemtype directory
        }

    }

    Process {
        
		#Send the request
		#Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Please wait while the appliance backup is generated.  This can take a few minutes..."
	
		#Now that the Support Dump has been requested, download the file
        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Downloading audit log to $($Location)"
		Download-File $script:applAuditLog $Location
    }
}

#######################################################
# Alerts & Events: 
#

function Get-HPOVAlert {

    # .ExternalHelp HPOneView.110.psm1-help.xml
	
	[CmdletBinding(DefaultParameterSetName = "Default")]

    Param(
         [parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $True, HelpMessage = "Resource URI or Object (i.e. Get-HPOV*)", ParameterSetName = "ServerProfile")]
         [parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $True, HelpMessage = "Resource URI or Object (i.e. Get-HPOV*)", ParameterSetName = "Default")]
         [ValidateNotNullOrEmpty()]
         [alias('resourceUri')]
         [Object]$resource = $null,

         [parameter(Position = 1, Mandatory = $false, HelpMessage = "Alert Severity 'OK','Critical','Disabled','Warning', or 'Unknown'.", ParameterSetName = "ServerProfile")]
         [parameter(Position = 1, Mandatory = $false, HelpMessage = "Alert Severity 'OK','Critical','Disabled','Warning', or 'Unknown'.", ParameterSetName = "Default")]
         [ValidateNotNullOrEmpty()]
         [ValidateSet('OK','Critical','Disabled','Warning','Unknown')]
         [string]$severity = $null,

         [parameter(Position = 2, Mandatory = $false, HelpMessage = "Alert/Health Category", ParameterSetName = "Default")]
         [ValidateNotNullOrEmpty()]
         [ValidateSet('Appliance', 'DeviceBay', 'Enclosure', 'Fan', 'Firmware', 'Host', 'Instance', 'InterconnectBay', 'LogicalSwitch', 'Logs', 'ManagementProcessor', 'Memory', 'Network', 'Operational', 'Power', 'Processor', 'RemoteSupport', 'Storage', 'Thermal', 'Unknown')]
         [string]$healthCategory=$null,

         [parameter(Mandatory = $false, HelpMessage = "Filter by User",Position=3, ParameterSetName = "Default")]
         [ValidateNotNullOrEmpty()]
         [String]$assignedToUser=$null,

         [parameter(Mandatory = $false,  HelpMessage = "Alert state",Position=4, ParameterSetName = "Default")]
         [ValidateNotNullOrEmpty()]
         [String]$alertState=$null
    )

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Get-HPOVAlert" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if (-not $PSBoundParameters['resource']) { $Pipelineinput = $True }

        $alerts = [PSCustomObject]@{members = @();count = 0}

    }

    Process {
       	
        if ($Pipelineinput) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource provided via pipeline." }

        if ($resource) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource [$($resource.gettype())] value: $($resource | out-string)" }

        #Check if input has URI property
        if (($resource -is [PsCustomObject] -or $resource -is [Hashtable]) -and -not ($resource.uri)) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource parameter does not contain a URI.  Resource Object: $($resource | out-string)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating terminating error."
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Get-HPOVAlert' -Message "The resource object provided does not contain a URI.  Please check the parameter value and try again." #-verbose
            $PsCmdlet.ThrowTerminatingError($errorRecord)

        }

        if ($resource.category -eq "server-profiles") {
        
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Input object is a Server Profile. Getting special URI for alert messages."
            
            $serverAlerts = Send-HPOVRequest ($resource.uri + "/messages")

            foreach ($alert in $serverAlerts) {

                switch ($alert | select * -ExcludeProperty etag,type | get-member -MemberType NoteProperty | select -expandproperty Name) {

                    "connections" { if ($alert.connections.count -gt 0) { $alerts.members += $alert.connections | % { $_.messages} } }
                    "serverHardware" { if ($alert.serverHardware.count -gt 0) {$alerts.members += $alert.serverHardware | % { $_.messages} } }
                    "firmwareStatus" { if ($alert.firmwareStatus.count -gt 0) { $alerts.members += $alert.firmwareStatus | % { $_.messages} } }
                
                }

            }

            $alerts.count = $alerts.members.count
        
        }
        else {

            $uri = $alertsUri + "?start=0&count=-1"

            if ($resource -is [String] -and -not $resource.startswith('/rest')) { $uri += "&filter=resourceName='$resource'" }

            elseif ($resource -is [String] -and $resource.startswith('/rest')) { $uri += "&filter=resourceUri='$resource'" }
            elseif ($resource -is [PsCustomObject]) { $uri += "&filter=resourceUri=`'$($resource.uri)`'" }
            
            if ($severity) { $uri += "&filter=severity='$severity'" }
            
            if ($healthCategory) { $uri += "&filter=healthCategory='$healthCategory'" }
            
            if ($assignedToUser) { $uri += "&filter=assignedToUser='$assignedToUser'" }
            
            if ($alertState) { $alertState = $alertState.ToLower(); $alertState = $alertState.substring(0,1).ToUpper()+$alertState.substring(1).tolower(); $uri += "&filter=alertState=`'$alertState`'" }

            $alerts = Send-HPOVRequest $uri
        
            Set-DefaultDisplay $alerts.members -defProps 'created', 'severity', 'alertState', 'description', 'assignedToUser', 'healthCategory', 'resourceURI'

        }

    }

    end {

        $alerts.members
        if ($resource -and $resource.name) {
                
            Write-Host "Done. $($alerts.count) alert(s) found for $($resource.name)."

        }
        else {
                
            Write-Host "Done. $($alerts.count) alert(s) found for $resource."

        }

    }

}

function Set-HPOVAlertAssignToUser {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param(
        [parameter (Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$alertUri,

        [parameter (Mandatory = $false)]
        [string]$assignedToUser=$NULL
	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Set-AlertAssignToUser" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $body = [PsCustomObject]@{ assignedToUser=$assignedToUser; }
        $alert = Send-HPOVRequest $alertUri PUT $body
        return $alert
    }
}

function Clear-HPOVAlert  {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]
    Param(
        [parameter (Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$alertUri,

        [parameter (Mandatory = $false)]
        [Bool]$cleared = $true
	)

    Begin {

        Write-Warning "The -Cleared parameter is being deprecated in this CMDLET.  Please use 'Set-HPOVAlert' to modify an Alerts State."

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Clear-HPOVAlert" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

    }

    Process {

        $body = [PsCustomObject]@{ alertState="Cleared"; }
        
        $alert = Send-HPOVRequest $alertUri PUT $body
        return $alert
    }

}

function Set-HPOVAlert  {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdLetBinding()]

    Param(

        [parameter (Position = 0, ValueFromPipeline = $True, Mandatory = $true, ParameterSetName = 'Cleared')]
        [parameter (Position = 0, ValueFromPipeline = $True, Mandatory = $true, ParameterSetName = 'Active')]
        [ValidateNotNullOrEmpty()]
        [alias('alertUri')]
        [Object]$alert,

        [parameter (Position = 1, Mandatory = $false, ParameterSetName = 'Cleared')]
        [parameter (Position = 1, Mandatory = $false, ParameterSetName = 'Active')]
        [ValidateNotNullOrEmpty()]
        [String]$notes,

        [parameter (Mandatory = $true, ParameterSetName = 'Cleared')]
        [parameter (Mandatory = $false)]
        [switch]$cleared,

        [parameter (Mandatory = $true, ParameterSetName = 'Active')]
        [parameter (Mandatory = $false)]
        [switch]$active

	)

    Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError "Set-HPOVAlert" -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)

        }

        if (-not $PSBoundParameters["alert"]) { $Pipelineinput = $True }

    }

    Process {

        if (-not $alert) { 
        
            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Get-HPOVAlert' -Message "The required parameter -alert was not provided." #-verbose
            $PsCmdlet.ThrowTerminatingError($errorRecord)

        }

        if ($Pipelineinput) { Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource provided via pipeline." }

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource [$($alert.gettype())] value: $($alert | out-string)"

        #Check if input has URI property
        if (-not $alert.uri) {

            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Resource parameter does not contain a URI.  Resource Object: $($alert | out-string)"
            Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Generating terminating error."

            $errorRecord = New-ErrorRecord InvalidOperationException InvalidArgumentValue InvalidArgument 'Get-HPOVAlert' -Message "The resource object provided does not contain a URI.  Please check the parameter value and try again." #-verbose
            $PsCmdlet.ThrowTerminatingError($errorRecord)

        }
        elseif ($alert.uri) { $uri = $alert.uri}
        else { $uri = $alert }

        switch ($PsCmdlet.ParameterSetName) {

            "Cleared" { $request = [PsCustomObject]@{ alertState="Cleared" } }
            "Active" { $request = [PsCustomObject]@{ alertState="Active" } }

        }

        if ($notes) {

            #Adding notes to alert object
            $request | Add-Member -MemberType NoteProperty -Name notes -Value $notes

        }
        
        $resp = Send-HPOVRequest $uri PUT $request
        
    }

    End {

        return $resp

    }

}
    
function Get-HPOVLicense {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdletBinding(DefaultParameterSetName = "Values")]
    param(
        [Parameter(Mandatory = $False, ParameterSetName = "Values",HelpMessage = "Please specify the type of license you wish to generate a report for. Accepted values are `"OneView`", `"OneViewNoiLO`", or `"all`".")]
        [ValidateSet("OneView", "OneViewNoiLO","all")]
        [parameter(Position=0)]
        [String]$Type,
        
        [Parameter(Mandatory = $False, ParameterSetName = "Values",HelpMessage = "Please specify the license state you wish to generate a report for. Accepted values are `"Unlicensed`" or `"Permanent`".")]
        [ValidateSet("Unlicensed", "Permanent",$null)]
        [parameter(Position=1)]
        [String]$State,

        [Parameter(Mandatory = $False, ParameterSetName = "Values")]
        [Switch]$Summary
    
    )

    begin {
	
		[string]$filter = $null
		
        If ($Type){

            write-verbose "License Type: $Type"

            switch ($Type){

                #User wants the HP OneView License report
                "OneView"{
                    $filter += "?filter=`"product='HP OneView'`""
                }

                #User wants the HP OneView without iLO License Report
                "OneViewNoiLO"{
                    $filter += "?filter=`"product='HP OneView w/o iLO'`""
                }

                default{
                    $filter += $null
                }

            }

        }

        If ($State){

            write-verbose "License $State State"

			#Check to see if the license type/product was specified, as we would have an existing filter value
            If ($filter){

				$filter += "&filter=`"licenseType='$State'`""

			}
			ElseIf (!$filter){

				$filter += "?filter=`"licenseType='$State'`""

			}

        }
		ElseIf (!$State){

            Write-Verbose "No license state provided ($State)"
			$filter += ""

        }
  
        If ($Summary){

            write-verbose "Generating Summary Report"
            write-host "Displaying Summary Report"
			
			#Check to see if the license type/product was specified, as we would have an existing filter value
            If ($filter){

				$disSummary = "&view=summary"

			}
			ElseIf (!$filter){

				$disSummary = "?view=summary"

			}
			
        }
        ElseIf(!$Summary){

            write-verbose "Generating detailed report"

            $disSummary = ""

        }
    
    }

    process {
		
		#Display verbose data of what will be sent to Send-HPOVRequest
        write-verbose (($script:licensesUri + $filter + $disSummary) + " GET")
		
		#Send the request
		$ret = Send-HPOVRequest ($script:licensesUri + $filter + $disSummary) GET
		
		Write-Verbose $ret

		#If the Summary switch was specified, display a summary report
		If ($Summary){
					
			$a = @{Expression={$_.Product};Label="License Name"},
				 @{Expression={$_.AvailableCapacity};Label="Available"},
				 @{Expression={$_.ConsumedCapacity};Label="Consumed"},
				 @{Expression={$_.TotalCapacity};Label="Total"},
				 @{Expression={$_.UnlicensedCount};Label="Unlicensed"}

            $ret.members | Format-Table $a -AutoSize -Wrap

		}
		
		#Otherwise, we will display a detailed report
		Else{

             $a = @{Expression={$_.Product};Label="License Name"},
                  @{Expression={$_.AvailableCapacity};Label="Available"},
                  @{Expression={$_.TotalCapacity};Label="Total"},
                  @{Expression={$licenseGroup.nodes.count};Label="Associated Nodes"}
			 
            $now = (Get-Date).ToShortDateString()

            ForEach ($licenseGroup in $ret.members){

				#convertto-json $member -depth 99
                $licenseGroup | Format-Table $a -autosize -wrap
            
                $b = @{Expression={$_.nodeName};Label="Device"},
                     @{Expression={$licenseGroup.LicenseType};Label="License Type"},
                     @{Expression={
                    
                        $appliedDate = (Get-Date($_.appliedDate)).ToShortDateString()
						
						if ($licenseGroup.LicenseType -eq "Evaluation" -or $licenseGroup.LicenseType -eq "Unlicensed") {

							$expire = (Get-Date($appliedDate)).AddDays(60)

							$warnDate = new-timespan -start $now -end $expire

							if ($warnDate.Days -eq 0 -or $warnDate.Days -lt 0) {

								$appliedDate = $appliedDate + " (EXPIRED)"

							} 
							elseif($warnDate.Days -gt 0) {
							
								$appliedDate = $appliedDate + " (Expires in " + $warnDate.days + " days)"
								$warning = "\(Expires in " + $warnDate.days + " days\)"

							}
						}
						
                        $appliedDate

                    };Label="Applied Date"}

                $licenseGroup.nodes | sort-object -property nodeName | Format-Table $b -autosize -wrap | Out-String | ForEach-Object {

                    $_.Split("`n") | ForEach-Object {

                        if($_ -match "EXPIRED") { Write-Host -ForegroundColor Red $_ }
                        elseif($_ -match "Expires in"){ Write-Host -ForegroundColor Yellow $_ }
                        else{ Write-Host $_ }
                   
                    }

                } 
 
            }

		}

    }

}

function New-HPOVLicense {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdletBinding(DefaultParameterSetName = "licenseKey")]
    param(
        [Parameter(Position=0, Mandatory = $true, ParameterSetName="licenseKey",HelpMessage = "Please specify the license you wish to install")]
        [ValidateNotNullOrEmpty()]
        [String]$LicenseKey,
        
        [Parameter(Position=0, Mandatory = $true, ParameterSetName = "InputFile",HelpMessage = "Please specify the license file")]
        [ValidateScript({Test-Path $_})]
        [String]$File

    )

	Begin {

        if (! $global:cimgmtSessionId) {
        
            $errorRecord = New-ErrorRecord HPOneview.Appliance.AuthSessionException NoAuthSession AuthenticationError 'New-HPOVLicense' -Message "No valid session ID found.  Please use Connect-HPOVMgmt to connect and authenticate to an appliance." #-verbose
            $PSCmdlet.ThrowTerminatingError($errorRecord)


        }

		if ($file){
			$licenseKey = Get-Content $file
		}

	}

    Process {
	    
		#Loop through all keys, and add one by one.
		foreach ($lk in $licenseKey){
			$key = [PsCustomObject] @{
	        	type = "License";
	        	key = $lk
	    	}
	    	$ret = New-HPOVResource $licensesUri $key
			
			if ($ret.errorCode -contains "LICENSE_ALREADY_EXISTS"){ Write-Error "Key already exists: `n$key" -Category ResourceExists -CategoryTargetName "New-HPOVLicense" }
            $ret
		}

	}

}

########################################################
# HP Support CMDLETs

function Enable-HPOVDebug {

    # .ExternalHelp HPOneView.110.psm1-help.xml
    
    [CmdletBinding(DefaultParameterSetName = "default")]
    param(
        [Parameter(Position=0, Mandatory = $true, ParameterSetName="default",HelpMessage = "Provide the debug Scope.")]
        [ValidateNotNullOrEmpty()]
        [String]$Scope,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="default",HelpMessage = "Provide the component Logger Name.")]
        [ValidateNotNullOrEmpty()]
        [String]$LoggerName,

        [Parameter(Position = 2, Mandatory = $true, ParameterSetName="default",HelpMessage = "Specify the verbose log level (ERROR, WARN, DEBUG or TRACE are allowed).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ERROR','WARN','DEBUG','TRACE', IgnoreCase = $False)]
        [String]$Level
    )

    Begin {

        write-host
        Write-Warning "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        Write-Warning "!!! FOR HP SUPPORT USE ONLY. DO NOT USE UNLESS OTHERWISE INSTRUCTED TO BY HP SUPPORT !!!"
        Write-Warning "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        write-host

        $body = [PSCustomObject]@{

            scope      = $Scope;
            loggerName = $LoggerName;
            level      = $Level

        }

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting '$Level' at '$Scope`:$LoggerName'"
        $resp = Send-HPOVRequest $script:applianceDebugLogSetting POST $body

    }

    end {

        if ([int]$script:lastWebResponse.StatusCode -eq 200) {

            "'{0}:{1}' successfully set to '{2}'" -f $Scope,$LoggerName,$Level
            Write-Warning "Remember to set '$Scope`:$LoggerName' back to 'INFO' with 'Disable-HPOVDebug $Scope $LoggerName'"

        }
        else {

            "Unable to set '{0}:{1}' to '{2}' logging level. HTTP Error {3}" -f $Scope,$LoggerName,$Level,[int]$script:lastWebResponse.StatusCode

        }

    }

}

function Disable-HPOVDebug {

    # .ExternalHelp HPOneView.110.psm1-help.xml

    [CmdletBinding(DefaultParameterSetName = "default")]
    param(
        [Parameter(Position=0, Mandatory = $true, ParameterSetName="default",HelpMessage = "Provide the debug Scope.")]
        [ValidateNotNullOrEmpty()]
        [String]$Scope,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="default",HelpMessage = "Provide the component Logger Name.")]
        [ValidateNotNullOrEmpty()]
        [String]$LoggerName

    )

    Begin {

        $Level= "INFO"

        write-host
        Write-Warning "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        Write-Warning "!!! FOR HP SUPPORT USE ONLY. DO NOT USE UNLESS OTHERWISE INSTRUCTED TO BY HP SUPPORT !!!"
        Write-Warning "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        write-host

        $body = [PSCustomObject]@{

            scope      = $scope;
            loggerName = $loggerName;
            level      = $Level

        }

    }

    Process {

        Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Setting '$Level' at '$scope`:$loggerName'"
        $resp = Send-HPOVRequest $script:applianceDebugLogSetting POST $body

    }

    end {

        if ([int]$script:lastWebResponse.StatusCode -eq 200) {

            "'{0}:{1}' successfully set to '{2}'" -f $Scope,$LoggerName,$Level

        }
        else {

            "Unable to set '{0}:{1}' to '{2}' logging level. HTTP Error {3}" -f $Scope,$LoggerName,$Level,[int]$script:lastWebResponse.StatusCode

        }

    }

}

########################################################
# PowerShell Filters

filter ColorPattern( [string]$Pattern, [hashtable]$Color) {

  $split = $_ -split $Pattern

  $found = [regex]::Matches( $_, $Pattern, 'IgnoreCase' )

  for( $i = 0; $i -lt $split.Count; ++$i ) {
    [ConsoleColor]$displayColor = $Color.keys | % { if ($_ -ieq $found[$i]) { $color[$_]} }
    Write-Host $split[$i] -NoNewline
    Write-Host $found[$i] -NoNewline -ForegroundColor $displayColor
  }

  Write-Host
}

#######################################################
#  CMDLET Aliases
set-alias New-HPOVEnclosure Add-HPOVEnclosure
set-alias New-HPOVServer Add-HPOVServer 
set-alias Wait-HPOVTaskAccepted Wait-HPOVTaskStart
set-alias Get-HPOVServerHardwareTypes Get-HPOVServerHardwareType
set-alias New-HPOVStorageSystem Add-HPOVStorageSystem
set-alias New-HPOVSanManager Add-HPOVSanManager
set-alias New-HPOVStoragePool Add-HPOVStoragePool
set-alias New-HPOVPowerDevice Add-HPOVPowerDevice 
set-alias Set-HPOVRole Set-HPOVUserRole

#######################################################
#  Export the public functions from this module
#  Generic suport functions:
Export-ModuleMember -Function Send-HPOVRequest
Export-ModuleMember -Function Connect-HPOVMgmt
Export-ModuleMember -Function Disconnect-HPOVMgmt
Export-ModuleMember -Function New-HPOVResource
Export-ModuleMember -Function Set-HPOVResource
Export-ModuleMember -Function Remove-HPOVResource
Export-ModuleMember -Function Set-HPOVPrompt
Export-ModuleMember -Function Show-HPOVAppliance
Export-ModuleMember -Function Wait-HPOVApplianceStart

#Appliance Configuration:
Export-ModuleMember -Function Get-HPOVVersion
Export-ModuleMember -Function Get-HPOVHealthStatus
Export-ModuleMember -Function Get-HPOVXApiVersion
Export-ModuleMember -Function Get-HPOVEulaStatus
Export-ModuleMember -Function Set-HPOVEulaStatus
Export-ModuleMember -Function Get-HPOVApplianceNetworkConfig
Export-ModuleMember -Function Set-HPOVApplianceNetworkConfig
Export-ModuleMember -Function Get-HPOVSnmpReadCommunity 
Export-ModuleMember -Function Set-HPOVSnmpReadCommunity 
Export-ModuleMember -Function Get-HPOVApplianceGlobalSetting
Export-ModuleMember -Function Set-HPOVApplianceGlobalSetting
Export-ModuleMember -Function Get-HPOVSPPFile
Export-ModuleMember -Function Add-HPOVSPPFile
Export-ModuleMember -Function New-HPOVSupportDump
Export-ModuleMember -Function New-HPOVBackup
Export-ModuleMember -Function New-HPOVRestore
Export-ModuleMember -Function Get-HPOVScmbCertificates
Export-ModuleMember -Function Install-HPOVUpdate
Export-ModuleMember -Function Remove-HPOVPendingUpdate
Export-ModuleMember -Function Show-HPOVSSLCertificate
Export-ModuleMember -Function Import-HPOVSSLCertificate
Export-ModuleMember -Function Restart-HPOVAppliance
Export-ModuleMember -Function Stop-HPOVAppliance
Export-ModuleMember -Function Enable-HPOVDebug
Export-ModuleMember -Function Disable-HPOVDebug

#Server hardware and enclosures:
Export-ModuleMember -Function Get-HPOVServer
Export-ModuleMember -Function Add-HPOVServer -alias New-HPOVServer
Export-ModuleMember -Function Set-HPOVServerPower
Export-ModuleMember -Function Remove-HPOVServer
Export-ModuleMember -Function Get-HPOVEnclosure
Export-ModuleMember -Function Update-HPOVEnclosure
Export-ModuleMember -Function Add-HPOVEnclosure -Alias New-HPOVEnclosure
Export-ModuleMember -Function Remove-HPOVEnclosure
Export-ModuleMember -Function Get-HPOVEnclosureGroup
Export-ModuleMember -Function New-HPOVEnclosureGroup
Export-ModuleMember -Function Remove-HPOVEnclosureGroup
Export-ModuleMember -Function Get-HPOVServerHardwareType -Alias Get-HPOVServerHardwareTypes
Export-ModuleMember -Function Show-HPOVFirmwareReport

#Storage Systems
Export-ModuleMember -Function Get-HPOVStorageSystem
Export-ModuleMember -Function Update-HPOVStorageSystem
Export-ModuleMember -Function Add-HPOVStorageSystem -Alias New-HPOVStorageSystem
Export-ModuleMember -Function Remove-HPOVStorageSystem
Export-ModuleMember -Function Get-HPOVStoragePool
Export-ModuleMember -Function Add-HPOVStoragePool -Alias New-HPOVStoragePool
Export-ModuleMember -Function Remove-HPOVStoragePool
Export-ModuleMember -Function Get-HPOVStorageVolumeTemplate
Export-ModuleMember -Function New-HPOVStorageVolumeTemplate
Export-ModuleMember -Function Remove-HPOVStorageVolumeTemplate
Export-ModuleMember -Function Get-HPOVStorageVolumeTemplatePolicy 
Export-ModuleMember -Function Set-HPOVStorageVolumeTemplatePolicy 
Export-ModuleMember -Function Get-HPOVStorageVolume
Export-ModuleMember -Function New-HPOVStorageVolume
Export-ModuleMember -Function Remove-HPOVStorageVolume
Export-ModuleMember -Function Get-HPOVSanManager
Export-ModuleMember -Function Add-HPOVSanManager -alias New-HPOVSanManager
Export-ModuleMember -Function Set-HPOVSanManager
Export-ModuleMember -Function Update-HPOVSanManager
Export-ModuleMember -Function Remove-HPOVSanManager
Export-ModuleMember -Function Get-HPOVManagedSan
Export-ModuleMember -Function Set-HPOVManagedSan

#Unmanaged Devices
Export-ModuleMember -Function Get-HPOVUnmanagedDevice
Export-ModuleMember -Function New-HPOVUnmanagedDevice

#Power Devices (iPDUs):
Export-ModuleMember -Function Get-HPOVPowerDevice
Export-ModuleMember -Function Add-HPOVPowerDevice -alias New-HPOVPowerDevice
Export-ModuleMember -Function Remove-HPOVPowerDevice
        
#Networking and Connections:
Export-ModuleMember -Function New-HPOVNetwork
Export-ModuleMember -Function Get-HPOVNetwork
Export-ModuleMember -Function Set-HPOVNetwork
Export-ModuleMember -Function Remove-HPOVNetwork
Export-ModuleMember -Function New-HPOVNetworkSet
Export-ModuleMember -Function Get-HPOVNetworkSet
Export-ModuleMember -Function Get-HPOVNetworkSetCTInfo
Export-ModuleMember -Function Set-HPOVNetworkSet
Export-ModuleMember -Function Remove-HPOVNetworkSet
Export-ModuleMember -Function Get-HPOVInterconnect
Export-ModuleMember -Function Get-HPOVInterconnectType
Export-ModuleMember -Function Get-HPOVLogicalInterconnect
Export-ModuleMember -Function Update-HPOVLogicalInterconnect
Export-ModuleMember -Function Install-HPOVLogicalInterconnectFirmware
Export-ModuleMember -Function Show-HPOVLogicalInterconnectMacTable
Export-ModuleMember -Function Get-HPOVLogicalInterconnectGroup
Export-ModuleMember -Function New-HPOVLogicalInterconnectGroup
Export-ModuleMember -Function Remove-HPOVLogicalInterconnectGroup
Export-ModuleMember -Function Get-HPOVUplinkSet
Export-ModuleMember -Function New-HPOVUplinkSet
Export-ModuleMember -Function Get-HPOVAddressPool
Export-ModuleMember -Function New-HPOVAddressRange
        
#Server Profiles:
Export-ModuleMember -Function Get-HPOVProfile
Export-ModuleMember -Function New-HPOVProfile
Export-ModuleMember -Function Copy-HPOVProfile
Export-ModuleMember -Function Remove-HPOVProfile
Export-ModuleMember -Function Get-HPOVProfileConnectionList
Export-ModuleMember -Function Get-HPOVAvailableServerConnections
Export-ModuleMember -Function New-HPOVProfileConnection
Export-ModuleMember -Function New-HPOVProfileAttachVolume
    
#Index:
Export-ModuleMember -Function Search-HPOVIndex
Export-ModuleMember -Function Search-HPOVAssociations

#Tasks:
Export-ModuleMember -Function Get-HPOVTask
Export-ModuleMember -Function Wait-HPOVTaskStart -alias Wait-HPOVTaskAccepted
Export-ModuleMember -Function Wait-HPOVTaskComplete
#Export-ModuleMember -Function Wait-HPOVTaskAccepted

#Security:
Export-ModuleMember -Function Get-HPOVUser
Export-ModuleMember -Function New-HPOVUser
Export-ModuleMember -Function Set-HPOVUser
Export-ModuleMember -Function Set-HPOVUserPassword
Export-ModuleMember -Function Remove-HPOVUser
Export-ModuleMember -Function Show-HPOVUserSession
Export-ModuleMember -Function Get-HPOVRole
Export-ModuleMember -Function Set-HPOVUserRole -alias Set-HPOVRole
Export-ModuleMember -Function Set-HPOVInitialPassword
Export-ModuleMember -Function Get-HPOVLdap
Export-ModuleMember -Function New-HPOVLdap
Export-ModuleMember -Function New-HPOVLdapServer
Export-ModuleMember -Function Set-HPOVLdapGroupRole
Export-ModuleMember -Function Remove-HPOVLdap
Export-ModuleMember -Function Show-HPOVLdapGroups
Export-ModuleMember -Function Get-HPOVLdapGroup
Export-ModuleMember -Function New-HPOVLdapGroup
Export-ModuleMember -Function Set-HPOVLdapGroup
Export-ModuleMember -Function Remove-HPOVLdapGroup
Export-ModuleMember -Function Get-HPOVAuditLog

#Alerts:
Export-ModuleMember -Function Get-HPOVAlert
Export-ModuleMember -Function Set-HPOVAlert
Export-ModuleMember -Function Set-HPOVAlertAssignToUser
Export-ModuleMember -Function Clear-HPOVAlert

#Licenses
Export-ModuleMember -Function Get-HPOVLicense
Export-ModuleMember -Function New-HPOVLicense

#######################################################
#  Import-Module Processing
#

#######################################################
# Get Library Prompt Setting
#

#Check to see if Global Policy is set first.
$regkeyGlobal = "HKLM:\Software\Hewlett-Packard\HPOneView"
$regkeyUser   = "HKCU:\Software\Hewlett-Packard\HPOneView" 
$regValueName = "Prompt"

#$RegQueryGlobalPrompt = Get-ItemProperty $regkeyGlobal $regValueName -ErrorAction SilentlyContinue
If (Test-Path "HKLM:\Software\Hewlett-Packard\HPOneView") { $RegQueryGlobalPrompt = Get-ItemProperty $regkeyGlobal $regValueName} 

#$RegQueryUserPrompt = Get-ItemProperty $regkeyUser $regValueName -ErrorAction SilentlyContinue
If (Test-Path "HKCU:\Software\Hewlett-Packard\HPOneView"){ $RegQueryGlobalPrompt = Get-ItemProperty $regkeyUser $regValueName} 

#Per User Setting overrides Global
if (($RegQueryUserPrompt) -and ($RegQueryGlobalPrompt)) { $RegQueryPrompt = $RegQueryUserPrompt }
elseif ((! $RegQueryUserPrompt) -and ($RegQueryGlobalPrompt)) { $RegQueryPrompt = $RegQueryGlobalPrompt }
elseif (($RegQueryUserPrompt) -and (!$RegQueryGlobalPrompt)) { $RegQueryPrompt = $RegQueryUserPrompt }

#Create Per-User if it and Global doesn't exist
else {

    $RegQueryPrompt = @{Prompt = "Enabled"}

}

#Control how the Prompt function will behave
$script:HPOneViewLibraryPrompt = ($RegQueryPrompt).Prompt

#Save the users PowerShell Session Prompt state
$Global:prompt_old = Get-Content Function:\prompt
$Script:PromptApplianceHostname = "[Not Connected]"

#Change the PowerShell Prompt
function global:prompt {

    if ($script:HPOneViewLibraryPrompt -eq "Enabled") {

        $cwd = (get-location).Path

        #Disply no more than 2 directories deep in the Prompt, otherwise there will be severe prompt wrapping
        [array]$cwdt=$()
        $cwdi=-1
        do {$cwdi=$cwd.indexofany(“\”,$cwdi+1) ; [array]$cwdt+=$cwdi} until($cwdi -eq -1)

        if ($cwdt.count -gt 3) {
            $cwd = $cwd.substring(0,$cwdt[0]) + “..” + $cwd.substring($cwdt[$cwdt.count-3])
        }

        Write-Host '[HPONEVIEW]: ' -ForegroundColor Yellow -NoNewline
	    if ($global:cimgmtSessionId){
    	    write-host $script:userName@$Script:PromptApplianceHostname PS $cwd>  -NoNewline
	    }
	    else{
		    write-host $Script:PromptApplianceHostname PS $cwd>  -NoNewline
	    }
        return " "

    }

    else { Invoke-Expression $Global:prompt_old }

}

# Import-Module Text
write-host ""
write-host "         Welcome to the HP OneView POSH Library, v$script:scriptVersion"
write-host "         ---------------------------------------------------"
write-host ""
write-host " To get a list of available CMDLETs in this library, type :  " -NoNewline
write-host "Get-Command -module HPOneView.110" -foregroundcolor yellow
write-host " To get help for a specific command, type:                   " -NoNewLine
write-host "get-help " -NoNewLine -foregroundcolor yellow
Write-Host "[verb]" -NoNewLine -foregroundcolor red
Write-Host "-HPOV" -NoNewLine -foregroundcolor yellow
Write-Host "[noun]" -foregroundcolor red
write-host " To get extended help for a specific command, type:          " -NoNewLine
write-host "get-help " -NoNewLine -foregroundcolor yellow
Write-Host "[verb]" -NoNewLine -foregroundcolor red
Write-Host "-HPOV" -NoNewLine -foregroundcolor yellow
Write-Host "[noun]" -NoNewLine -foregroundcolor red
Write-Host " -full" -foregroundcolor yellow
write-host " To update the offline help for this module, type:           " -NoNewLine
write-host "Update-Help -module HPOneView.110" -foregroundcolor yellow
Write-Host ""
Write-Host " Module sample scripts are located at: " -NoNewLine
write-host "$(split-path -parent $MyInvocation.MyCommand.Path)\Samples" -ForegroundColor yellow
write-host ""
write-host " If you need further help, please consult one of the following:" -ForegroundColor Green
write-host ""
write-host "  • Get-Help about_HPOneView.110"
Write-host "  • Online documentation at https://github.com/HewlettPackard/POSH-HPOneView/wiki"
Write-host "  • Online Issues Tracker at https://github.com/HewlettPackard/POSH-HPOneView/issues"
write-host ""
write-host " Copyright (C) 2015 Hewlett-Packard"
if ((Get-Host).UI.RawUI.MaxWindowSize.width -lt 150) {
    write-host ""
    write-host " Note: Set your PowerShell console width to 150 to properly view report output. (Current Max Width: $((Get-Host).UI.RawUI.MaxWindowSize.width))" -ForegroundColor Green
}
write-host ""

#######################################################
#  Remove-Module Processing
#

$ExecutionContext.SessionState.Module.OnRemove = {

    Write-Verbose "[$($MyInvocation.InvocationName.ToString().ToUpper())] Cleaning up"

    #Restore default prompt
    Set-Content Function:\prompt $Global:prompt_old

    if ([System.Net.ServicePointManager]::CertificatePolicy) {

        #Restore System.Net.ServicePointManager
        [System.Net.ServicePointManager]::CertificatePolicy = $Null

    }

}