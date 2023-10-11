TOPIC

    about_HPEOneView.830

COPYRIGHT

    (C) Copyright 2013-2023 Hewlett Packard Enterprise Development LP

LICENSE

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

SHORT DESCRIPTION

    PowerShell library for HPE OneView 8.30

WHAT'S NEW

   Release 8.30.3660.2366

      -- [#647] Fixed ConvertTo-OVPowerShellScript mishandling BIOS consistency policy
         when parsing a server profile template.
      -- [#642] Fixed incorrect use of internal variable within Update-OVServerFirmware.
      -- [#654] Fixed ConvertTo-OVPowerShellScript mishandling Tunnel uplink set resources.
      -- [#656] Fixed parameter evaluation bug with Update-OVServerProfile and the -Stage
         parameter.
      -- Added Update-OVRemoteSupportEntitlement Cmdlet to refresh remote support
         entitlement data with the backend.
      -- Added MegaRAID support to New-OVServerProfileLogicalDiskController.
      -- Added Get-OVServerHardwareAvailableController to return discovered disk drive
         controllers for volume servers (DL, ML, Apollo) and drives.  New classes added
         HPEOneView.Servers.StorageController and HPEOneView.Servers.PhysicalDrive.
      -- Added the ability to specify controller returned from Get-OVServerHardwareAvailableController.
      -- Added the ability to specify specific drives in New-OVServerProfileLogicalDisk
         after invoking Get-OVServerHardwareAvailableController to get list of controllers
         and available drives that are part of the HPEOneView.Servers.StorageController.Drives
         property.
      -- Updated core library to handle web proxy in a more efficient method.
      -- Updated core library to use TLS1.2 only.

   Release 8.30.3534.1611

      -- Support for PowerShell 5 and 6 is now deprecated and is no longer supported.
      -- Added workaround to supporting Gen10 Plus V2 platforms and supporting
         firmware management.
      -- Added Update-OVRemoteSupportEntitlement Cmdlet to refresh remote support
         entitlement data with the backend.
      -- Updated Get-OVTask to support multiple values for -State parameter, which
         will perform an OR operation with the target API.

   Release 8.30.3515.1690

      -- Initial HPE OneView 8.30 library release.
      -- [#633] Fixed mishandling of network sets when assigned to a profile
         connection and processing with ConvertTo-OVPowerShellScript.
      -- [#634] Fixed missing -IloHostname parameter in ConvertTo-OVPowerShellScript
         when processing either a server profile template or server profile object.
      -- [#637] Fixed generating user role output in ConvertTo-OVPowerShellScript.
      -- [#638] Fixed Set-OVNetworkSet inadvertantly trying to change the network set
         type to REGULAR.

LONG DESCRIPTION

    This library provides HP OneView management capabilities for Windows PowerShell.
    The library can be used as either a CLI or using the core cmdlets to call from
    wrapper scripts.  The core cmdlets are:

      -- Connect-OVMgmt
      -- Send-OVRequest
      -- New-OVResource
      -- Set-OVResource
      -- Remove-OVResource

    A set of sample scripts are also provided, that show how to fully configure an
    HP OneView appliance from the ground up.

    For information regarding this project, to request features or report
    issues, please see: https://github.com/HewlettPackard/POSH-HPEOneView/issues


SEE ALSO

    https://github.com/HewlettPackard/POSH-HPEOneView
    https://hpe-docs.gitbook.io/posh-hpeoneview
    http://hpe.com/info/oneviewcommunity
    Update-Help HPEOneView.830
    Get-Help about_Appliance_Connections
    Get-Help about_Appliance_Connection_Permissions
    Get-Help about_Two_Factor_Authentication
    Get-Help Connect-OVmgmt
    Get-Help Send-OVRequest
    [install_dir]\Samples



