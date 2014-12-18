##############################################################################
# ApplianceConfig_Sample.ps1
# - Example scripts for configuring the HP OneView appliance (networking, NTP, 
#   etc.).
#
#   VERSION 1.0
#
# (C) Copyright 2014 Hewlett-Packard Development Company, L.P.
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
Import-Module HPOneView.120

# NOTE: replace the IP address, below, with the current IP address of the 
# appliance to be configured.  If this is an initial setup of the appliance,
# use the DHCP-configured IP, as seen in the Summary tabe of vSphere for the 
# appliance VM.
$global:myApplianceIP = "192.0.2.20"
$global:mySupportAccess = "yes" # Allow HP support access to appliance

# NOTE: Replace all values below with actual desired appliance configuration:
$global:myHostname = "myappliance.example.com" # Fully-qualified DNS name
# IPv4 Config
$global:myIpv4Type = "DHCP"    # "DHCP", "STATIC" or "UNCONFIGURE"
$global:myIpv4Addr = ""        # "www.xxx.yyy.zzz" (blank for DHCP)
$global:myIpv4Subnet = ""      # "www.xxx.yyy.zzz" (blank for DHCP)
$global:myIpv4Gateway = ""     # "www.xxx.yyy.zzz" (blank for DHCP)
# IPv6 Config
$global:myIpv6Type = "UNCONFIGURE" # "DHCP", "STATIC" or "UNCONFIGURE"
$global:myIpv6Addr = ""        # "ssss:tttt:uuuu:vvvv:wwww:xxxx:yyyy:zzzz"
$global:myIpv6Subnet = ""      # "ffff:ffff:ffff:ffff:0:0:0:0"
$global:myIpv6Gateway = ""     # "ssss:tttt:uuuu:vvvv:wwww:xxxx:yyyy:zzzz"
# DNS Config
$global:myDomainName = "example.com"
$global:mySearchDomains = @()  # "example.com", "example.net"
$global:ipV4nameServers = @()  # "192.0.2.2", "192.0.2.3"
$global:ipV6nameServers = @()  # "fe80::200:f8ff:fe21:67cf", "fe80::200:f8ff:fe21:89cb"
# Appliance Time/NTP Configuration
$global:myNtpServers = @()     # "ntp.local.com", "backup.ntp.com"

# First check if the EULA has been accepted
if (Get-HPOVEulaStatus -appliance $global:myApplianceIP) {
    Write-Host "Accepting EULA..."
    Set-HPOVEulaStatus $mySupportAccess -appliance $global:myApplianceIP
}
# Next connect to the HP OneView appliance.
#

# For initial setup, connect first using "default" Administrator credentials:
$ret = Connect-HPOVMgmt -appliance $global:myApplianceIP -user "Administrator" -password "admin"
if ([int]$ret.statusCode -eq 403) 
{
    # Initial setup - password change required:
    Write-Host "Update password - enter new adminstrator password"
    Set-HPOVInitialPassword -userName "Administrator" -oldPassword "admin"
}
# Now, connect again, normally, with new password:
Connect-HPOVMgmt -appliance $global:myApplianceIP

# Update appliance networking configuration
$params = @{
    hostname        = $global:myHostname;
    ipv4Type        = $global:myIpv4Type;
    ipv4Addr        = $global:myIpv4Addr;
    ipv4Subnet      = $global:myIpv4Subnet;
    ipv4Gateway     = $global:myIpv4Gateway;
    ipv6Type        = $global:myIpv6Type;
    ipv6Addr        = $global:myIpv6Addr;
    ipv6Subnet      = $global:myIpv6Subnet;
    ipv6Gateway     = $global:myIpv6Gateway;
    domainName      = $global:myDomainName; `
    searchDomains   = $global:mySearchDomains;
    ipV4nameServers = $global:ipV4nameServers;
    ipV6nameServers = $global:ipV6nameServers;
    ntpServers      = $global:myNtpServers
}

Set-HPOVApplianceNetworkConfig @params