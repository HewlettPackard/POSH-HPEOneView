##############################################################################
# ConfigureRemoteSupport_Sample.ps1
# - Example script to configure Remote Support
#
#   VERSION 1.0
#
# (C) Copyright 2013-2019 Hewlett Packard Enterprise Development LP 
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

    [Parameter (Mandatory, HelpMessage = "Provide the Company Name.", ParameterSetName = 'Default')]
    [Parameter (Mandatory, HelpMessage = "Provide the Company Name.", ParameterSetName = 'Default')]
    [ValidateNotNullorEmpty()]
	[String]$CompanyName,

	[Parameter (Mandatory = $false, HelpMessage = "Use to enable HPE marketing emails.", ParameterSetName = 'Default')]
	[Parameter (Mandatory = $false, HelpMessage = "Use to enable HPE marketing emails.", ParameterSetName = 'InsightOnline')]
	[Switch]$MarketingOptIn,

	[Parameter (Mandatory, HelpMessage = "Provide the authorized HPE Passport account to register the appliance with Insight Online.", ParameterSetName = 'InsightOnline')]
	[ValidateNotNullorEmpty()]
	[String]$InsightOnlineUsername = 'MyPassportAccount@domain.com',

	[Parameter (Mandatory, HelpMessage = "Provide the authorized HPE Passport account password to register the appliance with Insight Online.", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
	[securestring]$InsightOnlinePassword = (ConvertTo-SecureString -String 'MyPassword' -AsPlainText -Force),

	[Parameter (Mandatory, HelpMessage = "Provide the default site Address.", ParameterSetName = 'Default')]
	[Parameter (Mandatory, HelpMessage = "Provide the default site Address.", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
	[String]$AddressLine1,

	[Parameter (Mandatory = $false, HelpMessage = "Provide the default site Address.", ParameterSetName = 'Default')]
	[Parameter (Mandatory = $false, HelpMessage = "Provide the default site Address.", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
	[String]$AddressLine2,

	[Parameter (Mandatory, HelpMessage = "Provide the default site City.", ParameterSetName = 'Default')]
	[Parameter (Mandatory, HelpMessage = "Provide the default site City.", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
	[String]$City,

	[Parameter (Mandatory, HelpMessage = "Provide the default site State or Provence.", ParameterSetName = 'Default')]
	[Parameter (Mandatory, HelpMessage = "Provide the default site State or Provence.", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
	[String]$State,

	[Parameter (Mandatory, HelpMessage = "Provide the default site Postal or Zip code.", ParameterSetName = 'Default')]
	[Parameter (Mandatory, HelpMessage = "Provide the default site Postal or Zip code.", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
	[String]$PostalCode,

    [Parameter (Mandatory, HelpMessage = "Provide the default site Country.", ParameterSetName = 'Default')]
    [Parameter (Mandatory, HelpMessage = "Provide the default site Country.", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
    [String]$Country,

    [Parameter (Mandatory, HelpMessage = "Provide the default site Timezone.", ParameterSetName = 'Default')]
    [Parameter (Mandatory, HelpMessage = "Provide the default site Timezone.", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
    [String]$TimeZone,

	[Parameter (Mandatory = $false, HelpMessage = "Provide the primary Remote Support contact as a Hashtable.  Example: @{FirstName = 'Bob'; LastName = 'Smith'; Email = 'bob.smith@domain.com'; PrimaryPhone = '123-456-7890'; Language = 'en'; Default = `$true}", ParameterSetName = 'Default')]
	[Parameter (Mandatory = $false, HelpMessage = "Provide the primary Remote Support contact as a Hashtable.  Example: @{FirstName = 'Bob'; LastName = 'Smith'; Email = 'bob.smith@domain.com'; PrimaryPhone = '123-456-7890'; Language = 'en'; Default = `$true}")]
    [ValidateNotNullorEmpty()]
    [ValidateNotNullorEmpty()]
	[Hashtable]$PrimaryContact,

	[Parameter (Mandatory = $false, HelpMessage = "Provide the secondary Remote Support contact as a Hashtable.  Example: @{FirstName = 'Bob'; LastName = 'Smith'; Email = 'bob.smith@domain.com'; PrimaryPhone = '123-456-7890'; Language = 'en'; Default = `$true}", ParameterSetName = 'Default')]
	[Parameter (Mandatory = $false, HelpMessage = "Provide the secondary Remote Support contact as a Hashtable.  Example: @{FirstName = 'Bob'; LastName = 'Smith'; Email = 'bob.smith@domain.com'; PrimaryPhone = '123-456-7890'; Language = 'en'; Default = `$true}")]
    [ValidateNotNullorEmpty()]
	[Hashtable]$SecondaryContact,

	[Parameter (Mandatory = $false, HelpMessage = "Provide the Remote Support Reseller Partner as a Hashtable.  Example: @{Name = 'My Reseller Partner'; Type = 'Reseller'; ResellerID = 1234567}", ParameterSetName = 'Default')]
	[Parameter (Mandatory = $false, HelpMessage = "Provide the Remote Support Reseller Partner as a Hashtable.  Example: @{Name = 'My Reseller Partner'; Type = 'Reseller'; ResellerID = 1234567}", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
    [Hashtable]$ResellerPartner,

	[Parameter (Mandatory = $false, HelpMessage = "Provide the secondary Remote Support contact as a Hashtable.  Example: @{Name = 'My Support Partner'; Type = 'Support'; ResellerID = 098765}", ParameterSetName = 'Default')]
	[Parameter (Mandatory = $false, HelpMessage = "Provide the secondary Remote Support contact as a Hashtable.  Example: @{Name = 'My Support Partner'; Type = 'Support'; ResellerID = 098765}", ParameterSetName = 'InsightOnline')]
    [ValidateNotNullorEmpty()]
    [Hashtable]$SupportPartner



)

if (-not (Get-Module HPOneView.410)) 
{

    Import-Module POSH-HPOneView.410

}

if (-not $ConnectedSessions) 
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-HPOVMgmt -Hostname $Appliance -Username $Username -Password $Password

}

"Connected to appliance: {0} " -f ($ConnectedSessions | ? Default).Name | Write-Host

#Add Primary (Default) Remote Support Contact
New-HPOVRemoteSupportContact @PrimaryContact

if ($PSBoundParameters['SecondaryContact'])
{

    New-HPOVRemoteSupportContact @SecondaryContact

}

#Set the datacenter site address
$DefaultSiteParams = @{

    AddressLine1 = $AddressLine1;
    State        = $State;
    City         = $City;
    PostalCode   = $PostalCode;
    Country      = $Country;
    TimeZone     = $TimeZone

}

if ($PSBoundParameters['AddressLine2'])
{

    $DefaultSiteParams.Add('AddressLine2',$AddressLine2)

}

Set-HPOVRemoteSupportDefaultSite @DefaultSiteParams

#Add a new Reseller Partner
if ($PSBoundParameters['ResellerPartner'])
{

    New-HPOVRemoteSupportPartner @ResellerPartner

}

#Add a new Support Partner
if ($PSBoundParameters['SupportPartner'])
{

    New-HPOVRemoteSupportPartner @SupportPartner

}

#Register and authorize the appliance with your Company Name.  Uncomment the end to enable Insight Online portal registration.
$EnableRemoteSupportParams = @{

    CompanyName = $CompanyName;
    MarketingOptIn = $MarketingOptIn.IsPresent

}

if ($PSCmdlet.ParameterSetName -eq 'InsightOnline')
{

    $EnableRemoteSupportParams.Add('InsightOnlineUsername', $InsightOnlineUsername)
    $EnableRemoteSupportParams.Add('InsightOnlinePassword', $InsightOnlinePassword)

}

Set-HPOVRemoteSupport @EnableRemoteSupportParams

