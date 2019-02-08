##############################################################################
# Configure_IIS_WebDav_ExternalRepo_Sample.ps1
# - Configure IIS WebDav server to support OneView 3.10 External Repository.
#   Windows Server 2012 R2 or Windows Server 2016
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

    [Parameter (Mandatory = $false, HelpMessage = "The IIS website name.  Defaults to 'Default Web Site'.")]
    [ValidateNotNullorEmpty()]
    [String]$WebsiteName = 'Default Web Site',

    [Parameter (Mandatory, HelpMessage = "Specify the phyiscal path of the virtual directory.")]
    [ValidateNotNullorEmpty()]
    [String]$Path,

    [Parameter (Mandatory = $false, HelpMessage = "Specify the Virtual Directory Name.")]
    [ValidateNotNullorEmpty()]
    [String]$VirtualDirectoryName = "HPOneViewRemoteRepository",

    [Parameter (Mandatory, HelpMessage = "Specify the max size in GB for the repository.")]
    [ValidateNotNullorEmpty()]
    [Int]$Size,

    [Parameter (Mandatory = $false, HelpMessage = "Specify the max size in GB for the repository.")]
    [Switch]$RequireSSL

)

function Test-IsAdmin 
{

    ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

}

if (-not(Test-IsAdmin))
{

    Write-Error -Message "Please run this script within an elevated PowerShell console." -Category AuthenticationError -ErrorAction Stop

}

$ErrorActionPreference = "Stop"
$FeatureName = 'Web-DAV-Publishing'

if (-not(Get-WindowsFeature -Name Web-Server).Installed)
{

    Write-Error -Message 'IIS is required to be installed.  Please install the Web-Server feature on this host.' -Category NotInstalled -TargetObject 'WindowsFeature:Web-Server'

}


if (-not(Get-WindowsFeature -Name $FeatureName).Installed)
{

    Stop-Service w3svc

    Write-Host 'Installing WebDAV' -ForegroundColor Cyan

    Try
    {
    
        $resp = Install-WindowsFeature -Name $FeatureName -IncludeManagementTools

        if ($resp.RestartNeeded -eq 'Yes')
        {

            Write-Warning "A reboot is needed to complete installation.  Please reboot the server, and re-run this script.  It will continue the configuration of WebDAV."

        }
    
        Write-Host 'Done.' -ForegroundColor Green

    }
    
    Catch
    {
    
        $PSCmdlet.ThrowTerminatingError($_)
    
    }

    Start-Service w3svc

}

if ((Get-WindowsFeature -Name $FeatureName).Installed -and $resp.RestartNeeded -ne 'Yes')
{

    if (-not(Get-WindowsFeature -Name Web-Dir-Browsing).Installed)
    {

        Write-Host 'Installing IIS Directory Browsing' -ForegroundColor Cyan

        Try
        {
        
            $null = Install-WindowsFeature -Name Web-Dir-Browsing -IncludeManagementTools
        
            Write-Host 'Done.' -ForegroundColor Green

        }
        
        Catch
        {
        
            $PSCmdlet.ThrowTerminatingError($_)
        
        }

    }

    Import-Module WebAdministration

    #Add Virtual Directory
    Try
    {

        if (-not(Test-Path IIS:\Sites\$WebsiteName\$VirtualDirectoryName))
        {

            $null = New-WebVirtualDirectory -Site $WebsiteName -Name $VirtualDirectoryName -PhysicalPath $Path

        }    

    }

    Catch
    {

        $PSCmdlet.ThrowTerminatingError($_)

    }

    #Check and enable Directory Browsing on the Virtual Directory
    if (-not(Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Location "$WebsiteName/$VirtualDirectoryName" -Name enabled).Value)
    {

        $null = Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Location "$WebsiteName/$VirtualDirectoryName" -Name enabled -Value $true

    }

    #Add custom HTTP Header for reposize
    Try
    {

        if (-not(Get-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders -Location $WebsiteName -Name collection[name="MaxRepoSize"]))
        {

            $null = Add-WebConfigurationProperty -PSPath ('MACHINE/WEBROOT/APPHOST/{0}' -f $WebsiteName) -Filter 'system.WebServer/httpProtocol/customHeaders' -Name . -Value @{name='MaxRepoSize'; value=('{0}G' -f $Size.ToString())} -ErrorAction Stop

        }

        elseif ((Get-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders -Location $WebsiteName -Name collection[name="MaxRepoSize"]).Value -ne $Size.ToString())
        {

            $null = Set-WebConfigurationProperty -PSPath ('MACHINE/WEBROOT/APPHOST/{0}' -f $WebsiteName) -Filter '/system.WebServer/httpProtocol/customHeaders' -Name . -Value @{name='MaxRepoSize'; value=('{0}G' -f $Size.ToString())} -ErrorAction Stop

        }

    }

    Catch
    {

        $PSCmdlet.ThrowTerminatingError($_)

    }

    #Add required MIME types
    Try
    {

        if (-not(Get-WebConfigurationProperty -Filter //staticContent -Location $WebsiteName -Name collection[fileExtension=".iso"]))
        {

            Add-webconfigurationproperty -Filter "//staticContent" -PSPath ("IIS:\Sites\{0}" -f $WebsiteName) -name collection -value @{fileExtension='.iso'; mimeType='application/octet-stream'} 
        
        }

        if (-not(Get-WebConfigurationProperty -Filter //staticContent -Location $WebsiteName -Name collection[fileExtension=".scexe"]))
        {

            Add-webconfigurationproperty -Filter "//staticContent" -PSPath ("IIS:\Sites\{0}" -f $WebsiteName) -name collection -value @{fileExtension='.scexe'; mimeType='application/octet-stream'} 
        
        }
        
        if ((Get-WebConfigurationProperty -Filter //staticContent -Location $WebsiteName -Name collection[fileExtension=".rpm"]).mimeType -ne "application/octet-stream")
        {

            Set-WebConfigurationProperty -Filter "//staticContent/mimeMap[@fileExtension='.rpm']" -PSPath ("IIS:\Sites\{0}" -f $WebsiteName) -Name mimeType -Value "application/octet-stream"

        }
        

    }

    Catch
    {

        $PSCmdlet.ThrowTerminatingError($_)

    }

    #Set WebDAV Access Rules
    Try
    {
        
        $NewRule = @{

            users  = "*";
            path   = "*";
            access = "Read"

        }

        if (-not(Get-WebConfigurationProperty -Filter system.webServer/webdav/authoringRules -Location $WebsiteName -Name collection[users="*"]))
        {

            $null = Add-WebConfiguration -Filter system.webServer/webdav/authoringRules -PSPath "MACHINE/WEBROOT/APPHOST" -Location $WebsiteName -Value $NewRule

        }   

        if (-not(Get-WebConfigurationProperty -filter 'system.webServer/webdav/authoring' -Location $WebsiteName -Name Enabled).Value)
        {

            [void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration")

            $IIS = new-object Microsoft.Web.Administration.ServerManager
            $WebSite = $IIS.Sites["Default Web Site"]

            $GlobalConfig = $IIS.GetApplicationHostConfiguration()
            $Config = $GlobalConfig.GetSection("system.webServer/webdav/authoring", "Default Web Site")

            if ($Config.OverrideMode -ne 'Allow')
            {

                $Config.OverrideMode = "Allow"
                $null = $IIS.CommitChanges()

            }

            Write-Host "Enabling WebDAV" -ForegroundColor Cyan
            Set-WebConfigurationProperty -filter 'system.webServer/webdav/authoring' -Location $WebsiteName -Name enabled -Value $true
            Write-Host "Done." -ForegroundColor Green

        }

        if (-not(Get-WebConfigurationProperty -filter 'system.webServer/webdav/authoring' -Location $WebsiteName -Name requireSsl).Value -and (Get-WebConfigurationProperty -filter 'system.webServer/webdav/authoring' -Location $WebsiteName -Name requireSsl).Value -ne $RequireSSL.IsPresent)
        {

            Write-Host "Enabling WebDAV SSL" -ForegroundColor Cyan
            Set-WebConfigurationProperty -filter 'system.webServer/webdav/authoring' -Location $WebsiteName -Name requireSsl -Value $RequireSSL.IsPresent
            Write-Host "Done." -ForegroundColor Green

        }

        #Enable WebDAV properties required
        Set-WebConfigurationProperty -Filter system.webServer/webdav/authoring -PSPath "MACHINE/WEBROOT/APPHOST" -Location $WebsiteName -name properties.allowAnonymousPropFind -Value $true
        Set-WebConfigurationProperty -Filter system.webServer/webdav/authoring -PSPath "MACHINE/WEBROOT/APPHOST" -Location $WebsiteName -name properties.allowInfinitePropfindDepth -Value $true


    }

    Catch
    {

        $PSCmdlet.ThrowTerminatingError($_)

    }

}