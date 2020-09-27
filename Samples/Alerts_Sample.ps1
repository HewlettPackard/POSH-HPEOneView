##############################################################################
# Alerts_Sample.ps1
# - Example scripts for creating a user account, and retrieving alerts specific
#   to the new user.
#
#   VERSION 3.1
#
# (C) Copyright 2013-2020 Hewlett Packard Enterprise Development LP
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
if (-not (get-module HPEOneView.540))
{

    Import-Module HPEOneView.540

}

# First connect to the HP OneView appliance.
if (-not $ConnectedSessions)
{

	$Appliance = Read-Host 'ApplianceName'
	$Username  = Read-Host 'Username'
	$Password  = Read-Host 'Password' -AsSecureString

    $ApplianceConnection = Connect-OVMgmt -Hostname $Appliance -Username $Username -Password $Password

}

# Make sure we have a local user 'Sally'
$sally = Get-OVUser -Name Sally -ErrorAction SilentlyContinue

If (-not $sally)
{

	Write-Host 'User Sally does not exist. Creating user account.'

	Try
	{

		New-OVUser -Username Sally -fullName "Sally Test User" -password SallyPassword -Roles "Network administrator"

	}

	Catch
	{

		Write-Error -ErrorRecord $_ -EA Stop

	}

}

Catch
{

	Write-Error -ErrorRecord $_ -EA Stop

}

# Now view the list of alerts
# Note: If there is a large set of alerts on the appliance, calling Get-OVAlert (without any filters)
# can take a VERY long time!  This query really needs to be filtered by category, state, etc.
Try
{

	Get-OVAlert

}

Catch
{

	Write-Error -ErrorRecord $_ -EA Stop

}

# Let's assign any Interconnect Bay alerts to Administrator

Try
{

	$alerts = Get-OVAlert -healthCategory Logical-Interconnect -alertState Active

}

Catch
{

	Write-Error -ErrorRecord $_ -EA Stop

}

foreach ($alert in $alerts)
{

	Try
	{

		$updatedAlert = Set-OVAlert -InputObject $alert -AssignToUser Sally

		"Assigned to Sally: {0}" -f $updatedAlert.description | Write-Host

	}

	Catch
	{

		Write-Error -ErrorRecord $_ -EA Stop

	}

}

# Clear any alerts older than one week
$alerts = Get-OVAlert -AlertState Active

foreach ($alert in $alerts)
{

    $created = Get-Date $alert.created

    if ((Get-Date) -gt $created.AddDays(7))
	{

		Try
		{

			$updatedAlert = Clear-OVAlert $alert

			"Cleared from {0} : {1}" -f $created,$updatedAlert.description | Write-Host

		}

		Catch
		{

			Write-Error -ErrorRecord $_ -EA Stop

		}

    }

}

#Display the active alerts for Sally, most recent first
Write-Host "Sally's active alerts:"

Get-OVAlert -AssignedToUser Sally -AlertState Active
