##############################################################################
# Wipe_Appliance.ps1
# - Remove ALL resource from an appliance (useful to clean a system between demos).
#
#   VERSION 3.00
#
# (C) Copyright 2013-2023 Hewlett Packard Enterprise Development LP
##############################################################################
# The information contained herein is subject to change without notice.
# The only warranties for HP products and services are set forth in the
# express warranty statements accompanying such products and services.
# Nothing herein should be construed as constituting an additional warranty.
# HP shall not be liable for technical or editorial errors or omissions
# contained herein.
#
##############################################################################
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param
(

    [Parameter (Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$Hostname,

    [Parameter (Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$Username,

    [Parameter (Mandatory)]
    [ValidateNotNullorEmpty()]
    [Object]$Password

)

if ($PSCmdlet.ShouldProcess($Hostname,("remove all resources on appliance")))
{

    if (! (Get-Module -Name 'HPEOneView.630'))
    {

        Import-Module HPEOneView.630

    }

    # First connect to the CI Management Appliance (if not already connected)
    if (! $ConnectedSessions)
    {

        Try
        {

            $Params = @{

                Hostname = $Hostname;
                Username = $Username;
                Password = $Password

            }

            Connect-OVMgmt @Params

        }

        Catch
        {

            PSCmdlet.ThrowTerminatingError($_)

        }

    }

    Try
    {

        ############################################################
        #  REMOVE CONFIGURATION (for cleanup after/between demos)  #
        ############################################################

        # Delete ALL Server Profiles
        $tasks = Get-OVServerProfile | Remove-OVServerProfile -Force -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Server Profile tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Server Profile Templates
        $tasks = Get-OVServerProfileTemplate | Remove-OVServerProfileTemplate -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Server Profile Template tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Remove ALL iPDUs
        $tasks = Get-OVPowerDevice | Remove-OVPowerDevice -Force -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Power Device tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Remove ALL Enclosures
        $tasks = Get-OVEnclosure | Remove-OVEnclosure -Force -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Enclosure tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Remove ALL Rack Servers
        $tasks = Get-OVServer | Remove-OVServer -Force -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Server Hardware Resources tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Enclosure Groups:
        $tasks = Get-OVEnclosureGroup | Remove-OVEnclosureGroup -Force -Confirm:$false

        if ($tasks | ? Message -ne 'Resource deleted successfully.') {

            $Tasks | ? Message -ne 'Resource deleted successfully.' | Format-List

            Write-Error '1 or more Remove Enclosure Group requests failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Logical Interconnect Groups
        $tasks = Get-OVLogicalInterconnectGroup | Remove-OVLogicalInterconnectGroup -Force -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Logical Interconnect Group tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Network-Sets
        $tasks = Get-OVNetworkSet | Remove-OVNetworkSet -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Network Set tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Networks
        $tasks = Get-OVNetwork | Remove-OVNetwork -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Network tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Storage Volumes
        $tasks = Get-OVStorageVolume | Remove-OVStorageVolume -Force -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Storage Volume tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Storage Pools
        $tasks = Get-OVStoragePool | Remove-OVStoragePool -Force -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Storage Pool tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Storage Systems
        $tasks = Get-OVStorageSYstem | Remove-OVStorageSystem -Force -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove Storage System tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL SAN Managers
        $tasks = Get-OVSanManager | Remove-OVSanManager -Confirm:$false | Wait-OVTaskComplete

        if ($tasks | ? taskState -ne 'Completed') {

            $Tasks | ? taskState -ne 'Completed' | Format-List

            Write-Error '1 or more Remove SAN Manager tasks failed to complete successfully.' -ErrorAction Stop

        }

        # Delete ALL Unmanaged Devices
        $tasks = Get-OVUnmanagedDevice | Remove-OVUnmanagedDevice -Force -Confirm:$false

        if ($tasks | ? Message -ne 'Resource deleted successfully.') {

            $Tasks | ? Message -ne 'Resource deleted successfully.' | Format-List

            Write-Error '1 or more Remove Unmanaged Device requests failed to complete successfully.' -ErrorAction Stop

        }

    }

    Catch
    {

        $PSCmdlet.ThrowTerminatingError($_)

    }

}

elseif ($PSBoundParameters['Whatif'])
{

    "[{0}] -WhatIf provided." -f $MyInvocation.InvocationName.ToString().ToUpper() | Write-Verbose

}

else
{

    "[{0}] User cancelled." -f $MyInvocation.InvocationName.ToString().ToUpper() | Write-Verbose

}