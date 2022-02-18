<#
.SYNOPSIS
    Exports logs from and removes an entire AVD Blueprint deployment
.DESCRIPTION
    Exports logs found in an AVD Blueprint deployment's Log Analytics Workspace to a csv file stored in the directory specified at runtime    

    Finds and removes the following items that were previously deployed via AVD Blueprint:
    - All SessionHosts and HostPools in a ResourceGroup based on resource prefix
    - All users discovered in 'AVD Users' group
    - 'AVD Users' group itself
    - 'AAD DC Admins' group

    
    Use of -verbose, -whatif or -comfirm ARE supported.

    Note: The script will create one Powershell Job for each Resource Group being removed

    
.LINK
    https://github.com/Azure/AVDBlueprint

.EXAMPLE
    .\Remove-AzAvdBpDeployment.ps1 -Verbose -Prefix "ABC" -LogPath "C:\projects"

    Exports logs of an AVD Blueprint deployment that used the prefix "ABC" followed by a removal of that deployment

.EXAMPLE
    .\Remove-AzAvdBpDeployment.ps1 -Verbose -Prefix "ABC" -DisableLogExport

    Performs a removal of an AVD Blueprint deployment that used the prefix "ABC" without first exporting the deployment's logs

.INPUTS
    None. You cannot pipe objects into this script.

.OUTPUTS
    None. Only console text is displayed by this script.

    Note: if a cleanup is performed, it is in the context of a Powershell Job after this script completes
#>

[CmdletBinding(SupportsShouldProcess=$true)]
Param(
    #The prefix used to match against Azure resources for inclusion in this cleanup
    [Parameter(Mandatory=$true)]
    [string] $Prefix,
    #Switch to override the default behavior of exporting a target environment's logs prior to cleanup
    [Parameter(Mandatory=$true, ParameterSetName="DisableLogExport")]
    [switch] $DisableLogExport,
    #Path to the folder where the target environment's logs should be copied
    [Parameter(Mandatory=$true, ParameterSetName="LogExport")]
    [string] $LogPath,
    #Switch to purge key vault, not just soft delete
    [Parameter()]
    [switch] $PurgeKeyVault
)


#Trying to work around an issue where the modules were previously installed but don't report that way to PowerShell
Write-Verbose "Checking PowerShell modules needed to run this script"
if (-not(Get-Module -Name 'Az.Keyvault')) {
    Import-Module -Name 'Az.Keyvault' -Force
    }
    if (-not(Get-Module -Name 'Az.Keyvault')) {
    Install-Module 'Az.Keyvault' -Force
    Import-Module -Name 'Az.Keyvault' -Force
}
if (-not(Get-Module -Name 'Az.Storage')) {
    Import-Module -Name 'Az.Storage' -Force
    }
    if (-not(Get-Module -Name 'Az.Storage')) {
    Install-Module 'Az.Storage' -Force
    Import-Module -Name 'Az.Storage' -Force
}
if (-not(Get-Module -Name 'Az.Resources')) {
    Import-Module -Name 'Az.Resources' -Force
    }
    if (-not(Get-Module -Name 'Az.Resources')) {
    Install-Module 'Az.Resources' -Force
    Import-Module -Name 'Az.Resources' -Force
}
if (-not(Get-Module -Name 'Az.OperationalInsights')) {
    Import-Module -Name 'Az.OperationalInsights' -Force
    }
    if (-not(Get-Module -Name 'Az.OperationalInsights')) {
    Install-Module 'Az.OperationalInsights' -Force
    Import-Module -Name 'Az.OperationalInsights' -Force
}
if (-not(Get-Module -Name 'AzureAD')) {
    Import-Module -Name 'AzureAD' -Force
    }
    if (-not(Get-Module -Name 'AzureAD')) {
    Install-Module 'AzureAD' -Force
    Import-Module -Name 'AzureAD' -Force
}
if (-not(Get-Module -Name 'Az.DesktopVirtualization')) {
    Import-Module 'Az.DesktopVirtualization' -Force
    }
    if (-not(Get-Module -Name 'Az.DesktopVirtualization')) {
    Install-Module 'Az.DesktopVirtualization' -Force
    Import-Module 'Az.DesktopVirtualization' -Force
}

$RemovalScope = Get-AzResourceGroup | Where-Object {$_.ResourceGroupName -like "$($Prefix)*"} 
Write-Verbose "Found $($RemovalScope.count) Resource Groups"

$RemovalScope | ForEach-Object {
    $ThisRG = $_
    $AllLocks = Get-AzResourceLock -ResourceGroupName $ThisRG.ResourceGroupName
    Write-Verbose "Found $($AllLocks.count) locks"
    $AllLocks | ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.Name, "Remove Lock")) {
            Remove-AzResourceLock -LockId $_.LockId -Force    
        }
    }

    $hp = Get-AzWvdHostPool -ResourceGroupName $ThisRG.ResourceGroupName
    Write-Verbose "Found $($hp.count) Host Pools"
    $hp | ForEach-Object {
        $ThisHP = $_
        Write-Verbose "Processing Host Pool $($ThisHP.Name) for Session Hosts"
        $sh = Get-AzWvdSessionHost -HostPoolName $ThisHP.Name -ResourceGroupName $ThisRG.ResourceGroupName
        Write-Verbose "Found $($sh.count) Session Hosts"
        $sh | ForEach-Object {
            #Workaround due to mismatch in Name formats between Get-AzWvdSessionHost and Remove-AzWvdSessionHost
            $ThisSH = ($_.Name -split "/")[1]

            if($PSCmdlet.ShouldProcess($ThisSH,"Remove Session Host")){
                Remove-AzWvdSessionHost -HostPoolName $ThisHP.Name -ResourceGroupName $ThisRG.ResourceGroupName -Name $ThisSH
            }
        }
        Write-Verbose "Processing Host Pool $($ThisHP.Name) for Application Groups"
        $ag = ($ThisHP | Select-Object -ExpandProperty ApplicationGroupReference) -split "/" | Select-Object -Last 1
        if ($PSCmdlet.ShouldProcess($ag, "Remove Application Group")) {
            Remove-AzWvdApplicationGroup -Name $ag -ResourceGroupName $ThisRG.ResourceGroupName
        }

        if($PSCmdlet.ShouldProcess($_.Name,"Remove Host Pool")){
            Remove-AzWvdHostPool -ResourceGroupName $RemovalScope.ResourceGroupName -Name $_.name
        }
    }
    
    Write-Verbose "Exporting logs to $LogPath"
    $laws = Get-AzOperationalInsightsWorkspace -Name "$prefix-sharedsvcs-log" -ResourceGroupName $thisrg.ResourceGroupName
    if($PSBoundParameters.ContainsKey('DisableLogExport')){
        Write-Verbose "-DisableLogExport switch called"
    } else {
        if($PSCmdlet.ShouldProcess($laws.Name, "Export logs to $LogPath")){
            Write-Verbose "Querying log data from $($laws.Name)"
            $logdata = Invoke-AzOperationalInsightsQuery -Workspace $laws -Query "search *" -Verbose
            $timestamp = Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }
            $tenantname = $(Get-AzTenant).Name
            $ExportFile = "$LogPath\$timestamp-$tenantname-log-export.csv"
            Write-Verbose "Writing log data to $ExportFile"
            $logdata.Results | Export-Csv -Path $ExportFile
        }
    }
   
    Write-Verbose "Now purging key vault"
    if ($PurgeKeyVault) {
        if(-not(Get-AzKeyVault -ResourceGroupName $RemovalScope.ResourceGroupName)) {
        Write-Host "No key vault found."
        } else {
        $KeyVaultToPurge = Get-AzKeyVault -ResourceGroupName $RemovalScope.ResourceGroupName
        Write-Verbose "Found '$($KeyVaultToPurge.VaultName)' Key Vault"
        Remove-AzKeyVault -VaultName $KeyVaultToPurge.VaultName -Location $RemovalScope.Location -Force
        Remove-AzKeyVault -InRemovedState -VaultName $KeyVaultToPurge.VaultName -Location $RemovalScope.Location -Force
        }
    }

    if($PSCmdlet.ShouldProcess($_.ResourceGroupName, "Remove ResourceGroup")){
        $_ | Remove-AzResourceGroup -Force -AsJob
    }
}

Write-Verbose "Processing tenant level items created by AVD Blueprint"

$RemoveAvdUsers = Get-AzADGroup -DisplayName "AVD Users" | Get-AzADGroupMember
Write-Verbose "Found $($RemoveAvdUsers.count) AVD users"
$RemoveAvdUsers | ForEach-Object {
    if ($PSCmdlet.ShouldProcess($_.DisplayName, "Remove AVD User")) {
        Remove-AzADUser -DisplayName $_.DisplayName -Force
    }
}

$RemoveDomAdminUser = Get-AzADUser -DisplayName "domainadmin"
Write-Verbose "Found $($RemoveDomAdminUser.count) DomainAdmin user"
$RemoveDomAdminUser | ForEach-Object {
    if ($PSCmdlet.ShouldProcess($_.DisplayName, "Remove DomainAdmin User")) {
        Remove-AzADUser -DisplayName $_.DisplayName -Force
    }
}

$RemoveAvdGroup = Get-AzADGroup -DisplayName "AVD Users"
if ($RemoveAvdGroup) {
    Write-Verbose "Found '$($RemoveAvdGroup.DisplayName)' group"
    if ($PSCmdlet.ShouldProcess($RemoveAvdGroup.DisplayName, "Remove AVD Group")) {
        $RemoveAvdGroup | Remove-AzADGroup -Force
    }
}

$RemoveAADDCAdminsGroup = Get-AzADGroup -DisplayName "AAD DC Administrators"
if ($RemoveAADDCAdminsGroup) {
    Write-Verbose "Found '$($RemoveAADDCAdminsGroup.DisplayName)' group"
    if ($PSCmdlet.ShouldProcess($RemoveAADDCAdminsGroup.DisplayName, "Remove AAD DC Administrators Group")) {
        $RemoveAADDCAdminsGroup | Remove-AzADGroup -Force
    }
}

if ($PSCmdlet.ShouldProcess("PowershellJobs", "DisplayActiveJobs")) {
    Get-Job | Group-Object State
    Write-Host "Use 'Get-Job | Group-Object State' to track status of Resource Group removal jobs"    
} else {
    Write-Verbose "Active removal jobs would be displayed here"
}
