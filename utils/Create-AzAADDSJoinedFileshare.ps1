[CmdletBinding(SupportsShouldProcess=$true)]
Param(
    [Parameter(Mandatory=$true)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string] $StorageAccountName,

    [Parameter(Mandatory=$true)]
    [string] $FileShareAdminUPN,

    [Parameter(Mandatory=$true)]
    [string] $FileShareUserGroupId
)

#Confirm AzContext
If (!(Get-AzContext)) {
    Write-Error "Please login to your Azure account"
}
else {
    $Location = (Get-AzResourceGroup -ResourceGroupName $ResourceGroupName).Location

    #Create AADDS enabled Storage account and accompanying share
    $StorageAccount = New-AzStorageAccount `
                        -ResourceGroupName $ResourceGroupName `
                        -Name $StorageAccountName `
                        -Location $Location `
                        -SkuName Standard_LRS `
                        -Kind StorageV2 `
                        -EnableAzureActiveDirectoryDomainServicesForFile $true `
                        -EnableLargeFileShare
    Write-Verbose "Created Storage account $($StorageAccount.StorageAccountName)"


    $StorageShare = New-AzRmStorageShare `
                        -StorageAccount $StorageAccount `
                        -Name "profiles"
    Write-Verbose "Created File Share $($StorageShare.Name)"


    #Construct the scope of the share
    #"/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Storage/storageAccounts/<storage-account>/fileServices/default/fileshares/<share-name>"
    $ShareScope = "/subscriptions/$($(Get-AzContext).Subscription.Id)/resourceGroups/$($StorageAccount.ResourceGroupName)/providers/Microsoft.Storage/storageAccounts/$($StorageAccount.StorageAccountName)/fileServices/default/fileshares/$($StorageShare.Name)"

    #Grant elevated rights to permit Share configuration
    $FileShareElevatedContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
    New-AzRoleAssignment -RoleDefinitionName $FileShareElevatedContributorRole.Name -Scope $ShareScope -SignInName $FileShareAdminUPN
    Write-Verbose "Granted elevated share rights"

    #Grant standard rights to permit user access
    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
    New-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $ShareScope -ObjectId $FileShareUserGroupId
    Write-Verbose "Granted user share rights"

    #Get a storage key based credential together
    $StorageKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName | Select-Object -First 1).value
    $SecureKey = ConvertTo-SecureString -String $storageKey -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential -ArgumentList "Azure\$($storageAccount.StorageAccountName)", $SecureKey

    #Mount share to set NTFS ACLs
    $StorageFQDN = "$($StorageAccount.StorageAccountName).file.core.windows.net"
    $StorageUNC = "\\$StorageFQDN\$($StorageShare.Name)"
    New-PSDrive -Name Z -PSProvider FileSystem -Root $StorageUNC -Credential $credential


    #Build some ACL rules
    $DomainUsersAllowThisFolderOnly = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users","Modify","None","None","Allow")
    $CreatorOwnerAllowSubFoldersAndFilesOnly = New-Object System.Security.AccessControl.FileSystemAccessRule("Creator Owner","Modify","ContainerInherit,ObjectInherit","InheritOnly","Allow")
    $AuthenticatedUsersPrincipal = New-Object System.Security.Principal.Ntaccount ("Authenticated Users")
    $UsersPrincipal = New-Object System.Security.Principal.Ntaccount ("Users")
    $CreatorOwnerPrincipal = New-Object System.Security.Principal.Ntaccount ("Creator Owner")

    #Clean up some undesired ACLs
    $acl = Get-Acl z:
    $acl.PurgeAccessRules($CreatorOwnerPrincipal)
    $acl | Set-Acl z:

    $acl = Get-Acl z:
    $acl.PurgeAccessRules($AuthenticatedUsersPrincipal)
    $acl | Set-Acl z:

    $acl = Get-Acl z:
    $acl.PurgeAccessRules($UsersPrincipal)
    $acl | Set-Acl z:

    #Apply FSLogix ACLs
    $acl = Get-Acl z:
    $acl.SetAccessRule($DomainUsersAllowThisFolderOnly)
    $acl | Set-Acl z:

    $acl = Get-Acl z:
    $acl.AddAccessRule($CreatorOwnerAllowSubFoldersAndFilesOnly)
    $acl | Set-Acl z:

    Write-Verbose "NTFS ACLs set on $StorageUNC"
}