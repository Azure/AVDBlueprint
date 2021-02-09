[CmdletBinding(SupportsShouldProcess=$true)]
Param(
    [Parameter(Mandatory=$true)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string] $StorageAccountName
)
#Install RSAT and other stuff
Install-WindowsFeature -name GPMC
Install-WindowsFeature -name RSAT-AD-Tools
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name Az -AllowClobber -Scope AllUsers -Force
Invoke-WebRequest -Uri 'https://agblueprintsa.blob.core.windows.net/blueprintscripts/InstallFSLogixClient.ps1' -OutFile C:\Windows\Temp\InstallFSLogixClient.ps1
Invoke-WebRequest -Uri 'https://agblueprintsa.blob.core.windows.net/blueprintscripts/FSLogixAppsSetup.exe' -OutFile C:\Windows\Temp\FSLogixAppsSetup.exe
Invoke-WebRequest -Uri 'https://agblueprintsa.blob.core.windows.net/blueprintscripts/PolicyDefinitions.zip ' -OutFile C:\Windows\Temp\PolicyDefinitions.zip
Expand-Archive -LiteralPath 'C:\Windows\Temp\PolicyDefinitions.zip' -DestinationPath C:\Windows\Temp\PolicyDefinitions

#Install Azure module
Install-Module -Name Az -Force

#Confirm AzContext
If (!(Get-AzContext)) {
    Write-Error "Please login to your Azure account"
}
else {
    $FileShareUserGroupId = (Get-AzADGroup -DisplayName "WVD Users").Id
    
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

    #Section added by RMS to create group policy object for WVD Session Hosts (and related work)
    #Create new WVD Organizational Unit

    $Domain = Get-ADDomain
    $PDC = $Domain.PDCEmulator
    $FQDomain = $Domain.DNSRoot
    $WVDPolicy = New-GPO -Name "WVD Session Host Policy"
    $WVDComputersOU = New-ADOrganizationalUnit -Name 'WVD Computers' -DisplayName 'WVD Computers' -Path $Domain.DistinguishedName -Server $PDC -PassThru
    New-GPLink -Target $WVDComputersOU.DistinguishedName -Name $WVDPolicy.DisplayName -LinkEnabled Yes

    #Create GPO Central Store
    Copy-Item 'C:\Windows\Temp\PolicyDefinitions' "\\$FQDomainName\SYSVOL\$FQDomain\Policies" -Recurse

    #Move WVD session host VMs to WVD
    #Get-ADComputer -Filter {Name -notlike "*mgmtvm*"} -SearchBase (Get-ADDomain).ComputersContainer -SearchScope subtree -Server $PDC | Foreach-Object {Move-ADObject -identity $_.DistinguishedName -TargetPath $WVDComputersOU.DistinguishedName -Server $PDC}

    #Cope WVD Session Host startup script that installs FSLogix
    #Create WVD GPO AD Object
    $WVDPolicy=Get-GPO -Name "WVD Session Host Policy"
    $PolicyID ="{" +  $WVDPolicy.ID + "}"
    Copy-Item 'C:\Windows\Temp\WVDSH_InstallFSLogix.ps1' "\\$FQDomain\SYSVOL\$FQDomain\Policies\$PolicyID\Machine\Scripts\Startup"

    #Create WVD FSLogix GPO
    #Switch to script Directory
    set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\Software\FSLogix\Profiles" -Type DWORD -ValueName "Enabled" -Value 1
    set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\Software\FSLogix\Profiles" -Type DWORD -ValueName "DeleteLocalProfileWhenVHDShouldApply" -Value 1
    set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\Software\FSLogix\Profiles" -Type STRING -ValueName "VHDLocations" -Value "\\$StorageAccountName\$($StorageShare.Name)"
}