[CmdletBinding(SupportsShouldProcess=$true)]
Param(
    [Parameter(Mandatory=$true)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string] $StorageAccountName
)
#Install RSAT-AD Tools, GP Tools, Az PS, and download components
Install-WindowsFeature -name GPMC
Install-WindowsFeature -name RSAT-AD-Tools
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name Az -AllowClobber -Scope AllUsers -Force


#Run most of the following as domainadmin user via invoke-command scriptblock
$Scriptblock = {
    Param(
    [Parameter(Mandatory=$true,Position=0)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory=$true,Position=1)]
    [string] $StorageAccountName
    )
    
    Start-Transcript -OutputDirectory C:\Windows\Temp

    #Login with Managed Identity
    Connect-AzAccount -Identity

    whoami | Out-File -append c:\windows\temp\innercontext.txt

    klist tickets | Out-File -append c:\windows\temp\innercontext.txt
    

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

    #Grant elevated rights to permit admin access
    
    $FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
    $ThisUPN = whoami /upn
    New-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $ShareScope -SignInName $ThisUPN
    Write-Verbose "Granted admin share rights"

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

############# Group Policy and FSLogix Session Host Section #################
    
Connect-AzAccount -Identity
        
$CTempPath = "C:\Temp"
New-Item -ItemType Directory -Path $CTempPath
$ScriptLogActionsTimes = 'C:\Temp\ScriptActionLogTimes.txt'
Get-Timezone | Out-File -FilePath $ScriptLogActionsTimes
Get-Date | Out-File -append $ScriptLogActionsTimes
"______________________________" | Out-File -append $ScriptLogActionsTimes

$DomainConfigItemsZip = "$CTempPath\DomainConfigItems.zip"
Invoke-WebRequest -Uri 'https://agblueprintsa.blob.core.windows.net/blueprintscripts/DomainConfigItems.zip' -OutFile $DomainConfigItemsZip

If (Test-Path $DomainConfigItemsZip){
Expand-Archive -LiteralPath $DomainConfigItemsZip -DestinationPath $CTempPath -ErrorAction SilentlyContinue
}

$Domain = Get-ADDomain
$PDC = $Domain.PDCEmulator
$FQDomain = $Domain.DNSRoot

Copy-Item "$CTempPath\PolicyDefinitions" "\\$FQDomain\SYSVOL\$FQDomain\Policies" -Recurse -Force

$WVDPolicy = New-GPO -Name "WVD Session Host Policy"
$PolicyID ="{" +  $WVDPolicy.ID + "}"
$WVDComputersOU = New-ADOrganizationalUnit -Name 'WVD Computers' -DisplayName 'WVD Computers' -Path $Domain.DistinguishedName -Server $PDC -PassThru
New-GPLink -Target $WVDComputersOU.DistinguishedName -Name $WVDPolicy.DisplayName -LinkEnabled Yes

$PolicyStartupFolder = "\\$FQDomain\SYSVOL\$FQDomain\Policies\$PolicyID\Machine\Scripts\Startup"
New-Item -ItemType Directory -Path $PolicyStartupFolder
Copy-Item "$CTempPath\InstallFSLogixClient.ps1" -Destination $PolicyStartupFolder -Force -ErrorAction SilentlyContinue

$CurrentVMName = hostname
$DeploymentPrefix = $CurrentVMName.Split('-')[0]
$CurrentResourceGroupName = ($DeploymentPrefix +, '-sharedsvcs-rg')
$DeploymentPrefixSS = ($DeploymentPrefix +,'sharedsvcs*')
$CurrentStorageAccountName = Get-AzStorageAccount -ResourceGroup $CurrentResourceGroupName | Where-Object {($_.StorageAccountName -Like "$DeploymentPrefix*" -and $_.StorageAccountName -notlike "$DeploymentPrefixSS")}
$StorageFQDN = "$($CurrentStorageAccountName.StorageAccountName).file.core.windows.net"
$StorageShareName = Get-AzRmStorageShare -StorageAccount $CurrentStorageAccountName
$StorageUNC = "\\$StorageFQDN\$($StorageShareName.Name)"

$Pattern = "\{[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\}"
Get-ChildItem -Path $CTempPath | Where-Object {$_.Name -match $Pattern}
$GPOBackupGuid = (Get-ChildItem -Path $CTempPath | Where-Object { $_.Name -match $Pattern }).Name -replace "{" -replace "}"
Import-GPO -BackupId $GPOBackupGuid -Path $CTempPath -TargetName $WVDPolicy.DisplayName

Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\Software\FSLogix\Profiles" -Type STRING -ValueName "VHDLocations" -Value $StorageUNC

#RDP Lockdowns
Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fDisableAudioCapture" -Value 1
Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fDisableCameraRedir" -Value 1
Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fDisableCcm" -Value 1
Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fDisableCdm" -Value 1
Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fDisableClip" -Value 1
Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fDisableLPT" -Value 1
Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fDisablePNPRedir" -Value 1
Set-GPRegistryValue -Name "WVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fEnableTimeZoneRedirection" -Value 1

$KeyVault = Get-AzKeyVault -VaultName "*-sharedsvcs-kv"
$DAUserUPN = (Get-AzADGroup -DisplayName "AAD DC Administrators" | Get-AzADGroupMember).UserPrincipalName
$DAUserName = $DAUserUPN.Split('@')[0]
$DAPass = (Get-AzKeyVaultSecret -VaultName $keyvault.VaultName -name $DAUserName).SecretValue
$DACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DAUserUPN, $DAPass
$WVDComputersOU = Get-ADOrganizationalUnit -Filter 'Name -like "WVD*"' -Server $PDC

$WVDComputersToMove = Get-ADComputer -Filter * -Server $PDC| Where-Object {($_.DNSHostName -like "$DeploymentPrefix*" -and $_.DNSHostName -notlike "*mgmtvm*")}
Foreach ($W in $WVDComputersToMove) {Move-ADObject -Credential $DACredential -Identity $W.DistinguishedName -TargetPath $WVDComputersOU.DistinguishedName -Server $PDC}

$VMsToManage = (Get-ADComputer -Filter * -Server $PDC -SearchBase $WVDComputersOU.DistinguishedName -SearchScope Subtree).name
Foreach ($V in $VMsToManage) {Invoke-Command -Computer $V -ScriptBlock {gpupdate /force}}
Foreach ($V in $VMsToManage) {Invoke-Command -Computer $V -ScriptBlock {shutdown /r /f /t 05}}

Get-Date | Out-File -Append $ScriptLogActionsTimes
"Apply GPO settings to Session Host VMs, and reboot completed" | Out-File -append $ScriptLogActionsTimes
############ END GROUP POLICY SECTION
    #>
}

#Get an Azure Managed Identity context
Connect-AzAccount -Identity

#Create a DAuser context, using password from Key Vault
$KeyVault = Get-AzKeyVault -VaultName "*-sharedsvcs-kv"
$DAUserUPN = (Get-AzADGroup -DisplayName "AAD DC Administrators" | Get-AzADGroupMember).UserPrincipalName
$DAUserName = $DAUserUPN.Split('@')[0]
$DAPass = (Get-AzKeyVaultSecret -VaultName $keyvault.VaultName -name $DAUserName).SecretValue
$DACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DAUserUPN, $DAPass
Register-PSSessionConfiguration -Name DASessionConf -RunAsCredential $DACredential -Force

whoami | Out-File c:\windows\temp\outercontext.txt
"KeyVault" | Out-File -append c:\windows\temp\outercontext.txt
$keyVault | Out-File -append c:\windows\temp\outercontext.txt
"dauserupn" | Out-File -append c:\windows\temp\outercontext.txt
$DAUserUPN | Out-File -append c:\windows\temp\outercontext.txt
"dausername" | Out-File -append c:\windows\temp\outercontext.txt
$DAUserName | Out-File -append c:\windows\temp\outercontext.txt
"dapass" | Out-File -append c:\windows\temp\outercontext.txt
$DAPass | Out-File -append c:\windows\temp\outercontext.txt
"dacred" | Out-File -append c:\windows\temp\outercontext.txt
$DACredential | Out-File -append c:\windows\temp\outercontext.txt
Get-PSSessionConfiguration | Out-File -append c:\windows\temp\outercontext.txt
systeminfo | Out-File -append c:\windows\temp\outercontext.txt
Get-AzContext | Out-File -append c:\windows\temp\outercontext.txt
klist tickets | Out-File -append c:\windows\temp\outercontext.txt

#Run the $scriptblock in the DAuser context
Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock $Scriptblock -ArgumentList $ResourceGroupName,$StorageAccountName

#Clean up DAuser context
Unregister-PSSessionConfiguration -Name DASessionConf -Force
