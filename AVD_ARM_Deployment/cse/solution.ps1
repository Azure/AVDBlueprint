Param(

    [Parameter(Mandatory=$true,Position=0)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory=$true,Position=1)]
    [string] $StorageAccountName,

    [Parameter(Mandatory=$true,Position=2)]
    [string] $AzureEnvironment,

    [Parameter(Mandatory=$true,Position=3)]
    [string] $StorageFQDN,

    [Parameter(Mandatory=$true,Position=4)]
    [string] $SessionHostPrefix,

    [Parameter(Mandatory=$true,Position=5)]
    [string] $SessionHostCount,

    [Parameter(Mandatory=$true,Position=6)]
    [string] $storageAccountKey,

    [Parameter(Mandatory=$true,Position=7)]
    [string] $AdminPassword,

    [Parameter(Mandatory=$true,Position=8)]
    [string] $AdminUsername
)


$ErrorActionPreference = 'Continue'
$VerbosePreference = 'Continue'

Start-Transcript -OutputDirectory 'C:\Windows\Temp'

# Install Group Policy Management Console
Install-WindowsFeature -Name 'GPMC'

# Install RSAT-AD Tools
Install-WindowsFeature -Name 'RSAT-AD-Tools'

# Set storage account credential to mount file share
$Username = 'Azure\' + $StorageAccountName
$Password = ConvertTo-SecureString -String "$storageAccountKey" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)

# Mount Azure File Share
$StorageUNC = '\\' + $StorageFQDN + '\profiles'
New-PSDrive -Name Z -PSProvider FileSystem -Root $StorageUNC -Credential $credential

# Build ACL Rules
$DomainUsersAllowThisFolderOnly = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users","Modify","None","None","Allow")
$CreatorOwnerAllowSubFoldersAndFilesOnly = New-Object System.Security.AccessControl.FileSystemAccessRule("Creator Owner","Modify","ContainerInherit,ObjectInherit","InheritOnly","Allow")
$AuthenticatedUsersPrincipal = New-Object System.Security.Principal.Ntaccount ("Authenticated Users")
$UsersPrincipal = New-Object System.Security.Principal.Ntaccount ("Users")
$CreatorOwnerPrincipal = New-Object System.Security.Principal.Ntaccount ("Creator Owner")

# Remove Undesired ACLs
$acl = Get-Acl z:
$acl.PurgeAccessRules($CreatorOwnerPrincipal)
$acl | Set-Acl z:

$acl = Get-Acl z:
$acl.PurgeAccessRules($AuthenticatedUsersPrincipal)
$acl | Set-Acl z:

$acl = Get-Acl z:
$acl.PurgeAccessRules($UsersPrincipal)
$acl | Set-Acl z:

# Add FSLogix ACLs
$acl = Get-Acl z:
$acl.SetAccessRule($DomainUsersAllowThisFolderOnly)
$acl | Set-Acl z:

$acl = Get-Acl z:
$acl.AddAccessRule($CreatorOwnerAllowSubFoldersAndFilesOnly)
$acl | Set-Acl z:

# Create working directory
$TempPath = 'C:\Temp'
if (-not(Test-Path $TempPath)) {
    New-Item -ItemType Directory -Path $TempPath
}

# Unzip AVD GPO templates to Temp Folder
Expand-Archive -Path ".\AVD_PostInstall_GP_Settings.zip" -DestinationPath "$TempPath" -Force

# Set up a file share for the session hosts
$SoftwareShare = "$TempPath\Software"
if (-not(Test-Path $SoftwareShare)) {
    New-Item -ItemType Directory -Path $SoftwareShare
}
if (-not(Get-SmbShare -Name "Software" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "Software" -Path $SoftwareShare
}

# Move VDOT zip to file share
Move-Item -Path ".\VDOT.zip" -Destination $SoftwareShare -Force

# Unzip FSLogix GPO templates to FSLogix Folder
if (-not(Test-Path "$SoftwareShare\FSLogix"))
{
    New-Item -ItemType Directory -Path "$SoftwareShare\FSLogix"
}
Expand-Archive -Path "FSLogixGPT.zip" -DestinationPath "$SoftwareShare\FSLogix" -Force

# Create a startup script for the session hosts to run the Virtual Desktop Optimization Tool
$AVDSHSWShare = "$" + "SoftwareShare" + " = " + "'\\$ENV:ComputerName\Software'"
$AVDSHSWShare | Out-File -FilePath "$TempPath\PostInstallConfigureAVDSessionHosts.ps1"
$PostInstallAVDConfig = @'
    $TempPath = 'C:\Temp'
    $VDOTZIP = "$TempPath\VDOT.zip"

    #Test if VDOT has run before and if it has not, run it
    If(-not(Test-Path "$env:SystemRoot\System32\Winevt\Logs\Virtual Desktop Optimization.evtx")){
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
        New-Item -ItemType Directory -Path $TempPath -ErrorAction SilentlyContinue
        Copy-Item "$SoftwareShare\VDOT.zip" $TempPath
        Expand-Archive -Path $VDOTZIP -DestinationPath $TempPath
        Get-ChildItem -Path C:\Temp\Virtual* -Recurse -Force | Unblock-File
        $VDOTString = "$TempPath\Virtual-Desktop-Optimization-Tool-main\Win10_VirtualDesktop_Optimize.ps1 -AcceptEula -Verbose"
        Invoke-Expression $VDOTString
        Invoke-Command -ScriptBlock {Shutdown -r -f -t 00}
    }
'@
Add-Content -Path "$TempPath\PostInstallConfigureAVDSessionHosts.ps1" -Value $PostInstallAVDConfig

# Create a Domain Admin credential
$DomainName = (Get-ComputerInfo).CsDomain
$DAUserPrincipalName = $AdminUsername + '@' + $DomainName
$DAPassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
$DACredential = New-Object System.Management.Automation.PSCredential ($DAUserPrincipalName, $DAPassword)  

# Create AVD GPO, AVD OU, link the two, then copy session host configuration start script to SYSVOL location
$Domain = Get-ADDomain -Credential $DACredential -Current LocalComputer
$PDC = $Domain.PDCEmulator
$FQDomain = $Domain.DNSRoot
Register-PSSessionConfiguration -Name DASessionConf -RunAsCredential $DACredential -Force
$AVDPolicy = Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock {New-GPO -Name "AVD Session Host Policy"}
$PolicyID ="{" +  $AVDPolicy.ID + "}"
$AVDComputersOU = Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock {New-ADOrganizationalUnit -Name 'AVD Computers' -DisplayName 'AVD Computers' -Path $Using:Domain.DistinguishedName -Server $Using:PDC -PassThru}
Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock {New-GPLink -Target $Using:AVDComputersOU.DistinguishedName -Name $Using:AVDPolicy.DisplayName -LinkEnabled Yes}

# Move AVD session hosts to their new OU
$AVDComputersToMove = Get-ADComputer -Credential $DACredential -Filter * -Server $PDC | Where-Object {$_.DNSHostName -like "$SessionHostPrefix*" -and $_.DNSHostName -notlike "*mgmtvm*"}
foreach ($W in $AVDComputersToMove)
{
    Move-ADObject -Credential $DACredential -Identity $W.DistinguishedName -TargetPath $AVDComputersOU.DistinguishedName -Server $PDC
}

# Create a "GPO Central Store" by copying the "PolicyDefinitions" folder from one of the new AVD session hosts
$VMsToManage = (Get-ADComputer -Credential $DACredential -Filter * -Server $PDC -SearchBase $AVDComputersOU.DistinguishedName -SearchScope Subtree).name
$AVDSH1PolicyDefinitionsUNC = "\\" + $VMsToManage[0] + "\C$\Windows\PolicyDefinitions"
Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock {Copy-Item -Path $Using:AVDSH1PolicyDefinitionsUNC -Destination "\\$Using:FQDomain\SYSVOL\$Using:FQDomain\Policies" -Recurse -Force}

# Now that GPO Central Store exists, copy in the FSLogix Group Policy template files
$PolicyDefinitions = "\\$FQDomain\SYSVOL\$FQDomain\Policies\PolicyDefinitions"
if (Test-Path "$SoftwareShare\FSLogix")
{
    Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock {
        Copy-Item "$Using:SoftwareShare\FSLogix\fslogix.admx" $Using:PolicyDefinitions -Force
        Copy-Item "$Using:SoftwareShare\FSLogix\fslogix.adml" "$Using:PolicyDefinitions\en-US" -Force
    }
}

# Determine profile share name and set a variable
$StorageUNC = '\\' + $StorageFQDN + '\profiles'

# Import AVD GP startup settings from an export and apply that to the AVD GPO
$Pattern = "\{[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\}"
$GPOBackupGuid = (Get-ChildItem -Path $TempPath | Where-Object { $_.Name -match $Pattern }).Name -replace "{" -replace "}"
Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock {Import-GPO -BackupId $Using:GPOBackupGuid -Path $Using:TempPath -TargetName $Using:AVDPolicy.DisplayName}

# Copy the AVD SH Startup script to the Scripts Startup folder
$PolicyStartupFolder = "\\$FQDomain\SYSVOL\$FQDomain\Policies\$PolicyID\Machine\Scripts\Startup"
Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock {Copy-Item "$Using:TempPath\PostInstallConfigureAVDSessionHosts.ps1" -Destination $Using:PolicyStartupFolder -Force}


# Now apply the rest of the AVD group policy settings
Write-Host "`tNow editing FSLogix group policy settings."
Invoke-Command -ConfigurationName DASessionConf -ComputerName $env:COMPUTERNAME -ScriptBlock {
    Set-GPRegistryValue -Name "AVD Session Host Policy" -Key "HKLM\SOFTWARE\FSLogix\Profiles" -Type STRING -ValueName "VHDLocations" -Value $Using:StorageUNC
    Set-GPRegistryValue -Name "AVD Session Host Policy" -Key "HKLM\SOFTWARE\FSLogix\Profiles" -Type DWORD -ValueName "Enabled" -Value 1
    Set-GPRegistryValue -Name "AVD Session Host Policy" -Key "HKLM\SOFTWARE\FSLogix\Profiles" -Type DWORD -ValueName "DeleteLocalProfileWhenVHDShouldApply" -Value 1
    Set-GPRegistryValue -Name "AVD Session Host Policy" -Key "HKLM\SOFTWARE\FSLogix\Profiles" -Type DWORD -ValueName "FlipFlopProfileDirectoryName" -Value 1
    Set-GPRegistryValue -Name "AVD Session Host Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Type DWORD -ValueName "fEnableTimeZoneRedirection" -Value 1
}


# Force a GPUpdate and a restart to make those settings apply, on each session host
Write-Host "`tNow running GPUpdate on session host VMs to apply GP and restart them to run VDOT"
for ($i = 0; $i -lt $SessionHostCount; $i++) 
{  
    $VMComputerName = $SessionHostPrefix + $i
    Write-Host "Now updating AVD session host $VMComputerName"
    $Session = New-PSSession -ComputerName $VMComputerName -Credential $DACredential
    Invoke-Command -Session $Session -ScriptBlock {
        gpupdate /force
        shutdown /r /f /t 03
    }
    Remove-PSSession -Session $Session
}
Get-PSDrive 

Stop-Transcript