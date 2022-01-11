[CmdletBinding()]
param(
    [Parameter()]
    [string]$AVDBPParamFile = ".\AVDBPParameters.json"
)

If (-not(Test-Path -Path '.\AVDBPParameters.json')) {
    Write-Host "    Could not find required parameter file 'AVDBPParameters.json'.
    Please check the path and try again" -ForegroundColor Cyan
    Return
}

If ($AVDBPParamFile -ne '.\AVDBPParameters.json') {
    Write-Host "The current value of parameter AVDBPParamFile is '$AVDBPParamFile'" -ForegroundColor Red
    Write-Host "The parameter 'AVDBPParamFile' is not set correctly" -ForegroundColor Red
    Write-Host "Please check the path and try again" -ForegroundColor Red
    Return
}

$BPScriptParams = Get-Content $AVDBPParamFile | ConvertFrom-Json
$BPScriptParams.PSObject.Properties | ForEach-Object {
     New-Variable -Name $_.Name -Value $_.Value -Force -ErrorAction SilentlyContinue
    }

$BPScriptParams

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

<#####################################################################################################################################
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
    THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
    INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant 
    You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form 
    of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in 
    which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code 
    is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
    including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
    Microsoft provides programming examples for illustration only, without warranty either expressed or
    implied, including, but not limited to, the implied warranties of merchantability and/or fitness 
    for a particular purpose. 
 
    This sample assumes that you are familiar with the programming language being demonstrated and the 
    tools used to create and debug procedures. Microsoft support professionals can help explain the 
    functionality of a particular procedure, but they will not modify these examples to provide added 
    functionality or construct procedures to meet your specific needs. if you have limited programming 
    experience, you may want to contact a Microsoft Certified Partner or the Microsoft fee-based consulting 
    line at (800) 936-5200. 
    For more information about Microsoft Certified Partners, please visit the following Microsoft Web site:
    https://partner.microsoft.com/global/30000104 
######################################################################################################################################>

<#####################################################################################################################################
- TITLE:          AVD Blueprint Configuration and Deployment script
- AUTHORED BY:    Robert M. Smith
- AUTHORED DATE:  01 September 2021
- CONTRIBUTORS:   Tim Muessig, Jason Masten, Dennis Payne, Chris Rutledge
- LAST UPDATED:   30 September 2021
- PURPOSE:        A single PowerShell script to perform everything necessary to deploy Azure Virtual Desktop (AVD)
                  into an Azure Subscription

- IMPORTANT:      This script is currently intended to be deployed in an environment without user Active Directory
                  or Azure Active Directory Domain Services (AAD DS).  This script currently creates a new instance of AAD DS.
                  A future version will add the ability to install to an environment with existing AD or AAD DS.

- DEPENDENCIES    1. An Azure tenant
                  2. An Azure subscription
                  3. An Azure account in the Azure tenant with the following roles:
                     - 'Global Administrator' at the Azure AD scope
                     - 'Owner' at the Azure subscription scope
                  4. A copy of the Blueprint files (Blueprint.json and all .JSON files in the \Artifacts folder)
                  5. This script and accompanying .JSON file, which can be found in 'Examples and Samples' folder
                  6. An Azure AD DS domain name (ex. corp.contoso.com)
                     NOTE: There are some conditions with replication if the AAD DS name is not the same as the AAD tenant name.


- PARAMETERS      This script only has one parameter '-File'.  This is set to look for a file called "AVDBPParameters.json"
                  in the current folder

- USAGE           'AssignAVDBlueprint.ps1 -file .\AVDBPParameters.json

- CUSTOMIZATION   
                    1. Download the repository from https://github.com/Azure/AVDBlueprint (as a .zip file)
                    2. Extract the downloaded .zip file to any location on your device.
                       a) This script is currently coded for 'C:\AVDBlueprint' but that location is your choice.
                       b) If you extract to a different path, edit the 'AVDBPParameters.json' parameter 'BlueprintPath' to the new path
                    2. The customization to your environment is accomplished with any text editor to the file "AVDBPParameters.json".
                     Visual Studio Code is a good option because it's free, and the extension "Azure Resource Manager (ARM) Tools" offers basic syntax
                     checking of the file. In Windows, you can use the built-in PowerShell ISE.  There are lots of options.
                     JSON FORMAT NOTES:
                       a) String values are contained in quotation marks
                       b) Integer values are not contained in quotation marks
                       c) Boolean (true/false) values are not contained in quotation marks

                         The included sample file "AVDBPParameters.json" only needs a few edits to get started:

                         I) "AADDSDomainName": "",
                         II)
                         
                     
                     The remaining sample values can be used "as is", or can be changed to suit your environment

                     NOTE: 1 value, "avdHostPool_vmImageType", should not be changed at this time.  The current value is 'Gallery',
                     meaning the VM will be deployed from an image in the Azure Marketplace. In the near future we will be adding
                     the capability to deploy using your custom image.
                     

- TROUBLESHOOTING
    - PROBLEM:      
      
      SOLUTION:   Try checking if there are updates queued up in 'Settings' -> 'Update & Security' -> 'Windows Update'.
                    If updates are needed, apply those, restart, then try running the script again.

######################################################################################################################################>


#region Checking for the required parameters, and if not set, exit script
 Write-Host "Checking PowerShell installed modules..." -ForegroundColor Cyan
if (-not($AADDSDomainName)) {
    Write-Host "`n    Azure Active Directory Domain Services name is not found
    AAD DS name must be specified in the parameter file 'AVDBPParameters.json'
    Your AAD DS prefix name must be 15 characters or less in the format 'domain.contoso.com'
    This script will now exit." -ForegroundColor Red
    Return
}

if (-not($AzureTenantID)) {
    Write-Host "`n    Azure Tenant ID is missing.
    The destination Azure Tenant ID must be present in the  file'AVDBPParameters.json'.
    This script will now exit." -ForegroundColor Red
    Return
}

if (-not($AzureSubscriptionID)) {
    Write-Host "`n    Azure Subscription ID is missing.
    The destination Azure Subscription ID must be present in the  file'AVDBPParameters.json'.
    This script will now exit." -ForegroundColor Red
    Return
}

if (-not($BlueprintResourcePrefix)) {
    Write-Host "`n    'BlueprintResourcePrefix' parameter value is missing in the parameter file 'AVDBPParameters.json'
    Please enter a 4-8 character value to be used for the blueprint deployment prefix.
    This prefix is used in naming some objects during the blueprint deployment, including computer names.
    Prefixes longer than 8 or 9 characters start to limit number of session hosts VMs that can get created because of name length.
    This script will now exit." -ForegroundColor Red
    Return
}

#endregion

#region Make sure required Az modules are installed
# Including the "import-module" line in case the modules were installed by xcopy method, but not yet imported
# Also including a test for the PSGallery/

# This script requires Az modules:
    #  - Az.Blueprint
    #  - Az.ManagedServiceIdentity
    #  - Az.Resources
    #  - AzureAD

    Write-Host "Checking PowerShell installed modules..." -ForegroundColor Cyan

    $AzModuleGalleryMessage = @"
    You may be prompted to install from the PowerShell Gallery
    If the Az PowerShell modules were not previously installed you may be prompted to install `'Nuget`'
    If your policies allow those items to be installed, click `'Yes to All`' when prompted.
"@
            
    if (-not(Get-PSRepository -Name 'PSGallery')) {
    Write-Host "    PowerShell Gallery 'PSGallery' not available.  Now resetting local repository to default,`n
    to allow access to the PSGallery (PowerShell Gallery),`n
    so subsequent Az modules needed for this script can be installed." -ForegroundColor Cyan
    Register-PSRepository -Default
    }
    
    $RequiredModules = @('Az.ManagedServiceIdentity', 'Az.Resources', 'Az.Blueprint', 'AzureAD')
    $InstalledModules = Get-Module -ListAvailable | Select-Object -ExpandProperty Name

    Write-Host "$AzModuleGalleryMessage `n" -ForegroundColor Cyan
    $RequiredModules | ForEach-Object {
        Write-Host "Checking for $_ : " -NoNewline
        If ($InstalledModules -notcontains $_)
        {
            Write-Host "Missing! Installing..." -ForegroundColor Red
            Install-Module $_ -Scope CurrentUser
        }
        Else
        {
            Write-Host "Installed" -ForegroundColor Green
        }
        Import-Module $_
    }

#endregion
#region Menu function
Function Get-MenuSelection
{
    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [String]
        $LableText = 'Please select an Azure Location:',
        [Parameter()]
        [Array]
        $MenuItems,
        [Parameter()]
        [String]
        $FormText = 'Please select an Azure Location:'

    )
    Begin { }
    Process
    {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $form = New-Object System.Windows.Forms.Form
        $form.Text = $FormText
        $form.Size = New-Object System.Drawing.Size(300, 200)
        $form.StartPosition = 'CenterScreen'
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(75, 120)
        $okButton.Size = New-Object System.Drawing.Size(75, 23)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(150, 120)
        $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 20)
        $label.Size = New-Object System.Drawing.Size(280, 20)
        $label.Text = $LableText
        $form.Controls.Add($label)
        $listBox = New-Object System.Windows.Forms.ListBox
        $listBox.Location = New-Object System.Drawing.Point(10, 40)
        $listBox.Size = New-Object System.Drawing.Size(260, 20)
        $listBox.Height = 80
        ForEach ($A in $MenuItems)
        {
            Write-Output $A | ForEach-Object { [void] $listBox.Items.Add($_) }
        }
        $form.Controls.Add($listBox)
        $form.Topmost = $true
        $result = $form.ShowDialog()
    }
    End
    {
        if ($result -eq [System.Windows.Forms.DialogResult]::CANCEL)
        {
            
            Return 'Cancel'
        }
        Else
        {
            Return $listBox.SelectedItem
        }
    }
}

#endregion

#region Pop-up Azure Cloud instance for user selection
Write-Host "`nEnumerating list of Azure Clouds..." -ForegroundColor Cyan
$AzureEnvironmentName = Get-MenuSelection -MenuItems (Get-AzEnvironment | Select-Object -ExpandProperty Name) -LableText "Select an Azure Region" -FormText "Select Azure Cloud"
If ($AzureEnvironmentName -eq 'Cancel')
{
    Write-Host "The 'Cancel' button was pressed.`nPlease re-run this script and select an Azure cloud in the pop-up pick-list" -ForegroundColor Red
    Return
}
Else
{
    
    If ($null -eq $AzureEnvironmentName)
    {
        Write-host "An Azure cloud was not selected`nPlease re-run this script and select an Azure cloud in teh pop-up pick-list" -for Red
        return
    }
    Write-Host "Your chosen Azure Cloud is: " -NoNewline
    Write-Host $AzureEnvironmentName -ForegroundColor Green
}


#endregion

#region Checking for and setting up environment
Write-Host "The next action will prompt you to login to your Azure portal using a Global Admin account`n" -ForegroundColor Cyan
Start-Sleep -Seconds 3

Connect-AzAccount -Tenant $AzureTenantID -Subscription $AzureSubscriptionID -Environment $AzureEnvironmentName -Force

Write-Host "Enumerating Azure context..." -ForegroundColor Cyan
$AzureEnvironment = Get-AzContext
$AzureStorageEnvironment = ($AzureEnvironment).Environment.StorageEndpointSuffix
$AzureStorageFileEnv = 'file.' + $AzureStorageEnvironment

# Present a pop-up form to select region to deploy to
Write-Host "`n    Enumerating list of locations in your environment, that offer the AVD service..." -ForegroundColor Cyan
$AzureLocations = Get-MenuSelection -MenuItems ((Get-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization).Locations.ToLower() -replace '\s', '' | Select-Object -Unique ) -LableText "Please select an Azure Location:" -FormText 'Select Azure Location'
If ($AzureLocations -eq 'Cancel')
{
    Write-Host "The 'Cancel' button was pressed. The script will now exit." -ForegroundColor Red
    Return
}
Else 
{
    If ($null -eq $AzureLocations)
    {
        Write-Host "An Azure Location was not selected.`nPlease re-run this script and select an Azure location in the pop-up pick-list" -ForegroundColor Red
        Return
    }

    $ChosenAzureLocation = $AzureLocations
    Write-Host "Your chosen Azure location is '$ChosenAzureLocation'"
}

#region If management VM Sku prompt set true, query and display available Skus
if ($PromptForManagementVMOSSku)
{
    Write-Host "`n    Gathering list of available Server Windows Skus..." -ForegroundColor Cyan
    $ServerSkus = Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' | Where-Object { $_.Skus -like "20??-?atacenter*" -and $_.Skus -notlike "*core*" -and $_.Skus -notlike "*smalldisk*" -and $_.Skus -notlike "*containers*" } | Select-object -Expandproperty Skus
    $managementVMOSSku = Get-MenuSelection -MenuItems $ServerSkus -LableText 'Please select MGMT VM OS Sku:' -FormText 'MGMT VM OS Sku'
    if ($managementVMOSSku -eq 'Cancel')
    {
        $managementVMOSSku = '2022-datacenter'
        Write-Host "Operation canceled, defaulting to '$managementVMOSSku'"
    }
    If ($null -eq $managementVMOSSku)
    {
        $managementVMOSSku = '2022-datacenter'
    }
    Write-Host "Your chosen management VM OS Sku is '$managementVMOSSku'"
} 
else 
{
    $managementVMOSSku = '2022-datacenter'
    Write-Host "Your chosen management VM OS Sku is '$managementVMOSSku'"
}
#endregion

#region If AVD session host prompt set true, query and display available Skus
if ($PromptForSessionHostOSSku){
    Write-Host "`n    Gathering list of available Windows session host SKUs..." -ForegroundColor Cyan
    $AVDSHvmsku = @('windows-10', 'office-365', 'windows-11') | ForEach-Object { Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsDesktop' -offer $_ | Where-Object ( { $_.Skus -like "*evd*" -and $_.Skus -notlike "*rs5*" -or $_.Skus -like "*avd*" }) | Select-Object -ExpandProperty Skus }
    $avdHostPool_vmGalleryImageSKU = Get-MenuSelection -MenuItems $AVDSHvmsku -LableText 'Please select AVD OS Sku:' -FormText 'AVD OS Sku'

    # Present a pop-up form to select management VM OS Sku to build from

    if ($avdHostPool_vmGalleryImageSKU -eq 'CANCEL')
    {
        Write-Host "The 'Cancel' button was pressed. The script will now exit." -ForegroundColor Red
        Return
    }
    else
    {
        # Set the correct 'ImageOffer' based on the image selected
        If ($null -eq $avdHostPool_vmGalleryImageSKU)
        {
            $avdHostPool_vmGalleryImageSKU = '21h1-evd-o365pp'
        }
        switch -Wildcard ($avdHostPool_vmGalleryImageSKU)
        {
            *win11-* { $avdHostPool_vmGalleryImageOffer = 'windows-11' ; Break }
            *-o365pp* { $avdHostPool_vmGalleryImageOffer = 'office-365'; Break }
            Default { $avdHostPool_vmGalleryImageOffer = 'windows-10' }
        }

        Write-Host "Your chosen Windows session host OS Sku is '$avdHostPool_vmGalleryImageSKU' - Image Offer is '$avdHostPool_vmGalleryImageOffer'"
    }
}
else 
{
    $avdHostPool_vmGalleryImageSKU = '21h1-evd-o365pp'
}
#endregion

Write-Host "`nThe following parameters will be used, based on the login information provided:

Azure Tenant ID:                  $AzureTenantID
Azure Subscription ID:            $AzureSubscriptionID
Azure Cloud Instance:             $AzureEnvironmentName
Azure Location:                   $ChosenAzureLocation
`n" -ForegroundColor Cyan

$UserPrincipalName = (Get-AzContext).Account.Id
#Internal Account
$UserAssignedObjectId = (Get-AzADUser -UserPrincipalName $UserPrincipalName).Id
#Guest Account
if(!$UserAssignedObjectId)
{
    $UserAssignedObjectId = (Get-AzADUser -Mail $UserPrincipalName).Id
}

#Read-Host -Prompt "If the listed parameters are correct, press any key to continue or 'CTRL+C' to end script"

Write-Host "The next action will prompt you to login to your Azure Active Directory`n" -ForegroundColor Cyan
Write-Host "If the prompt does not appear in the foreground, try minimizing your current app`n" -ForegroundColor Cyan
#Read-Host -Prompt "Press any key to continue or 'CTRL + C' to end script"
Start-Sleep -Seconds 3
Connect-AzureAD -AzureEnvironmentName $AzureEnvironmentName -TenantId $AzureTenantID

#endregion

#region Create a "global" resource group for AVD resources...
# which should not be the same resource group that the AVD Blueprint is later assigned to

    Write-Host "`nCreating AVD resource group for persistent objects such as user-assigned identity" -ForegroundColor Cyan
    $ResourceGroupCheck = Get-AzResourceGroup -Name $BlueprintGlobalResourceGroupName -ErrorAction SilentlyContinue
    If (-not($ResourceGroupCheck)){
        Write-Host "`Resource Group $BlueprintGlobalResourceGroupName does not currently exist. Now creating Resource Group" -ForegroundColor Cyan
        New-AzResourceGroup -ResourceGroupName $BlueprintGlobalResourceGroupName -Location $ChosenAzureLocation
        } else {
        Write-Host "`Resource Group '$BlueprintGlobalResourceGroupName' already exists." -ForegroundColor Cyan
        $ResourceGroupCheck
    }
#endregion

#region Check to see if there is a user assigned managed identity with name 'UAI1', and if not, create one
$ManagedIdentityCheck = Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $BlueprintGlobalResourceGroupName -ErrorAction SilentlyContinue
Write-Host "`nCreating user-assigned managed identity account, that will be the context of the AVD assignment" -ForegroundColor Cyan
    If (-not($ManagedIdentityCheck)){
$UserAssignedIdentity = Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $BlueprintGlobalResourceGroupName -ErrorAction SilentlyContinue
Write-Host "`nCreating user-assigned managed identity account, which will be the context of the AVD assignment" -ForegroundColor Cyan
}
    If (-not($UserAssignedIdentity)){
        Write-Host "        Managed identity '$UserAssignedIdentityName' does not currently exist.
        Now creating managed identity '$UserAssignedIdentityName' in resource group '$BlueprintGlobalResourceGroupName'" -ForegroundColor Cyan
        $UserAssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $BlueprintGlobalResourceGroupName -Name $UserAssignedIdentityName -Location $ChosenAzureLocation
        $UserAssignedIdentity
        } else {
        Write-Host "`nUser Assigned Identity '$UserAssignedIdentityName' already exists`n" -ForegroundColor Cyan
        $UserAssignedIdentity = $ManagedIdentityCheck
        $ManagedIdentityCheck
        Write-Host "`nUser Assigned Identity '$UserAssignedIdentityName' already exists" -ForegroundColor Cyan
        $UserAssignedIdentity
    }
    $UserAssignedIdentityId = $UserAssignedIdentity.Id
    $ScriptExecutionUserObjectID = $UserAssignedIdentity.PrincipalId
#endregion    

#region Grant the 'Owner' subscription level role to the managed identity
Write-Host "Now checking if user assigned identity '$UserAssignedIdentityName' has 'Owner' subscription level role assignment" -ForegroundColor Cyan
$UAMIOwnerSubRoleCheck = Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $BlueprintGlobalResourceGroupName -ErrorAction SilentlyContinue
if (-not($UAMIOwnerSubRoleCheck))
{
    Do
    {
        Write-Host "Waiting 3 seconds for user assigned managed identity '$UserAssignedIdentityName' to become available for next operation..." -ForegroundColor Cyan
        Start-Sleep -Seconds 3
    } until (Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $BlueprintGlobalResourceGroupName -ErrorAction SilentlyContinue)
    
    New-AzRoleAssignment -ObjectId $UserAssignedIdentity.PrincipalId -RoleDefinitionName 'Owner' -Scope "/subscriptions/$AzureSubscriptionID"

}
else
{
    Write-Host "User assigned identity '$UserAssignedIdentityName' already has 'Owner' role assigned at the subscription level" -ForegroundColor Cyan
    $UAMIOwnerSubRoleCheck
}
#endregion

#region Register the Azure Blueprint provider to the subscription, if not already registered
Write-Host "Now checking the 'Microsoft.Blueprint' provider, and registering if needed" -ForegroundColor Cyan
$BlueprintProviderRegistration = Get-AzResourceProvider -ListAvailable | Where-Object {($_.ProviderNamespace -EQ "Microsoft.Blueprint" -and $_.RegistrationState -EQ "Registered")}
if (-not($BlueprintProviderRegistration))
{
    Write-Host "The 'Microsoft.Blueprint' provider is not currently registered. Now registering..." -ForegroundColor Cyan
    Register-AzResourceProvider -ProviderNamespace 'Microsoft.Blueprint'
    # adding a pause here until the 'Blueprint' provider is in the actual 'Registered' state
    Do
    {
        Write-Host "Pausing to ensure 'Blueprint' provider is in the 'registered' state. waiting 3 seconds..." -ForegroundColor Cyan
        Start-Sleep -Seconds 3
    } until (Get-AzResourceProvider -ListAvailable | Where-Object { ($_.ProviderNamespace -EQ "Microsoft.Blueprint" -and $_.RegistrationState -EQ "Registered") } -ErrorAction SilentlyContinue)
    Get-AzResourceProvider -ListAvailable | Where-Object { ($_.ProviderNamespace -EQ "Microsoft.Blueprint" -and $_.RegistrationState -EQ "Registered") }
}
else
{
    Write-Host "The 'Microsoft.Blueprint' provider is already registered" -ForegroundColor Cyan
    $BlueprintProviderRegistration
}
#endregion

#region Register the Azure Blueprint provider to the subscription, if not already registered
Write-Host "Now checking the 'Microsoft.Blueprint' provider, and registering if needed" -ForegroundColor Cyan
$BlueprintProviderList = Get-AzResourceProvider -ListAvailable | Where-Object {($_.ProviderNamespace -EQ "Microsoft.Blueprint" -and $_.RegistrationState -EQ "Registered")}
if (-not($BlueprintProviderList))
{
    Write-Host "The 'Microsoft.Blueprint' provider is not currently registered. Now registering..." -ForegroundColor Cyan
    Register-AzResourceProvider -ProviderNamespace 'Microsoft.Blueprint'
    Get-AzResourceProvider -ListAvailable | Where-Object { ($_.ProviderNamespace -EQ "Microsoft.Blueprint" -and $_.RegistrationState -EQ "Registered") }
}
else
{
    Write-Host "The 'Microsoft.Blueprint' provider is already registered" -ForegroundColor Cyan
    $BlueprintProviderList
}
#endregion

#region Grant the 'Blueprint Operator' subscription level role to the managed identity
Write-Host "Now checking if user assigned identity '$UserAssignedIdentityName' has 'Blueprint Operator' subscription level role assignment" -ForegroundColor Cyan
$UAMIBlueprintOperatorRoleCheck = Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $BlueprintGlobalResourceGroupName
if (-not($UAMIBlueprintOperatorRoleCheck))
{
    Do
    {
        Write-Host "User assigned identity '$UserAssignedIdentityName' is not currently available, waiting 3 seconds..." -ForegroundColor Cyan
        Start-Sleep -Seconds 3
    } until (Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $BlueprintGlobalResourceGroupName -ErrorAction SilentlyContinue)
    Write-Host "User Assigned Managed Identity '$UserAssignedIdentityName' is now available..." -ForegroundColor Cyan
}   
$UAMIBlueprintOperatorRoleCheck2 = Get-AzRoleAssignment -ResourceGroupName $BlueprintGlobalResourceGroupName -ObjectID ($UserAssignedIdentity).PrincipalId -RoleDefinitionName 'Blueprint Operator'
if (-not($UAMIBlueprintOperatorRoleCheck2))
{
    Write-Host "Now checking if 'Blueprint Operator' role is currently assigned to '$UserAssignedIdentityName'" -ForegroundColor Cyan
    Get-AzRoleAssignment -ResourceGroupName $BlueprintGlobalResourceGroupName -ObjectID ($UserAssignedIdentity).PrincipalId -RoleDefinitionName 'Blueprint Operator'
    New-AzRoleAssignment -ObjectId ($UserAssignedIdentity).PrincipalId -RoleDefinitionName 'Blueprint Operator' -Scope "/subscriptions/$AzureSubscriptionID"
}
else
{    
    Write-Host "User assigned identity '$UserAssignedIdentityName' already has 'Blueprint Operator' role assigned at the subscription level" -ForegroundColor Cyan
    Get-AzRoleAssignment -ResourceGroupName $BlueprintGlobalResourceGroupName -ObjectID ($UserAssignedIdentity).PrincipalId -RoleDefinitionName 'Blueprint Operator' -ErrorAction SilentlyContinue
}
#endregion

#region Assign Azure AD role 'Global Administrator' to the managed identity, to allow creation of AD objects during assignment, if not already assigned
$AADGlobalAdminRoleInfo = Get-AzureADMSRoleDefinition -Filter "displayName eq 'Global Administrator'"
$AADGlobalAdminRoleInfoId = $AADGlobalAdminRoleInfo.Id
$AADGlobalAdminRoleDisplayName = $AADGlobalAdminRoleInfo.displayName

Write-Host "`Assigning Azure AD role 'Global Administrator' to the managed identity" -ForegroundColor Cyan

$UAMIOwnerSubRoleCheck = Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $BlueprintGlobalResourceGroupName -ErrorAction SilentlyContinue
if (-not($UAMIOwnerSubRoleCheck)){
    Do {
    Write-Host "Waiting 3 seconds for user assigned managed identity '$UserAssignedIdentityName' to become available for next operation..." -ForegroundColor Cyan
    Start-Sleep -Seconds 3
    } until (Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $BlueprintGlobalResourceGroupName -ErrorAction SilentlyContinue)
}

if (-not(Get-AzureADMSRoleAssignment -Filter "principalID eq '$ScriptExecutionUserObjectID' and roleDefinitionId eq '$AADGlobalAdminRoleInfoId'")){
    Write-Host "User assigned identity"$UserAssignedIdentity.name"does not have the"$AADGlobalAdminRoleInfo.displayName"role currently assigned." -ForegroundColor Cyan
    Write-Host "Now assigning role to managed identity." -ForegroundColor Cyan
    New-AzureADMSRoleAssignment -RoleDefinitionId $AADGlobalAdminRoleInfoId -PrincipalId $ScriptExecutionUserObjectID -DirectoryScopeId '/' -ErrorAction SilentlyContinue
} else {
    Write-Host "User assigned identity '$UserAssignedIdentityName' already has the '$AADGlobalAdminRoleDisplayName' role assigned." -ForegroundColor Cyan
    Get-AzureADMSRoleAssignment -Filter "principalID eq '$ScriptExecutionUserObjectID' and roleDefinitionId eq '$AADGlobalAdminRoleInfoId'"
}
#endregion

#region Register the 'Microsoft.AAD' provider to the subscription, if not already registered
Write-Host "Now checking the 'Microsoft.AAD' provider, and registering if needed" -ForegroundColor Cyan
$MicrosoftAADProviderCheck = Get-AzResourceProvider -ListAvailable | Where-Object {($_.ProviderNamespace -EQ "Microsoft.AAD" -and $_.RegistrationState -EQ "Registered")}
if (-not($MicrosoftAADProviderCheck)) {
    Write-Host "The 'Microsoft.AAD' provider is not currently registered. Now registering..." -ForegroundColor Cyan
    Register-AzResourceProvider -ProviderNamespace 'Microsoft.AAD'
    Get-AzResourceProvider -ListAvailable | Where-Object {($_.ProviderNamespace -EQ "Microsoft.AAD" -and $_.RegistrationState -EQ "Registered")}
} else {
    Write-Host "The 'Microsoft.AAD' provider is already registered" -ForegroundColor Cyan
    $MicrosoftAADProviderCheck
}
#endregion

#region Register the 'Azure AD Domain Services' enterprise application to the subscription if not already registered
Write-Host "`Now checking registration for 'Azure AD Domain Services' enterprise application" -ForegroundColor Cyan
$AzureADDSappregistration = Get-AzureADServicePrincipal -SearchString "Azure AD Domain Services" | Where-Object AppId -EQ '6ba9a5d4-8456-4118-b521-9c5ca10cdf84'
if (-not ($AzureADDSappregistration)) {
    Write-Host "The 'Azure AD Domain Services' enterprise application is not currently registered. Now registering" -ForegroundColor Cyan
    New-AzureADServicePrincipal -AppId "6ba9a5d4-8456-4118-b521-9c5ca10cdf84" -ErrorAction SilentlyContinue
} else {
    Write-Host "The 'Azure AD Domain Services' enterprise application is already registered" -ForegroundColor Cyan
    $AzureADDSappregistration
}
#endregion

#region Register the 'Domain Controller Services' service principal to the subscription if not already registered
Write-Host "Now checking registration for Domain Controller Services service principal, and registering if needed" -ForegroundColor Cyan
$DCServicePrincipalCheck = Get-AzureADServicePrincipal -SearchString "Domain Controller Services" | Where-Object AppID -like "2565bd9d-da50-47d4-8b85-4c97f669dc36"
if (-not ($DCServicePrincipalCheck)) {
    Write-Host "The 'Domain Controller Services' service principal is not currently registered. Now registering" -ForegroundColor Cyan
    New-AzureADServicePrincipal -AppId "2565bd9d-da50-47d4-8b85-4c97f669dc36"
} else {
    Write-Host "The 'Domain Controller Services' service principal is already registered" -ForegroundColor Cyan
    $DCServicePrincipalCheck
}
#endregion

#region Import Blueprint section
Write-Host "Now importing AVD Blueprint to subscription`n" -ForegroundColor Cyan
Import-AzBlueprintWithArtifact -Name $BlueprintName -InputPath $BlueprintPath -SubscriptionId $AzureSubscriptionID
#endregion

#region Publish Blueprint section
$BlueprintDefinition = Get-AzBlueprint -SubscriptionId $AzureSubscriptionID -Name $BlueprintName
$BlueprintVersion = (Get-Date -Format "yyyyMMddHHmmss").ToString()
Write-Host "Now publishing AVD blueprint version '$BlueprintVersion'`n" -ForegroundColor Cyan
Publish-AzBlueprint -Blueprint $BlueprintDefinition -Version $BlueprintVersion
#endregion

#region Create the hash table for Parameters
$bpParameters = @{
    adds_domainName                     =   $AADDSDomainName
    script_executionUserResourceID      =   $UserAssignedIdentityId
    scriptExecutionUserObjectID         =   $ScriptExecutionUserObjectID
    keyvault_ownerUserObjectID          =   $UserAssignedObjectId
    AzureEnvironmentName                =   $AzureEnvironmentName
    AzureStorageFQDN                    =   $AzureStorageFileEnv
    scriptURI                           =   $ScriptURI
    resourcePrefix                      =   $BlueprintResourcePrefix
    avdHostPool_CreateAvailabilitySet   =   $avdHostPool_CreateAvailabilitySet
    vnetEnableDdosProtection            =   $vnetEnableDdosProtection
    managementVMOSSku                   =   $managementVMOSSku
    avdHostPool_vmSize                  =   $avdHostPool_vmSize
    avdHostPool_vmGalleryImageOffer     =   $avdHostPool_vmGalleryImageOffer
    avdHostPool_vmGalleryImageSKU       =   $avdHostPool_vmGalleryImageSKU
    avdHostPool_vmNumberOfInstances     =   $avdHostPool_vmNumberOfInstances
    avdHostPool_maxSessionLimit         =   $avdHostPool_maxSessionLimit
    avdHostPool_loadBalancerType        =   $avdHostPool_loadBalancerType
    avdHostPool_HostPoolType            =   $avdHostPool_HostPoolType
    avdUsers_userCount                  =   $avdUsers_userCount
    logsRetentionInDays                 =   $logsRetentionInDays
 }
#endregion

#region finish setting up assignment parameters, and assign blueprint
$bpRGParameters = @{ResourceGroup=@{location=$ChosenAzureLocation}}

$version =(Get-Date -Format "yyyyMMddHHmmss").ToString()
$BlueprintAssignmentName = $BlueprintName + '_' + $version

# Create the new blueprint assignment
$BlueprintParams = @{
    Name                        = $BlueprintAssignmentName
    Blueprint                   = $BlueprintDefinition
    SubscriptionId              = $AzureSubscriptionID
    Location                    = $ChosenAzureLocation
    UserAssignedIdentity        = $UserAssignedIdentityId
    Parameter                   = $bpParameters
    ResourceGroupParameter      = $bpRGParameters
}
Write-Host "Now assigning Blueprint '$BlueprintAssignmentName'`n" -ForegroundColor Cyan
$BlueprintAssignment = New-AzBlueprintAssignment @BlueprintParams

$BlueprintAssignmentStatus = Get-AzBlueprintAssignment -ErrorAction SilentlyContinue
if ($BlueprintAssignmentStatus){
$BlueprintAssignmentStatus
Write-Host "`nThe Blueprint named '$($BlueprintAssignment.Name)' successfully assigned. To check progress...
go to your Azure tenant, go to the Blueprints main blade, go to the Blueprint Assignments blade.
Or copy and paste the following into a web browser to check progress of the Blueprint assignment:`n
https://portal.azure.com/#blade/Microsoft_Azure_Policy/BlueprintsMenuBlade/BlueprintAssignments" -ForegroundColor Cyan
} else {
Write-Host "`nThere was a problem with the Blueprint assignment.
Please check the error output for possible causes.
If you believe the problem is with this code,
please visit the Github repository:`n
    https://github.com/Azure/AVDBlueprint
`n and open an issue for collaboration" -ForegroundColor Yellow
}

#endregion
