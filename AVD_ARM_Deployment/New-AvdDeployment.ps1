<#####################################################################################################################################
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
    THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
    INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant 
    You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form 
    of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in 
    which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code 
    is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
    including attorneys fees, that arise or result from the use or distribution of the Sample Code.
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
- TITLE:          AVD ARM Deployment script
- AUTHORED BY:    Jason Masten
- AUTHORED DATE:  10 October 2021
- CONTRIBUTORS:   Robert M. Smith, Dennis Payne, & Tim Muessig
- LAST UPDATED:   03 February 2022
- PURPOSE:        A single PowerShell script to perform everything necessary to deploy Azure Virtual Desktop (AVD)
                  into an Azure Subscription utilizing the ARM deployment method.

- IMPORTANT:      This script is currently intended to be deployed in an environment without user Active Directory
                  or Azure Active Directory Domain Services (AAD DS).  This script currently creates a new instance of AAD DS.
                  A future version will add the ability to install to an environment with existing AD or AAD DS.

- DEPENDENCIES    1. An Azure tenant
                  2. An Azure subscription
                  3. An Azure account in the Azure tenant with the following roles:
                     - 'Global Administrator' at the Azure AD scope
                     - 'Owner' at the Azure subscription scope
                  4. This script and accompanying .JSON and .PS1 files, which can be found in 'scripts' folder
                  5. The "CSE" sub-folder and all it's contents.


- PARAMETERS      This script only has one parameter a few required parameters to login to Azure and to set your Azure ADDS domain.

- USAGE           New-AvdDeployment.ps1 -AzureADDSDomainName 'azcontoso.com' -AzureEnvironment 'AzureCloud' -AzureSubscriptionID '00000000-0000-0000-0000-000000000000' -AzureTenantID '11111111-1111-1111-1111-1111111111111' -ResourcePrefix 'avd01'

- CUSTOMIZATION   
                    1. Download the repository from ? (as a .zip file)
                    2. Extract the downloaded .zip file to any location on your device.
                    3. The customization to your environment is accomplished by the values entered for the parameters.
                     Visual Studio Code is a good option because it's free, and the extension "Azure Resource Manager (ARM) Tools" offers basic syntax
                     checking of the file. In Windows, you can use the built-in PowerShell ISE.  There are lots of options.
                     JSON FORMAT NOTES:
                       a) String values are contained in quotation marks
                       b) Integer values are not contained in quotation marks
                       c) Boolean (true/false) values are not contained in quotation marks
                     
                     The VARIABLES can be used "as is", or can be changed to suit your environment
                     

######################################################################################################################################>

[CmdletBinding()]
param(

    [Parameter(Mandatory,
    HelpMessage="Enter the name of the domain used in this deployment")]
    [string]$AzureADDSDomainName,

    [Parameter(Mandatory,
    HelpMessage="Enter the name of the Azure cloud instance being deployed to")]
    [ValidateSet('AzureCloud','AzureUSGovernment', 'AzureChinaCloud', 'AzureGermanCloud')]
    [string]$AzureEnvironment,

    [Parameter(Mandatory,
    HelpMessage="Enter the Azure subscription ID for this deployment")]
    [string]$AzureSubscriptionID,

    [Parameter(Mandatory,
    HelpMessage="Enter the Azure tenant ID for this deployment")]
    [string]$AzureTenantID,
    
    [Parameter(Mandatory,
    HelpMessage="Text string to used to name various objects created by this deployment (must be 1-8 characters")]
    [ValidateLength(1,8)]
    [string]$ResourcePrefix,

    [Parameter()]
    [switch]$PromptForSessionHostOSsku,

    [Parameter()]
    [switch]$PromptForSessionHostVMsize,
    
    [Parameter()]
    [switch]$PromptForManagementVMOSSku,

    [Parameter()]
    [switch]$ExistingAVDDeployment,

    [Parameter()]
    [switch]$ForceRerunDeployment,

    [Parameter()]
    [ValidateSet('Pooled','Personal')]
    [string]$HostPoolType = 'Pooled',

    [Parameter()]
    [ValidateSet('DepthFirst','BreadthFirst','Persistent')]
    [string]$HostPoolLBType = 'BreadthFirst',

    [Parameter()]
    [ValidateRange(1,200)]
    [int]$avdHostPool_vmNumberOfInstances = 2,

    [Parameter()]
    [string]$UserAssignedIdentityName = 'UAI1',

    [Parameter()]
    [int]$avdHostPool_maxSessionLimit = 16,

    [Parameter()]
    [ValidateRange(0,365)]
    [int]$LogRetentionDays = 365,

    [Parameter()]
    [int]$NumTestUsersToCreate = 5
    
)
   
#region output parameter values to this point in the script, just for reference   
Write-Host "`tParameters to be used with this deployment are listed below`n" -ForegroundColor Cyan
If ($PromptForSessionHostOSSku){
   Write-Host "`tPrompt for session host SKU is '$PromptForSessionHostOSSku'" -ForegroundColor Cyan
} else {
Write-Host "`tNo prompt for session host SKU" -ForegroundColor Cyan
}
If ($PromptForSessionHostVMsize){
Write-Host "`tPrompt for session host VM size is '$PromptForSessionHostVMsize'" -ForegroundColor Cyan
} else {
Write-Host "`tNo prompt for session host VM size" -ForegroundColor Cyan
}
If ($PromptForManagementVMOSSku){
Write-Host "`tPrompt for management VM OS version is $PromptForSessionHostOSSku" -ForegroundColor Cyan
} else {
Write-Host "`tNo prompt for management VM OS version" -ForegroundColor Cyan
}
Write-Host "
`tDomain name is '$AzureADDSDomainName'
`tAzure cloud instance is '$AzureEnvironment'
`tUser-assigned managed identity name is '$UserAssignedIdentityName'
`tHost pool type is '$HostPoolType'
`tHost pool load-balancer type is '$HostPoolLBType'
`tHost pool max session limit is '$avdHostPool_maxSessionLimit'
`tNumber of session hosts to create is '$avdHostPool_vmNumberOfInstances'
`tNumber of test users to create is '$NumTestUsersToCreate'
`tResourcePrefix is '$ResourcePrefix'
   " -ForegroundColor Cyan
#endregion
Pause

#region Validate if the file 'solution.json' is available, to prevent a later failure
$PSScriptStartingLocation = Get-Location
If (-not (Test-Path $PSScriptStartingLocation\solution.json))
{
    write-warning "`tCan't find file 'solution.json' in the current path. Please check the path. This script will now end."
    Return
}
Else
{
    Write-Host "`tFile 'solution.json' found...deployment will continue." -ForegroundColor Cyan
}
Write-Host "`tCurrent location = $PSScriptStartingLocation" -ForegroundColor Cyan
#endregion

#region PowerShell local logging
Write-Host "`n`tNow starting PowerShell transcript to record activity associated with this deployment." -ForegroundColor Cyan
If (-not(Test-Path -Path "$PSScriptStartingLocation\Logs")) {
New-Item -ItemType Directory -Path "$PSScriptStartingLocation\Logs"
}
Start-Transcript -IncludeInvocationHeader -OutputDirectory "$PSScriptStartingLocation\Logs"
#endregion

#region Variables
$AdminCredential = Get-Credential -Message 'Input Administrator credential prefix name' -UserName 'domainadmin'
$UserPassword = Get-Credential -Message 'Input password only, for test user accounts' -UserName 'IGNORE'
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'
$ResourceGroupName = $ResourcePrefix + '-sharedsvcs-rg'
#endregion

#region Remove existing Azure & Azure AD sessions
Disconnect-AzAccount -ErrorAction SilentlyContinue
try{Disconnect-AzureAD -ErrorAction Stop}catch{}
#endregion

try 
{
    #region Connect to Azure
    Write-Host "`tThe next action will prompt you to login to your Azure portal using a Global admin account`n" -ForegroundColor Cyan
    Read-Host -Prompt "Press any key to continue or CTRL + C to exit script"
    Connect-AzAccount -Environment $AzureEnvironment -Tenant $AzureTenantID -Subscription $AzureSubscriptionID
    #endregion

    #region Connect to Azure AD
    Write-Host "`tThe next action will prompt you to login to connect to Azure Active Directory.`n`tIf the prompt does not appear in the foreground, try minimizing your current app." -ForegroundColor Cyan
    Read-Host -Prompt "Press any key to continue"
    Connect-AzureAD -AzureEnvironmentName $AzureEnvironment -TenantId $AzureTenantID
    #endregion

    #region (Mandatory) Choose Azure deployment region by presenting selection box (if user specifies a selection prompt)
    Write-Host "`n`tEnumerating list of regions in your Azure cloud that support AVD..." -ForegroundColor Cyan
    $AzureLocations = (Get-AzResourceProvider -ListAvailable | Where-Object {($_.ProviderNamespace -EQ "Microsoft.DesktopVirtualization" -and $_.RegistrationState -EQ "Registered")}).Locations.ToLower() -replace '\s',''
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Select Azure region'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Please select an Azure region:'
    $form.Controls.Add($label)
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 80

    foreach ($A in $AzureLocations)
    {
        Write-Output $A | ForEach-Object {[void] $listBox.Items.Add($_)}
    }

    $form.Controls.Add($listBox)
    $form.Topmost = $true
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::CANCEL)
    {
        Write-Host "`n`tThe 'Cancel' button was pressed. The script will now exit." -ForegroundColor Red
        Return
    }

    if ($null -eq $listBox.SelectedItem)
    {
        Write-Host "`n`tAn Azure region was not selected.`n`tPlease re-run the script and select an Azure region.`n`tThis script will now end." -ForegroundColor Red
        Return
    }

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $ChosenAzureLocation = $listBox.SelectedItem
        Write-Host "`tYour chosen Azure region is '$ChosenAzureLocation'" -ForegroundColor Cyan
    }
    #endregion

    #region (Optional) Choose session host Azure VM size by presenting selection box (if user requests a selection prompt)
    Write-Host "`n`tNow setting session host Azure VM size." -ForegroundColor Cyan
    
    if ($PromptForSessionHostVMsize){
    Write-Host "`n`tEnumerating list of VM sizes in your Azure cloud and region..." -ForegroundColor Cyan
    $AzureSHVMsize = Get-AzVMSize -Location $ChosenAzureLocation | Where-Object ({$_.NumberOfCores -ge 4 -and $_.NumberOfCores -le 32 -and $_.Name -notlike "*Promo"}) | Sort-Object -Property 'Name' | Select-Object -Expand 'Name'
    #size parameters from: https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/virtual-machine-recs?context=/azure/virtual-desktop/context/context
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Select session host VM size'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Select a VM size:'
    $form.Controls.Add($label)
    $form.AutoScaleMode = "DPI"
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 80

    foreach ($A in $AzureSHVMsize)
    {
        Write-Output $A | ForEach-Object {[void] $listBox.Items.Add($_)}
    }

    $form.Controls.Add($listBox)
    $form.Topmost = $true
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::CANCEL)
    {
        Write-Host "`n`tThe 'Cancel' button was pressed. The script will now exit." -ForegroundColor Red
        Return
    }

    if ($null -eq $listBox.SelectedItem)
    {
        Write-Host "`n`tAn Azure VM size was not selected.`n`tPlease re-run the script and select an Azure VM size.`n`tThis script will now end." -ForegroundColor Red
        Return
    }

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
      {
        $ChosenSHVMsize = $listBox.SelectedItem
        Write-Host "`tYour chosen AVD session host size is '$ChosenSHVMsize'"
      }
    }
    #If no prompt for session host VM size, a common default size is set on next line
        if (-not($ChosenSHVMsize)){
        $ChosenSHVMsize = 'Standard_D4s_v5'
        }

        Write-Host "`tThe AVD session host VM size will be '$ChosenSHVMsize'" -ForegroundColor Cyan

    #endregion

    #region Choose management VM OS SKU by presenting selection box (if user requests a selection prompt)
    Write-Host "`n`tNow setting the VM OS Sku of the management VM" -ForegroundColor Cyan
    if ($PromptForManagementVMOSSku){
    Write-Host "`tGathering list of available Server Windows Skus..." -ForegroundColor Cyan
    $ServerSkus = Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer'  | Where-Object {$_.Skus -like "20??-?atacenter*" -and $_.Skus -notlike "*core*" -and $_.Skus -notlike "*smalldisk*" -and $_.Skus -notlike "*containers*" -and $_.Skus -notlike "*2012*" -and $_.Skus -notlike "*zhcn*"} | Select-object -Expandproperty Skus

    # Present a pop-up form to select management VM OS Sku to build from
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'MGMT VM OS Sku'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Please select MGMT VM OS Sku:'
    $form.Controls.Add($label)

    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 80

    ForEach ($S in $ServerSkus){
    Write-Output $S | ForEach-Object {[void] $listBox.Items.Add($_)}
    }

    $form.Controls.Add($listBox)

    $form.Topmost = $true

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::CANCEL)
     {
        Write-Host "`n`tThe 'Cancel' button was pressed. The script will now exit." -ForegroundColor Red
        Return
     }
    if ($null -eq $listBox.SelectedItem)
     {
        Write-Host "`n`tA Windows Server OS Sku was not selected.`n`tPlease re-run this script and select a Windows OS Sku in the pop-up pick-list,`n`tor you can run the script without specifying the parameter to prompt for MGMT VM OS Sku." -ForegroundColor Red
        Return
     }
    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
     {
        $managementVMOSSku = $listBox.SelectedItem
        Write-Host "`tYour selected management VM OS Sku is '$managementVMOSSku'" -ForegroundColor Cyan
     }
       
    }
        #If no prompt for management VM OS SKU, select the latest version as default
        if (-not($managementVMOSSku)){
         $managementVMOSSku = '2022-datacenter'
         Write-Host "`tManagement VM OS version is set to default value of '$managementVMOSSku'" -ForegroundColor Cyan
         }

    #endregion

    #region Choose AVD session host OS SKU by presenting selection box (if user requests a selection prompt)
    if ($PromptForSessionHostOSSku){
    Write-Host "`n`tGathering list of available AVD Windows Skus..." -ForegroundColor Cyan
    $AVDSHvmsku = Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsDesktop' -offer 'windows-10' | Where-Object ({$_.Skus -like "*evd*" -and $_.Skus -notlike "*rs5*" -or $_.Skus -like "*avd*"})| Select-Object -ExpandProperty Skus
    $AVDSHvmsku += Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsDesktop' -offer 'office-365' | Where-Object ({$_.Skus -like "*evd*" -and $_.Skus -notlike "*rs5*" -or $_.Skus -like "*avd*"})| Select-Object -ExpandProperty Skus
    $AVDSHvmsku += Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsDesktop' -offer 'windows-11' | Where-Object ({$_.Skus -like "*evd*" -and $_.Skus -notlike "*rs5*" -or $_.Skus -like "*avd*"})| Select-Object -ExpandProperty Skus
    
    # Present a pop-up form to select session host OS Sku to build from
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Select session host OS Sku'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Select session host OS Sku:'
    $form.Controls.Add($label)

    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(260,20)
    $listBox.Height = 80

    ForEach ($S in $AVDSHvmsku){
    Write-Output $S | ForEach-Object {[void] $listBox.Items.Add($_)}
    }

    $form.Controls.Add($listBox)

    $form.Topmost = $true

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::CANCEL)
     {
        Write-Host "`tThe 'Cancel' button was pressed. The script will now exit." -ForegroundColor Red
        Return
     }
    if ($null -eq $listBox.SelectedItem)
     {
        Write-Host "`tAn AVD OS Sku was not selected.`n`tPlease re-run this script and select an AVD OS Sku in the pop-up pick-list.`n`tOr you can run this script without specifying the prompt for MGMTVM OS Sku" -ForegroundColor Red
        Return
     }
    if ($result -eq [System.Windows.Forms.DialogResult]::OK){
    $avdHostPool_vmGalleryImageSKU = $listBox.SelectedItem
    Write-Host "`tYour selected session host OS SKU is '$avdHostPool_vmGalleryImageSKU'" -ForegroundColor Cyan
    
    # Set the correct 'Offer' value based on the image selected
    
    if (Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsDesktop' -Offer 'windows-10' | Where-Object -Property Skus -EQ $avdHostPool_vmGalleryImageSKU -ErrorAction SilentlyContinue) {
    $avdHostPool_vmGalleryImageOffer = 'windows-10'
    } elseif (Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsDesktop' -Offer 'windows-11' | Where-Object -Property Skus -EQ $avdHostPool_vmGalleryImageSKU -ErrorAction SilentlyContinue) {
    $avdHostPool_vmGalleryImageOffer = 'windows-11'
    } elseif (Get-AzVMImageSku -Location $ChosenAzureLocation -PublisherName 'MicrosoftWindowsDesktop' -Offer 'office-365' | Where-Object -Property Skus -EQ $avdHostPool_vmGalleryImageSKU -ErrorAction SilentlyContinue) {
    $avdHostPool_vmGalleryImageOffer = 'office-365'
    }
    }
    }
        #If no prompt for AVD OS SKU, select a late version for default
        if (-not($PromptForSessionHostOSSku)){
         $avdHostPool_vmGalleryImageSKU = 'win10-21h2-avd-m365'
         $avdHostPool_vmGalleryImageOffer = 'office-365'
         }

    Write-Host "`n`tThe AVD session host OS Sku will be '$avdHostPool_vmGalleryImageSKU'`n`tThe AVD session host VM gallery image offer will be '$avdHostPool_vmGalleryImageOffer'" -ForegroundColor Cyan

    
    #endregion

    #region Create Resource Group for AVD deployment resources
    Write-Host "`n`tCreating AVD resource group for objects created by this AVD deployment" -ForegroundColor Cyan
    if (-not(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue))
    {
        Write-Host "`tResource Group $ResourceGroupName does not currently exist.`n`tNow creating Resource Group '$ResourceGroupName'" -ForegroundColor Cyan
        New-AzResourceGroup -ResourceGroupName $ResourceGroupName -Location $ChosenAzureLocation
    } 
    else
    {
        Write-Host "`tResource Group '$ResourceGroupName' already exists." -ForegroundColor Cyan
    }
    #endregion

    #region Create User Assigned Managed Identity and wait until it is ready within Azure for further operations
    Write-Host "`n`tCreating and/or checking status of the user-assigned managed identity account, which will be the context of the AVD assignment" -ForegroundColor Cyan
    $UAMIOwnerSubRoleCheck = $null
    $UAMIOwnerSubRoleCheck = Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not($UAMIOwnerSubRoleCheck))
    {
        Write-Host "`tManaged identity '$UserAssignedIdentityName' does not currently exist.`n`tNow creating '$UserAssignedIdentityName' in resource group '$ResourceGroupName'" -ForegroundColor Cyan
        $UAMIOwnerSubRoleCheck = New-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $ResourceGroupName -Location $ChosenAzureLocation
        $UAMIOwnerSubRoleCheck
    }
    else
    {
        Write-Host "`tUser Assigned Identity '$UAMIOwnerSubRoleCheck.name' already exists`n" -ForegroundColor Cyan
        $UAMIOwnerSubRoleCheck
    }

        #Testing that the previously created identity is ready within Azure, so that subsequent operations to the UAMI don't fail
        $UAMIOwnerSubRoleCheck = Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        if (-not($UAMIOwnerSubRoleCheck)){
            Do {
            Write-Host "`tWaiting 3 seconds for user assigned managed identity '$UserAssignedIdentityName' to become available for next operation..." -ForegroundColor Cyan
            Start-Sleep -Seconds 3
            } until (Get-AzUserAssignedIdentity -Name $UserAssignedIdentityName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
        }
     $UAMIOwnerSubRoleCheck   

    #endregion

    #region Assign 'Owner' role at resource group scope to the managed identity
    Write-Host "`n`tNow checking if user assigned identity '$UAMIOwnerSubRoleCheck.name' has the 'Owner' role at the resource group scope" -ForegroundColor Cyan
    if (-not(Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -ObjectID ($UAMIOwnerSubRoleCheck.PrincipalId) -RoleDefinitionName 'Owner'))
      {
        Write-Host "`tUser assigned identity '$UAMIOwnerSubRoleCheck.name' does not currently have the 'Owner' role at the resource group scope" -ForegroundColor Cyan
        Write-Host "`tNow assigning 'Owner' role to '$UAMIOwnerSubRoleCheck.name'" -ForegroundColor Cyan
        New-AzRoleAssignment -ObjectId ($UAMIOwnerSubRoleCheck).PrincipalId -RoleDefinitionName 'Owner' -ResourceGroupName $ResourceGroupName -ObjectType 'ServicePrincipal'
      }
    else
      {
        Write-Host "`tUser assigned identity '$UAMIOwnerSubRoleCheck.name' already has 'Owner' role assigned at the resource group scope`n" -ForegroundColor Cyan
        Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName -ObjectID ($UAMIOwnerSubRoleCheck.PrincipalId) -RoleDefinitionName 'Owner'
      }
    #endregion

    #region Assign 'Global Administrator' role to the managed identity, to allow creation of AD objects
    $UserAssignedObjectID = $UAMIOwnerSubRoleCheck.PrincipalId
    $AADRoleInfo = Get-AzureADMSRoleDefinition -Filter "displayName eq 'Global Administrator'"
    $AADRoleInfoId = $AADRoleInfo.Id
    $AADGlobalAdminRoleDisplayName = $AADRoleInfo.displayName
    Write-Host "`n`tAssigning Azure AD role 'Global Administrator' to managed identity '$UAMIOwnerSubRoleCheck.name'." -ForegroundColor Cyan

        # assign the role
    if (-not(Get-AzureADMSRoleAssignment -Filter "principalID eq '$UserAssignedObjectID' and roleDefinitionId eq '$AADRoleInfoId'"))
      {
        Write-Host "`tUser assigned identity"$UAMIOwnerSubRoleCheck.name"does not have the"$AADRoleInfo.displayName"role currently assigned." -ForegroundColor Cyan
        Write-Host "`tNow assigning role to managed identity '$UAMIOwnerSubRoleCheck.name'." -ForegroundColor Cyan
        New-AzureADMSRoleAssignment -RoleDefinitionId $AADRoleInfo.Id -PrincipalId $UAMIOwnerSubRoleCheck.PrincipalId -DirectoryScopeId '/'
      }
    else
      {
        Write-Host "`tUser assigned identity '$UAMIOwnerSubRoleCheck.name' already has the '$AADGlobalAdminRoleDisplayName' role assigned." -ForegroundColor Cyan
        Get-AzureADMSRoleAssignment -Filter "principalID eq '$UserAssignedObjectID' and roleDefinitionId eq '$AADRoleInfoId'"
      }
    #endregion

    #region Register the 'Microsoft.AAD' provider to the subscription, if not already registered
    Write-Host "`n`tNow checking the 'Microsoft.AAD' provider, and registering if needed" -ForegroundColor Cyan
    if (-not(Get-AzResourceProvider -ListAvailable | Where-Object {($_.ProviderNamespace -EQ "Microsoft.AAD" -and $_.RegistrationState -EQ "Registered")}))
    {
        Write-Host "`tThe 'Microsoft.AAD' provider is not currently registered. Now registering..." -ForegroundColor Cyan
        Register-AzResourceProvider -ProviderNamespace 'Microsoft.AAD'
        Get-AzResourceProvider -ListAvailable | Where-Object {($_.ProviderNamespace -EQ "Microsoft.AAD" -and $_.RegistrationState -EQ "Registered")}
    }
    else
    {
        Write-Host "`tThe 'Microsoft.AAD' provider is already registered" -ForegroundColor Cyan
        Get-AzResourceProvider -ListAvailable | Where-Object {($_.ProviderNamespace -EQ "Microsoft.AAD" -and $_.RegistrationState -EQ "Registered")}
    }
    #endregion

    #region Register the 'Azure AD Domain Services' enterprise application to the subscription if not already registered
    Write-Host "`n`tNow checking registration for 'Azure AD Domain Services' enterprise application" -ForegroundColor Cyan
    if (-not (Get-AzureADServicePrincipal -SearchString "Azure AD Domain Services" |  Where-Object AppId -EQ '6ba9a5d4-8456-4118-b521-9c5ca10cdf84'))
    {
        Write-Host "`tThe 'Azure AD Domain Services' enterprise application is not currently registered. Now registering" -ForegroundColor Cyan
        New-AzureADServicePrincipal -AppId "6ba9a5d4-8456-4118-b521-9c5ca10cdf84" -ErrorAction SilentlyContinue
    }
    else
    {
        Write-Host "`tThe 'Azure AD Domain Services' enterprise application is already registered" -ForegroundColor Cyan
        Get-AzureADServicePrincipal -SearchString "Azure AD Domain Services" |  Where-Object AppId -EQ '6ba9a5d4-8456-4118-b521-9c5ca10cdf84'
    }
    #endregion

    #region Register the 'Domain Controller Services' service principal to the subscription if not already registered
    Write-Host "`n`tNow checking registration for Domain Controller Services service principal, and registering if needed" -ForegroundColor Cyan
    if (-not (Get-AzureADServicePrincipal -SearchString "Domain Controller Services" | Where-Object AppID -like "2565bd9d-da50-47d4-8b85-4c97f669dc36"))
    {
        Write-Host "`tThe 'Domain Controller Services' service principal is not currently registered. Now registering" -ForegroundColor Cyan
        New-AzureADServicePrincipal -AppId "2565bd9d-da50-47d4-8b85-4c97f669dc36"
    }
    else
    {
        Write-Host "`tThe 'Domain Controller Services' service principal is already registered" -ForegroundColor Cyan
        Get-AzureADServicePrincipal | Where-Object AppID -like "2565bd9d-da50-47d4-8b85-4c97f669dc36"
    }
    #endregion

    #region Parameters
    $Params = @{
        adminUsername                       =   $AdminCredential.UserName
        avdHostPool_type                    =   $HostPoolType
        avdHostPool_loadBalancerType        =   $HostPoolLBType
        avdHostPool_maxSessionLimit         =   $avdHostPool_maxSessionLimit
        avdHostPool_userCount               =   $NumTestUsersToCreate
        avdHostPool_vmSize                  =   $ChosenSHVMsize
        avdHostPool_vmGalleryImageOffer     =   $avdHostPool_vmGalleryImageOffer
        avdHostPool_vmGalleryImageSKU       =   $avdHostPool_vmGalleryImageSKU
        avdHostPool_vmNumberOfInstances     =   $avdHostPool_vmNumberOfInstances
        createAvailabilitySet               =   $true
        domainName                          =   $AzureADDSDomainName
        logsRetention                       =   $LogRetentionDays  
        managedIdentity                     =   $UserAssignedIdentityName
        resourcePrefix                      =   $ResourcePrefix
        managementVMOSSku                   =   $managementVMOSSku
    }
    $Params.Add("adminPassword", $AdminCredential.Password) # Secure Strings must use Add Method for proper deserialization
    $Params.Add("avdHostPool_userPassword", $UserPassword.Password) # Secure Strings must use Add Method for proper deserialization
    #endregion

    Pause

    # Deploy ARM template
    $Params
    $Deployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile .\solution.json -TemplateParameterObject $Params

    #region Set Variables for Storage Account & Custom Script Extension
    Set-Location 'cse'
    $AzureEnvironment = (Get-AzContext).Environment.Name
    $Files = @('AVD_PostInstall_GP_Settings.zip','FSLogixGPT.zip','solution.ps1','VDOT.zip')
    $SessionHostCount = $Deployment.Outputs['sessionHostCount'].Value
    $SessionHostPrefix = $Deployment.Outputs['sessionHostPrefix'].Value
    $StorageAccountName = $Deployment.Outputs['storageAccountName'].Value
    $StorageAccountSuffix = $Deployment.Outputs['storageAccountSuffix'].Value
    $storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName | Where-Object {$_.KeyName -eq "key1"}).Value
    $StorageContainerName = 'cse'
    $StorageFQDN = $StorageAccountName + '.file.' + $StorageAccountSuffix
    $TimeStamp = Get-Date -Format 'yyyyMMddhhmmss'
    #endregion

    # Copy script & ZIP files to Blob Storage
    $Cxt = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context
    New-AzStorageContainer -Name $StorageContainerName -Permission Blob -Context $Cxt
    
    $URIs = @()
    foreach($File in $Files)
    {
        Set-AzStorageBlobContent -File $File -Container $StorageContainerName -Blob $File -Context $Cxt -Force
        $URIs += 'https://' + $StorageAccountName + '.blob.' + $StorageAccountSuffix + '/' + $StorageContainerName + '/' + $File
    }
    
    #region Write parameters out to transcript for reference
    Write-Host
    "
    `n`tWriting out parameters for later reference in case troubleshooting is needed
    ============================================================================`n
    $ResourcePrefix
    $ResourceGroupName
    $StorageAccountName
    $AzureEnvironment
    $ChosenAzureLocation
    $StorageFQDN
    $SessionHostPrefix
    $SessionHostCount
    $storageAccountKey
    $URIs
    $TimeStamp
    $($ResourcePrefix.ToLower() + '-mgmtvm')
    $($AdminCredential.UserName)
    "
    Write-Host
    "
    `n`tNow running Custom Script Extension on management VM for script 'solution.ps1'
    ==============================================================================
    "
    #endregion

    # Deploy Custom Script Extension to Management VM
    # Had to place double-quotes around password field in case password value contains reserved characters that could cause the script to fail
    # also, accounting for the case where a management VM is redeployed
    $settings = @{"fileUris" = $URIs; "timestamp" = $TimeStamp};
    $protectedSettings = @{"storageAccountName" = $StorageAccountName; "storageAccountKey" = "$StorageAccountKey"; "commandToExecute" = "powershell.exe -ExecutionPolicy Unrestricted -File solution.ps1 $ResourceGroupName $StorageAccountName $AzureEnvironment $StorageFQDN $SessionHostPrefix $SessionHostCount `"$storageAccountKey`" `"$($AdminCredential.GetNetworkCredential().Password)`" $($AdminCredential.UserName)"};
    $RandomTimeStamp = Get-Date -Format 'yyyyMMddhhmmssffff'
    if(-not(Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $($ResourcePrefix.ToLower() + '-mgmtvm') -Name 'CustomScriptExtension' -ErrorAction SilentlyContinue))
    {
    Set-AzVMExtension -ResourceGroupName $ResourceGroupName -Location $ChosenAzureLocation -vmName $($ResourcePrefix.ToLower() + '-mgmtvm') -Name "CustomScriptExtension" -Publisher "Microsoft.Compute" -ExtensionType "CustomScriptExtension" -TypeHandlerVersion "1.10" -Settings $settings -ProtectedSettings $protectedSettings
    }
    else
    {
    Set-AzVMExtension -ForceRerun $RandomTimeStamp -ResourceGroupName $ResourceGroupName -Location $ChosenAzureLocation -vmName $($ResourcePrefix.ToLower() + '-mgmtvm') -Name "CustomScriptExtension" -Publisher "Microsoft.Compute" -ExtensionType "CustomScriptExtension" -TypeHandlerVersion "1.10" -Settings $settings -ProtectedSettings $protectedSettings
    }

}
catch
{
    $_ | Select-Object *
    throw
}
Stop-Transcript
Set-location $PSScriptStartingLocation