$jConfig = Get-Content "C:\VSCode\CustomizedFiles\run.config.json" | ConvertFrom-Json
$tenantID = $jConfig.args.tenantID
$subID = $jConfig.args.subscriptionID
$bpPath = $jConfig.args.blueprintPath
$bpName = $jConfig.args.blueprintName

If (!(Get-AzContext)) {
    Write-Host "Please login to your Azure account"
    Connect-AzAccount -Tenant $tenantID -Subscription $subID
}

Import-AzBlueprintWithArtifact -Name $bpName -InputPath $bpPath -SubscriptionId $subID

$bpDef = Get-AzBlueprint -SubscriptionId $subID -Name $bpName
$version = (Get-Date -Format "yyyyMMddHHmmss").ToString()
Publish-AzBlueprint -Blueprint $bpDef -Version $version