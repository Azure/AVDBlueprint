IF (-not(Test-path C:\Windows\Temp\FSLogixAppsSetup.exe)){
    Invoke-WebRequest -Uri https://agblueprintsa.blob.core.windows.net/blueprintscripts/FSLogixAppsSetup.exe -OutFile C:\Windows\Temp\FSLogixAppsSetup.exe
} 
ELSE {write-warning "File Already Exists!"}

If (-not(Get-Service frxsvc -ErrorAction SilentlyContinue))
{
    If (Test-path C:\Windows\Temp\FSLogixAppsSetup.exe) {
        Start-Process C:\Windows\Temp\FSLogixAppsSetup.exe -ArgumentList "/quiet /install"
    }
    
}
