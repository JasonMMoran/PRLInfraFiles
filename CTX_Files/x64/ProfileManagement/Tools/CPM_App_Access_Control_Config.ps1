<# 
.SYNOPSIS
    Citrix Profile Management App Access Control Config Tool

.DESCRIPTION 
    A long description of how the script works and how to use it. It should be ran as administrator.
 
.NOTES 
    This PowerShell script was developed to help admins configure rules for UPM App Access Control feature.

.COMPONENT 
    Required Module AD, GPMC

.LINK 
    It is released with UPM
 
.Parameter ParameterName 
    NA 
#>


function Import-CTXModules {
    $Global:importModulesCnt++
    #already imported
    $moduleGPMAvailable = Get-Module *grouppolicy*
    $moduleADAvailable = Get-Module *activedirectory*
    if (($moduleGPMAvailable -ne $null) -and ($moduleADAvailable -ne $null)) {
        return
    }
    #not imported but installed
    try {
        if ($Global:importModulesCnt -eq 1) {
            write-host "`r`nPlease wait while PowerShell is importing the necessary Windows modules. " -ForegroundColor Yellow
        }
        
        Import-Module grouppolicy -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        return
    }
    catch {
        
    }
    #uninstalled
    #check OS version
    $curOS = ''
    try {
        if ($Global:importModulesCnt -eq 1) {
            write-host "`r`nPlease wait while PowerShell is installing the necessary Windows additional features. " -ForegroundColor Yellow
        }
        
        $curOS = wmic os get Caption
        if ($curOS[2].Contains('Server')) {
            Import-Module ServerManager
            if ($moduleGPMAvailable -eq $null) {
                Install-WindowsFeature GPMC -IncludeManagementTools -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null            
            }
            else {
                Add-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null            
            }		      
 			
        }			
        elseif ($curOS[2].Contains('Windows 11')) {
            if ($moduleGPMAvailable -eq $null) {
                DISM.exe /Online /add-capability /CapabilityName:Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null	
            }
            else {
                Add-WindowsCapability –online –Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0  -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null	
            }
		
        }
        #win10
        else {		
            if ($moduleGPMAvailable -eq $null) {
                Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -ErrorAction Stop -WarningAction SilentlyContinue  | Out-Null             
            }
            else {
                try {
                    Add-WindowsCapability –online –Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop -WarningAction SilentlyContinue  | Out-Null
                }
                catch {
                    #old versions up to 1803
                    Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell  -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                } 
            }
      
        }


        Import-Module grouppolicy -ErrorAction Stop -WarningAction SilentlyContinue  | Out-Null
        Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue  | Out-Null
	
    }
    catch {
        if ($Global:importModulesCnt -eq 1) {
            #we try re-run for admin
            return $false

        }
        else {
            if ($curOS[2].Contains('Server')) {
                write-host 'Unable to use this tool because imports for the following modules failed: ServerManager, Group Policy Managemnt Component, or Active Directory.' -ForegroundColor Yellow		
            }
            else {
                write-host 'Unable to use this tool because imports for the following modules failed: Group Policy Managemnt Component, or Active Directory.' -ForegroundColor Yellow		
            }

            write-host 'If it does not work, restart the machine, make sure the Windows update service is running, and then run this tool again.' -ForegroundColor Yellow
            Start-Sleep -Seconds 30
            Exit
        }

    }
    return $true

}

#clear some vars when turns back to the begining of the script
function Set-CTXGlobalVars {
    $Global:targetGPO = ''
    $Global:targetApp = ''
	

    $Global:installedAppsFoundInUnInstallKey.Clear()

    #whole app list
    $Global:existingHiddenAppNameList.Clear()
    $Global:appList.Clear()

    #current app's records if an app is chosen
    $Global:assList.Clear()
    $Global:fileRegList.Clear()
    $Global:userList.Clear()
    $Global:ouList.Clear()
    $Global:computerList.Clear()
    $Global:processList.Clear()
    $Global:rulesList.Clear()	
}
#region find app list
function Get-CTXInstallApps {
    foreach ($curScope in $Global:unisntallKeySearchScope) {   
        if (Test-Path $curScope) {
            $res = foreach ($key in (Get-ChildItem $curScope)) {              
                $tmp = $key.Name.split('\')[-1]


                if ($tmp.Contains('{')) {
                    if (($key.GetValue('DisplayName', '') -ne '') -and ($key.GetValue('SystemComponent', 0) -ne 1)) {

                        if (($Global:knownIgnoredAppsList -Contains $key.GetValue('DisplayName', '')) -or ($key.GetValue('DisplayName', '') -like 'Citrix Virtual Apps and Desktops*')) {
                            continue
                        }

                        #if already found 
                        if ($Global:installedAppsFoundInUnInstallKey.ContainsKey($key.GetValue('DisplayName', ''))) {
                            continue
                        }

                        #if not found
                        else {                           
                            $curInstallPath = $key.GetValue('InstallLocation', '')
                            if ($curInstallPath -eq '') {                              
                                if ($key.GetValue('DisplayIcon', '') -eq '') {

                                }
                                else {
                                    #if the path is 'c:\users\public\a.exe',c:\users\public\a.exe, 'c:\users\public\a.exe 0' all works
                                    $curInstallPath = Split-Path -parent $key.GetValue('DisplayIcon', '')
                                }
                            
                            }

                            [void]$Global:installedAppsFoundInUnInstallKey.Add($key.GetValue('DisplayName', ''), $curInstallPath)                         
                        }
                    }
                }
                else {
                    if (($Global:knownIgnoredAppsList -Contains $tmp) -or ($tmp -like 'Citrix Virtual Apps and Desktops*')) {
                        continue
                    }
                    if (($Global:installedAppsFoundInUnInstallKey.ContainsKey($tmp)) -or ($key.GetValue('SystemComponent', 0) -eq 1) -or ($key.GetValue('DisplayName', '') -eq '')) {
                        continue
                    }
                    #if not exists, add it
                    else {
                        $curInstallPath = $key.GetValue('InstallLocation', '')
                        if ($curInstallPath -eq '') {                               
                            if ($key.GetValue('DisplayIcon', '') -eq '') {
                               
                            }
                            else {
                                #if the path is 'c:\users\public\a.exe',c:\users\public\a.exe, 'c:\users\public\a.exe 0' all works
                                $curInstallPath = Split-Path -parent $key.GetValue('DisplayIcon', '')
                            }                           
                        }

                        $curDisplayName = $key.GetValue('DisplayName', '')
                        if ($curDisplayName -ne '') {
                            $tmp = $curDisplayName
                        }
                        if ($Global:installedAppsFoundInUnInstallKey.ContainsKey($tmp) -eq $false)
                        {
                            [void]$Global:installedAppsFoundInUnInstallKey.Add($tmp, $curInstallPath)
                        }
                         
                    }
                }
            }       
        } 

    } 

    if ($Global:manuallyAppList.Count -ne 0) {

        $uniqueManList = $Global:manuallyAppList | select -Unique 
        $Global:manuallyAppList.Clear()
        if ($uniqueManList.Count -eq 1) {
            [void]$Global:manuallyAppList.Add($uniqueManList)
        }
        else {
            [void]$Global:manuallyAppList.AddRange($uniqueManList)
        }

        $curNames = $Global:installedAppsFoundInUnInstallKey.Keys

        foreach ($var in $Global:manuallyAppList) {
            if (!($curNames -Contains ($var))) {
                [void]$Global:installedAppsFoundInUnInstallKey.Add($var, '') 
            }
        }           
    }

}
function Get-CTXWindowsAppx {
    $res = Get-AppxPackage -AllUsers | Select-Object Name, InstallLocation
    if ($res -eq $null) {
        return
    }
    foreach ($curApp in $res) {
        if ($Global:installedAppsFoundInUnInstallKey.ContainsKey($curApp.Name) -eq $false) {
            [void]$Global:installedAppsFoundInUnInstallKey.Add($curApp.Name, $curApp.InstallLocation) 
        }
    }
}
function Get-CTXMergedApps {

    #loop $Global:installedAppsFoundInUnInstallKey, add to $Global:appList
    foreach ($tmp in $Global:installedAppsFoundInUnInstallKey.Keys) {
        if ((($Global:existingHiddenAppNameList -Contains $tmp) -eq $false) -and !(Test-CTXIsGuid -StringGuid $tmp)) {
            #Not a hidden app
            if (!($Global:RulesInMemoryAppList -contains $tmp)) {
                $val = [PsCustomObject]@{'Index' = $Global:appList.Count + 1; 'Status' = 'Not configured  '; 'Name' = $tmp; 'InstallDir' = $Global:installedAppsFoundInUnInstallKey[$tmp] }
            }
            else {
                $val = [PsCustomObject]@{'Index' = $Global:appList.Count + 1; 'Status' = 'Configured  '; 'Name' = $tmp; 'InstallDir' = $Global:installedAppsFoundInUnInstallKey[$tmp] }
            }
            
            $Global:appList.Add($val) | Out-NUll 
        }
    }    

}

function Get-CTXHiddenApps {
    $curRuleListFromReg = New-Object -TypeName 'System.Collections.ArrayList'
    #read policy HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Citrix\UserProfileManager\AppAccessControlRules
    $regPath = 'HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager'
    if (Test-Path $regPath) {
        $regKey = Get-Item –Path  $regPath

        $regValue = $regKey.GetValue('AppAccessControlRules', '')
        if ($regValue -eq '') {
        }
        else {
            $regValue = $regValue.Replace("`r`n","`n")
            $splitList = $regValue -split "`n"
            $hideAppwithchanges = New-Object -TypeName 'System.Collections.ArrayList'
    
            foreach ($curValue in $splitList) {        
                if (($curValue -eq $null) -or ($curValue -eq '')) {
                    continue
                }
                $curApp = $curValue.Split('|')[-1]

                #if remaining changes of apps exists in memory, ignore those from reg

                if (!($Global:RulesInMemoryAppList -contains $curApp)) {
                    [void]$Global:existingRuleList.Add($curValue)
                    [void]$curRuleListFromReg.Add($curValue)
                }
                else {
                    [void]$hideAppwithchanges.Add($curValue)
                }

            }


            if ($curRuleListFromReg.Count -gt 0) {
                #$uniqueList is in fixed size         
                $uniqueList = $curRuleListFromReg | select -Unique 
                $curRuleListFromReg.Clear()
                if ($uniqueList.Count -eq 1) {
                    [void]$curRuleListFromReg.Add($uniqueList)
                }
                else {
                    [void]$curRuleListFromReg.AddRange($uniqueList)
                }
               
                $uniqueList2 = $Global:existingRuleList | select -Unique 
                $Global:existingRuleList.Clear()

                if ($uniqueList2.Count -eq 1) {
                    [void]$Global:existingRuleList.Add($uniqueList2)
                }
                else {
                    [void]$Global:existingRuleList.AddRange($uniqueList2)
                }
            }


            #parse: <action type>|<target type>|<target path>| <target value>| <user and group list>|<process list>|<OU list>|<computer list>|<app name>
    
            foreach ($curRule in $curRuleListFromReg) {       
                $suspiciousRule = $curRule.Split('|')

                if (($suspiciousRule.Count -eq 9) -and ($suspiciousRule[0] -eq '0')) {
                    [void]$Global:existingHiddenAppNameList.Add($suspiciousRule[8])
                }
        
            } 
            foreach ($curRule in $hideAppwithchanges) {       
                $suspiciousRule = $curRule.Split('|')

                if (($suspiciousRule.Count -eq 9) -and ($suspiciousRule[0] -eq '0')) {
                    [void]$Global:existingHiddenAppNameList.Add($suspiciousRule[8])
                }       
            }

            if ($Global:existingHiddenAppNameList.Count -gt 0) {
                $uniqueListofHiddenApp = $Global:existingHiddenAppNameList | select -Unique
                $Global:existingHiddenAppNameList.Clear()
                if ($uniqueListofHiddenApp.Count -eq 1) {
                    [void]$Global:existingHiddenAppNameList.Add($uniqueListofHiddenApp)
                }
                else {
                    [void]$Global:existingHiddenAppNameList.AddRange($uniqueListofHiddenApp)
                }        
            }

 
            $found = $false 
            foreach ($tmpAppName in $Global:existingHiddenAppNameList) {

                for ($i = 0; $i -lt $Global:appList.Count; $i++) {
                    if ($Global:appList[$i].Name -eq $tmpAppName) {
                        $found = $true
                        $Global:appList.RemoveAt($i)
                        $i--
                        break
                    }
                }


                if ($found) {

                    $found = $false
                }
                if (!(Test-CTXIsGuid -StringGuid $tmpAppName)) {
                    if (!($Global:RulesInMemoryAppList -contains $tmpAppName)) {
                        $newval = [PsCustomObject]@{'Index' = $Global:appList.Count + 1; 'Status' = 'Configured & applied  '; 'Name' = $tmpAppName; 'InstallDir' = '' }
                    }
                    else {
                        $newval = [PsCustomObject]@{'Index' = $Global:appList.Count + 1; 'Status' = 'Configured  '; 'Name' = $tmpAppName; 'InstallDir' = '' }
                    }
                    $Global:appList.Add($newval) | Out-NUll 
                }


            } 		
        }

		
    }

       
} 

#endregion
function Test-CTXInteger {
    param(
        [string]$curInput
    )
    return $curInput -match '^[0-9]+$'

}
function Show-CTXCurrentFileRegs {
    write-host "`r`nFile and registry list:" -ForegroundColor Green
    if ($Global:fileRegList.Count -eq 0) {
        write-host 'No files and registry entries exist. With no files and registry entries configured, this app is visible to all users, machines, and processes.' -ForegroundColor yellow
    }
    else {
        $Global:fileRegList | Format-Table -wrap -autosize -property Index, Type, Path
    }              
}
function Show-CTXCurrentAssignments {
    write-host "`r`nAssignment list:" -ForegroundColor Green
    if ($Global:assList.Count -eq 0) {
        write-host 'No assignments configured. This app is not visible to any users, computers, or processes.' -ForegroundColor Yellow
    }
    else {
        $Global:assList | Select-object Index, Type, SID, Name | Format-Table
    }
}
function Get-CTXTargetApp {
    
    Write-Host "`r`n`r`n"
    $configuredRules = $Global:appList | Where-Object Status -ne 'Not configured  '
    $choiceList = @('D', 'V', 'A')
    if ($configuredRules -eq $null) {
        $choiceList = @('D', 'A')
        Write-Host "`r`n[D] Delete all configured rules" -ForegroundColor green          
    }
    else {
        Write-Host "`r`n[D] Delete all configured rules`r`n[V] View existing rules for all apps" -ForegroundColor green 
    }

    Write-Host "[A] Add an app to the list`r`n------------------------------------------------------------`r`nTo add rules for an app from the list above, enter its index.`r`n" -ForegroundColor green 
    $appChosenID = (Read-Host  'Enter input').Trim() 
    
    while (($appChosenID -eq $null) -or ($appChosenID -eq '') -or (((Test-CTXInteger -curInput $appChosenID) -eq $false) -and (!($choiceList -Contains $appChosenID))) -or (((Test-CTXInteger -curInput $appChosenID) -eq $true) -and (([int]$appChosenID -gt $Global:appList.Count) -or ([int]$appChosenID -lt 1)))) {
        Write-Host 'Invalid input. Enter the input correctly.' -ForegroundColor yellow
        $appChosenID = (Read-Host  'Enter input').Trim()
    }
    if ($appChosenID -eq 'D') {
        #generate rules
        Format-CTXAppAccessControlRules -saveChangesAndReturnToBegining $false -deleteAll $true
        return
    }
    elseif ($appChosenID -eq 'A') {
        #allow admin to manaully enter an app name
        $tmp = (Read-Host  'Enter the app name. If you do not want to add it now, press <Enter>').Trim()

        while (($tmp -eq $null) -or (($Global:appList | Select-Object Name).Name -contains $tmp) -or (($tmp -ne '') -and ((Test-CTXIsGuid -StringGuid $tmp) -or !(Test-CTXAppName -path $tmp) -or (($Global:knownIgnoredAppsList -Contains $tmp) -or ($tmp -like 'Citrix Virtual Apps and Desktops*'))))) {
            if (($tmp -eq $null) -or !(Test-CTXAppName -path $tmp)) {
                Write-Host 'Invalid input.' -ForegroundColor yellow
                $tmp = (Read-Host  'Enter the app name. If you do not want to add it now, press <Enter>').Trim()
            }
            elseif (Test-CTXIsGuid -StringGuid $tmp) {
                Write-Host 'Invalid input. Please enter an app name instead of a GUID.' -ForegroundColor yellow
                $tmp = (Read-Host  'Enter the app name. If you do not want to add it now, press <Enter>').Trim()
            }
            elseif (($Global:knownIgnoredAppsList -Contains $tmp) -or ($tmp -like 'Citrix Virtual Apps and Desktops*')) {
                Write-Host 'Protected app.' -ForegroundColor yellow
                $tmp = (Read-Host  'Enter the app name. If you do not want to add it now, press <Enter>').Trim()
            }
            else {
                Write-Host 'This app name is already on the app list.' -ForegroundColor yellow
                Get-CTXTargetApp
            }

            
            
        }
        if ($tmp -ne '') {
            $anotherApp = [PsCustomObject]@{'Index' = $Global:appList.Count + 1; 'Status' = 'Not configured  '; 'Name' = $tmp; 'InstallDir' = '' }
            $Global:appList.Add($anotherApp) | Out-Null
            $Global:manuallyAppList.Add($tmp) | Out-Null
            Show-CTXWholeAppList
        }

        Get-CTXTargetApp
    }
    elseif ($appChosenID -eq 'V') {
        write-host "`r`n`r`n************************************************************" -ForegroundColor Yellow
        write-host "`r`nAll Apps details:" -ForegroundColor Yellow
        #display ruls for all apps
        $Global:targetApp = ''
        $allApps = ($Global:appList | Select-Object Name).Name
        foreach ($var in $allApps) {           
            Get-CTXAppRelatedRules -app $var
            if (($Global:fileRegList.Count -eq 0) -and ($Global:assList.Count -eq 0)) {
                #skip
            }
            else {
                write-host "`r`n`r`n************************************************************" -ForegroundColor Yellow
                write-host "`r`nApp:"$var -ForegroundColor Green
                Show-CTXCurrentFileRegs
                Show-CTXCurrentAssignments                
            } 
                    
        }
        write-host "`r`n************************************************************`r`n`r`n" -ForegroundColor Yellow
        #generate rules
        $configuredRules = $Global:appList | Where-Object Status -eq 'Configured  '
        if ($configuredRules -ne $null) {
            Format-CTXAppAccessControlRules -saveChangesAndReturnToBegining $false         
        }
        else {
            write-host "`r`n[Y] Add more rules`r`n[N] Exit`r`n" -ForegroundColor Green
            $continueGeneratingRules = (Read-Host  'Enter input').Trim() 
            while (($continueGeneratingRules -ne 'Y') -and ($continueGeneratingRules -ne 'N')) {
                write-host 'Invalid input:'$continueGeneratingRules -ForegroundColor yellow
                $continueGeneratingRules = (Read-Host  'Enter input').Trim() 
            }                                         
            if ($continueGeneratingRules -eq 'Y') {
                Get-CTXAppAccessControlRules
            }
            else {
                Exit
            }
        }
       
        return
    }
    else {
        $appChosenRecord = $Global:appList | Where-Object Index -EQ $appChosenID
        $Global:targetApp = $appChosenRecord.Name
    }

    Get-CTXAppRelatedRules -app $Global:targetApp

    #if app is a hidden app
    if ( ($appChosenRecord.Status -eq 'Configured & applied  ') -or ($appChosenRecord.Status -eq 'Configured  ')) {        
        #nothing to do
    }
    #app is not hidden, but there are remaining rules for it in $Global:existingRuleList which is set into $Global:fileRegList in above Get-CTXAppRelatedRules
    elseif ($Global:fileRegList.Count -gt 0) {
        #nothing to do
    }

    #if app is not hide now
    else {
        # collect the install dir
        $appChosenInstallPath = $appChosenRecord.InstallDir              

        if ($appChosenInstallPath -ne '') {          
        }
        else {
            Write-Host 'Installation folder not found. Enter the full installation path. If you do not want to add it now, press <Enter>' -ForegroundColor Yellow
            $appChosenInstallPath = (Read-Host  'Enter path').Trim()
            while (($appChosenInstallPath -ne '') -and (((Test-CTXAppPath -path $appChosenInstallPath) -ne $true) -or (Check-CTXImportantFileFolderPath -testPath $appChosenInstallPath.Trim().TrimEnd('\')))) {
                if (($appChosenInstallPath -ne '') -and ((Test-CTXAppPath -path $appChosenInstallPath) -ne $true)) {
                    Write-Host 'Invalid path:'$appChosenInstallPath'. Make sure that you enter the path correctly, or press the Enter key directly if you do not want to add path here.' -ForegroundColor Yellow 
                }
                else {
                    Write-Host 'Make sure that you enter the path correctly, or press the Enter key directly if you do not want to add path here.' -ForegroundColor Yellow 

                }
                $appChosenInstallPath = (Read-Host  'Enter path').Trim() 
            }
        }
        if (($appChosenInstallPath -ne '') -and !(Check-CTXImportantFileFolderPath -testPath $appChosenInstallPath.Trim().TrimEnd('\'))) {
            $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Folder'; 'Path' = $appChosenInstallPath.Trim().TrimEnd('\'); 'Value' = '' }) | Out-NUll
        }



        #  collect the install key

        Get-CTXInstallKey



        #  collect the uninstall key

        Get-CTXUninstallKey


        #  collect key containing service or driver info
        if (Test-Path $Global:ServiceORDriverInfoSearchScope) {
            $res = foreach ($key in (Get-ChildItem $Global:ServiceORDriverInfoSearchScope)) {
                if (($key.GetValue('DisplayName') -like $Global:targetApp) -and !(Check-CTXImportantRegPath -testPath $key.Name.Trim().TrimEnd('\'))) {
                    $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry key'; 'Path' = $key.Name.Trim().TrimEnd('\'); 'Value' = '' }) | Out-NUll               
                }
            }
        }

        #find out shortcut
        Get-CTXShotcuts


        # findout HKLM\software\
        $keyUnderSoftware = 'HKLM:\software\' + $Global:targetApp 
        $res = Test-Path $keyUnderSoftware
        if (($res -eq $True) -and !(Check-CTXImportantRegPath -testPath $keyUnderSoftware.Trim().TrimEnd('\'))) { 
            $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry key'; 'Path' = $keyUnderSoftware.Trim().TrimEnd('\'); 'Value' = '' }) | Out-NUll
        }

        #HKLM:\software\*\<app>
        $indirect = @('HKLM:\SOFTWARE\')
        if (Test-Path $indirect) {
            $res = foreach ($key in (Get-ChildItem $indirect)) {
                $res2 = foreach ($key2Name in $key.GetSubKeyNames()) {
                    if ($key2Name -eq $Global:targetApp) {
                        $t = 'HKLM:\SOFTWARE\' + $key.Name.Split('\')[-1] + '\' + $key2Name 
                        if (!(Check-CTXImportantRegPath -testPath $t.Trim().TrimEnd('\'))) {
                            $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry key'; 'Path' = $t.Trim().TrimEnd('\'); 'Value' = '' }) | Out-NUll
                        }                                         
                    }
                }
            }
        }




    }

    Get-CTXUserInteractions
}


#retrieve from both reg and the previous config after this tool started
function Get-CTXAppRelatedRules {
    param(
        [string]$app
    )
    $assignProcessed = $false
    $Global:fileRegList.Clear()
    $Global:assList.Clear()
    foreach ($curRule in $Global:existingRuleList) {
        $bSkip = $false       
        $suspiciousRule = $curRule.Split('|')

        if (($suspiciousRule.Count -eq 9) -and ($suspiciousRule[0] -eq '0') -and ($suspiciousRule[8] -eq $app)) {
            switch ($suspiciousRule[1]) {

                '0' {
                    if (Check-CTXImportantFileFolderPath -testPath $suspiciousRule[2].Trim().TrimEnd('\')) {
                        $bSkip = $true
                        break                       
                    }
                    $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'File'; 'Path' = $suspiciousRule[2].Trim().TrimEnd('\'); 'Value' = '' }) | Out-Null
                       
                }
                '1' {
                    if (Check-CTXImportantRegPath -testPath $suspiciousRule[2].Trim().TrimEnd('\')) {
                        $bSkip = $true
                        break 
                    }
                    $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry key'; 'Path' = $suspiciousRule[2].Trim().TrimEnd('\'); 'Value' = '' }) | Out-Null


                }
                '2' {
                    if (Check-CTXImportantRegPath -testPath ($suspiciousRule[2].Trim().TrimEnd('\') + '\' + $suspiciousRule[3].Trim().TrimEnd('\'))) {
                        $bSkip = $true
                        break 
                    }
                    $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry Value'; 'Path' = $suspiciousRule[2].Trim().TrimEnd('\') + '\' + $suspiciousRule[3].Trim().TrimEnd('\'); 'Value' = $suspiciousRule[3].Trim().TrimEnd('\') }) | Out-Null
                       
                }
                '3' {
                    if (Check-CTXImportantFileFolderPath -testPath $suspiciousRule[2].Trim().TrimEnd('\')) {
                        $bSkip = $true
                        break 
                    }
                    $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Folder'; 'Path' = $suspiciousRule[2].Trim().TrimEnd('\'); 'Value' = '' }) | Out-Null


                }
            }
            if ($bSkip) {
                continue
            }
            if ($assignProcessed -eq $false) {
                $bIsADAllComputers = $false
                $bIsNDJAllComputers = $false

                for ($i = 4; $i -lt 8; $i++) {
                    if ($suspiciousRule[$i] -eq '*') {
                   
                    }
                    else {
                        $tmpList = $suspiciousRule[$i].split(':')
                        foreach ($var in  $tmpList) { 
                            $eachAss = $var -split '@CTXASSSEP@'
                            #AD*, NDJ* 
                            if(($eachAss[1] -eq 'AD*') -and ($eachAss[0] -eq 'Computer'))
                            {
                                $bIsADAllComputers = $true
                                continue
                            }
                            elseif(($eachAss[1] -eq 'NDJ*') -and ($eachAss[0] -eq 'Computer'))
                            {
                                $bIsNDJAllComputers = $true
                                continue
                            }

                            #user /group for NDJ                                                                                           
                            if((($eachAss[0] -EQ 'User') -or ($eachAss[0] -EQ 'Group')) -and ($eachAss[1] -like '/*' ))
                            {
                                $val = [PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = $eachAss[0]; 'SID' = $eachAss[1]; 'Name' = $eachAss[2]; 'Scope' = 'NDJ'}
                                $Global:assList.Add($val) | Out-NUll
                                continue
                            } 
                            #others
                            $type = $eachAss[0]                    
                            if($eachAss[1] -EQ 'NDJ')
                            {   #machine or machine catalog for NDJ
                                #<action type>|<target type>|<target path>| <target value>| <user and group list>|<process list>|<OU list>|<computer list>|<app name>

                                if($i -eq 6)
                                {
                                    $type = 'Machine catalog'
                                }
                                elseif($i -eq 7)
                                {
                                    $type = 'AAD/NDJ machine'
                                }
                                $val = [PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = $type; 'SID' = ''; 'Name' = $eachAss[2]; 'Scope' = 'NDJ'}
                                $Global:assList.Add($val) | Out-NUll                            
                            }

                            else
                            {

                                if($i -eq 6)
                                {
                                    $type = 'OU'
                                }
                                elseif($i -eq 7)
                                {
                                    $type = 'AD machine'
                                }

                                $val = [PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = $type; 'SID' = $eachAss[1]; 'Name' = $eachAss[2]}
                                $Global:assList.Add($val) | Out-NUll                         
                            }                                                

                        }  
                        
                                              
                    }
                }
                if($bIsADAllComputers -and $bIsNDJAllComputers)
                {
                    #it equals to *
                    for ($i = $Global:assList.Count - 1; $i -ge 0; $i--) {
                        if (($Global:assList[$i]).Type -eq  'AD machine') {
                            $Global:assList.RemoveAt($i)
                        }
                    }
                    for ($i = $Global:assList.Count - 1; $i -ge 0; $i--) {
                        if (($Global:assList[$i]).Type -eq  'AAD/NDJ machine') {
                            $Global:assList.RemoveAt($i)
                        }
                    }
                }
                elseif($bIsADAllComputers)
                {
                    # delete assignments to other AD computers
                    
                    for ($i = $Global:assList.Count - 1; $i -ge 0; $i--) {
                        if (($Global:assList[$i]).Type -eq  'AD machine') {
                            $Global:assList.RemoveAt($i)
                        }
                    }
                    $val = [PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'AD machine'; 'SID' = ''; 'Name' = 'AD*'}
                    $Global:assList.Add($val) | Out-NUll

                }
                elseif($bIsNDJAllComputers)
                {
                    for ($i = $Global:assList.Count - 1; $i -ge 0; $i--) {
                        if (($Global:assList[$i]).Type -eq  'AAD/NDJ machine') {
                            $Global:assList.RemoveAt($i)
                        }
                    }
                    $val = [PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'AAD/NDJ machine'; 'SID' = ''; 'Name' = 'NDJ*'; 'Scope' = 'NDJ'}
                    $Global:assList.Add($val) | Out-NUll

                }


                $assignProcessed = $true  
            }
            
        }        
    }
}


function Get-CTXInstallKey {

    $installKeySearchScope1 = 'HKLM:\software\classes\installer\products'
    $installKeySearchScope2 = 'HKLM:\software\Microsoft\windows\currentversion\installer\userdata'

    if (Test-Path $installKeySearchScope1) {
        $res = foreach ($key in (Get-ChildItem $installKeySearchScope1)) {
            if (($key.GetValue('ProductName') -like $Global:targetApp) -and !(Check-CTXImportantRegPath -testPath $key.Name.Trim().TrimEnd('\'))) {        
                #eg,KEY_LOCAL_MACHINE\software\classes\installer\products\023B5DCD9D98C7C4E9B84894568847E4
                $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry key'; 'Path' = $key.Name.Trim().TrimEnd('\'); 'Value' = '' }) | Out-Null
            }   
        }
    }

    if (Test-Path installKeySearchScope2) {
        $res = foreach ($key in (Get-ChildItem $installKeySearchScope2)) {
            #HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18
            $subKeyName = $installKeySearchScope2 + '\' + $key.Name.split('\')[-1] + '\Products'  

            if (Test-Path $subKeyName) {
                foreach ($key2 in (Get-ChildItem $subKeyName)) {
                    #HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\1A66E47F49A35C54A94E209149516CB2
                    $subkeyName2 = $subKeyName + '\' + $key2.Name.split('\')[-1] + '\InstallProperties'

                    if (Test-Path $subkeyName2) {
                        $subKey2 = Get-Item -Path $subkeyName2
                        if (($subKey2.GetValue('DisplayName', '') -like $Global:targetApp) -and !(Check-CTXImportantRegPath -testPath $key2.Name.Trim().TrimEnd('\'))) {                            

                            $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry key'; 'Path' = $key2.Name.Trim().TrimEnd('\'); 'Value' = '' }) | Out-Null
                        
                        }  
                    }
                }
            }
        }
    }

}

function Get-CTXUninstallKey {

    foreach ($tmpKey in $Global:unisntallKeySearchScope) {
        if (Test-Path $tmpKey) {
            $res = foreach ($key in (Get-ChildItem $tmpKey)) {
                if (($key.GetValue('DisplayName') -like $Global:targetApp) -and !(Check-CTXImportantRegPath -testPath $key.Name.Trim().TrimEnd('\'))) {
                    $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry key'; 'Path' = $key.Name.Trim().TrimEnd('\'); 'Value' = '' }) | Out-Null
                }
            }
        }

    }
}
function Get-CTXShotcuts {    
    $pattern = '*' + $Global:targetApp + '*'
    $Global:ShotcutList.Clear()
    if (Test-Path 'c:\users') {
        $curList = Get-ChildItem 'c:\users'
        foreach ($curPath in $curList) {
            #C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\app.ink 
            #C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\app
            $shortCutInStartMenu = 'c:\users\' + $curPath + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\'
            Get-CTXShotcutImpl -testPath shortCutInStartMenu -addFolder $false
            #C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\<company>\
            $shortCutInStartMenu = 'c:\users\' + $curPath + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\'       
            $res = Test-Path $shortCutInStartMenu
            if ($res -eq $True) {
                $tmpList = Get-ChildItem $shortCutInStartMenu
                foreach ($potentialCompany in $tmpList) {
                    if (($potentialCompany.Name -like $pattern) -or ($Global:targetApp.ToLower().Contains($potentialCompany.Name.ToLower()))) {
                        $curFullpath = $shortCutInStartMenu + $potentialCompany.Name + '\'
                        Get-CTXShotcutImpl -testPath $curFullpath -addFolder $true
                    }

                }
            }
        
            #Desktop\app.lnk
            $shortCutInDesktop = 'c:\users\' + $curPath + '\Desktop\'
            Get-CTXShotcutImpl -testPath $shortCutInDesktop -addFolder $false


            #AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\app.lnk
            $shortCutInExplorer = 'c:\users\' + $curPath + '\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\'
            Get-CTXShotcutImpl -testPath $shortCutInExplorer -addFolder $false

            #AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\app.lnk
            $shortCutInExplorer = 'c:\users\' + $curPath + '\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\'
            Get-CTXShotcutImpl -testPath $shortCutInExplorer -addFolder $false

            #AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\app.lnk
            $shortCutInExplorer = 'c:\users\' + $curPath + '\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\'
            Get-CTXShotcutImpl -testPath $shortCutInExplorer -addFolder $false
        }
    }
    #C:\ProgramData\Microsoft\Windows\Start Menu\Programs\app.lnk
    #C:\ProgramData\Microsoft\Windows\Start Menu\Programs\app
    $shortCutInStartMenu = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\'
    Get-CTXShotcutImpl -testPath $shortCutInStartMenu -addFolder $false
    

    #C:\ProgramData\Microsoft\Windows\Start Menu\Programs\<company>\
    $shortCutInStartMenu = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\'      
    $res = Test-Path $shortCutInStartMenu
    if ($res -eq $True) {
        $tmpList = Get-ChildItem $shortCutInStartMenu
        foreach ($potentialCompany in $tmpList) {
            if (($potentialCompany.Name -like $pattern) -or ($Global:targetApp.ToLower().Contains($potentialCompany.Name.ToLower()))) {
                $curFullpath = $shortCutInStartMenu + $potentialCompany.Name + '\'
                Get-CTXShotcutImpl -testPath $curFullpath -addFolder $true
            }

        }
    }


    foreach ($curShotcut in $Global:ShotcutList) {
        if (($Global:fileRegList.Count -eq 0) -or (!($Global:fileRegList.Path -contains $curShotcut.path))) {
            $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = $curShotcut.Type; 'Path' = $curShotcut.Path; 'Value' = '' }) | Out-Null
        }
    }
    
}
#find out  $testPath\app or $testPath\app.lnk, $testPath ends with '\'
function Get-CTXShotcutImpl {
    param(
        [Parameter(Mandatory = $true)][string]$testPath,
        [Parameter(Mandatory = $true)][bool]$addFolder
    )
    if (($testPath -eq $null) -or ($testPath -eq '')) {
        return 
    }
    $blnkFound = $false
    $existCnt = $Global:ShotcutList.count
    $sh = New-Object -ComObject WScript.Shell
    

    $res = Test-Path $testPath
    if ($res -eq $True) {
        #1 add $testPath\*.lnk that has target involved
        $potentialShotcutList = Get-ChildItem $testPath | Where-Object Name -Like *.lnk
        if ($potentialShotcutList.Count -gt 0) {
            foreach ($t in $potentialShotcutList) {
                $blnkFound = $false

                $tmpPath = $testPath + $t.Name.Trim().TrimEnd('\')
                $target = $sh.CreateShortcut($tmpPath).TargetPath

                #target is not empty, and target is already found or link name is app name, then this link is what we want
                if ($target -ne '') {   

                    if ($Global:fileRegList.Count -gt 0) {
                        foreach ($curPath in $Global:fileRegList) {
                            if ($curPath.Type -ne 'Folder') {
                                continue
                            }
                            $lowercurPath = $curPath.Path.ToLower()
                            $lowerTarget = $target.TrimEnd('\').ToLower()

                            if ($lowercurPath -eq $lowerTarget) {
                                $blnkFound = $true
                                break
                            }
                            elseif ($lowerTarget.Contains($lowercurPath) -and $lowerTarget.Contains($lowercurPath + '\')) {
                                $blnkFound = $true
                                break
                            }

                        }
                    }
                    else {
                        
                        continue
                    }
                    if (!$blnkFound) {
                        continue
                    }
                    #lnk found now                                                     
                    if (!(Check-CTXImportantFileFolderPath -testPath $tmpPath)) {
                        $Global:ShotcutList.Add([PsCustomObject]@{'Index' = $Global:ShotcutList.Count + 1; 'Type' = 'File'; 'Path' = $tmpPath; 'Value' = '' }) | Out-Null
                    }

                    
                }
            }           
        }

        #2 add sub folder with name $Global:targetApp
        $cur = (Get-ChildItem $testPath | Where-Object Name -eq $Global:targetApp)
        if ($cur -ne $null) {
            $Global:ShotcutList.Add([PsCustomObject]@{'Index' = $Global:ShotcutList.Count + 1; 'Type' = 'Folder'; 'Path' = $testPath + $Global:targetApp; 'Value' = '' }) | Out-Null
        }

    }
    #add the whole folder if anything found in it
    if ($addFolder -and ($Global:ShotcutList.count -gt $existCnt) ) {
        $Global:ShotcutList.Add([PsCustomObject]@{'Index' = $Global:ShotcutList.Count + 1; 'Type' = 'Folder'; 'Path' = $testPath.TrimEnd('\'); 'Value' = '' }) | Out-Null
    }



}
function Remove-CTXMultpleItems {
    param(
        [Parameter(Mandatory = $true)][string]$deleteData,
        [Parameter(Mandatory = $true)][System.Collections.ArrayList]$sourceList
    )

    $invalidInputIndex = New-Object -TypeName 'System.Collections.ArrayList'
    $dupInputIndex = New-Object -TypeName 'System.Collections.ArrayList'

    try { 
        $tmp = $deleteData.Split(',')
        $IDs = New-Object -TypeName 'System.Collections.ArrayList'
        [void]$IDs.AddRange($tmp)
        for ($i = 0; $i -lt $IDs.Count; $i++) {
            if (((Test-CTXInteger -curInput $IDs[$i]) -eq $false) -or (([int]$IDs[$i]) -lt 1) -or (([int]$IDs[$i]) -gt $sourceList.Count)) { 
                [void]$invalidInputIndex.Add($IDs[$i])                 
                $IDs.RemoveAt($i--)                                                    
            }
        }
        if ($IDs.Count -gt 0) {	
            $uniqueIDs = $IDs | select -Unique

            $cmp = Compare-object –referenceobject $uniqueIDs –differenceobject $IDs
	
            if ($cmp.InputObject.Count -gt 0) {	
                [void]$dupInputIndex.AddRange($cmp.InputObject)                          
            } 
          						
                        
            for ($i = 0; $i -lt $sourceList.Count; $i++) {
                if ($uniqueIDs -Contains [INT](($sourceList[$i]).Index)) {
                    $sourceList.RemoveAt($i--)		                            
                }
            }
        
            for ($i = 0; $i -lt $sourceList.Count; $i++) {
                $sourceList[$i].Index = $i + 1
            }
        }

	
        if ($invalidInputIndex.Count -gt 0) {
            $res = ''
            foreach ($invalidID in $invalidInputIndex) {
                $res = $res + $invalidID + ','
            }
            write-host 'Invalid items skipped:'$res.ToString().TrimEnd(',') -ForegroundColor yellow	
                            
        }

        if ($dupInputIndex.Count -gt 0) {
            $res = ''
            foreach ($invalidID in $dupInputIndex) {
                $res = $res + $invalidID + ','
            }
            write-host 'Duplicated items skipped:'$res.ToString().TrimEnd(',') -ForegroundColor yellow	
                            
        }  					
                        			
    }
    catch {
        write-host 'Invalid value: '$deleteData	-ForegroundColor yellow			
    }

}
function Get-CTXAssignments {
    Show-CTXCurrentAssignments


    $curCommand = ''
    $choiceList = @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13')
    if ($Global:assList.Count -eq 0) {
        $curCommand = "`r`nDo you want to add an assignment for this app?`r`n`r`n[1] Discard the changes you made to the app and continue adding rules for other apps`r`n[2] Save your changes and continue adding rules for other apps`r`n[3] Edit files and resgistries`r`n[4] Generate the rules for deployment to machines`r`n    If no assignments are configured, this app is not visible`r`n------------------------------------------------------------`r`n[5] Add users`r`n[6] Add user groups`r`n[7] Add OUs `r`n[8] Add AAD/NDJ machine catalogs`r`n    AAD: Azure AD; NDJ: Non-Domain-Joined`r`n[9] Add AD machines`r`n[10] Add AAD/NDJ machines`r`n[11] Add processes`r`n" 
        $choiceList = @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11')
    }
    else {
        $curCommand = "`r`nDo you want to add an assignment for this app? Or want to delete one? `r`n`r`n[1] Discard the changes you made to the app and continue adding rules for other apps`r`n[2] Save your changes and continue adding rules for other apps`r`n[3] Edit files and resgistries`r`n[4] Generate the rules for deployment to machines`r`n    If no assignments are configured, this app is not visible`r`n------------------------------------------------------------`r`n[5] Add users`r`n[6] Add user groups`r`n[7] Add OUs `r`n[8] Add AAD/NDJ machine catalogs`r`n    AAD: Azure AD; NDJ: Non-Domain-Joined`r`n[9] Add AD machines`r`n[10] Add AAD/NDJ machines`r`n[11] Add processes`r`n[12] Delete specific assignments`r`n[13] Delete all assignments`r`n"      
    }
    write-host $curCommand -ForegroundColor Green

    $tmpchoice = (Read-Host  'Enter value').Trim()


    
    while ($true) {     
        if (($tmpchoice -eq $null) -or ($tmpchoice -eq '') -or ((Test-CTXInteger -curInput $tmpchoice) -ne $true) -or (($choiceList -Contains $tmpchoice) -ne $true)) {      
            $max = $choiceList.Count    
            write-host 'Invalid value. Enter a value of 1 -'$max "`r`n" -ForegroundColor yellow
            $tmpchoice = (Read-Host  'Enter value').Trim()
            continue
        }
        else {                       
            switch ([int]$tmpchoice) {
                '1' {
                    #return to the begining
                    Get-CTXAppAccessControlRules
                    return
                }
                '2' {
                    #generate rules and add to $Global:existingRuleList: raw data
                    if (!($Global:RulesInMemoryAppList -contains $Global:targetApp)) {
                        $Global:RulesInMemoryAppList.Add($Global:targetApp) | Out-Null
                    } 
                    Format-CTXAppAccessControlRules -saveChangesAndReturnToBegining $true
                    #return to the begining
                    Get-CTXAppAccessControlRules
                    return
                }
                '3' {
                    if (!($Global:RulesInMemoryAppList -contains $Global:targetApp)) {
                        $Global:RulesInMemoryAppList.Add($Global:targetApp) | Out-Null
                    } 
                    Get-CTXUserInteractions
                    return			 
                }
                '4' {
                    #go to generate rules
                    if (!($Global:RulesInMemoryAppList -contains $Global:targetApp)) {
                        $Global:RulesInMemoryAppList.Add($Global:targetApp) | Out-Null
                    } 
                    Format-CTXAppAccessControlRules -saveChangesAndReturnToBegining $false
                    return
                }
                '5' {  
                    $command =  "Enter users you want to add, separated by pipe.`r`n`    - For AD users, enter <Domain name>\<User name1>|<Domain name>\<User name2>.`r`n`    - For AAD/NDJ users, use the AAD/NDJ object selector in the WEM web console to collect their names and OIDs, and then enter <OID>\<User name1>|<OID>\<User name2>. Example: /azuread/989c2938-6527-4133-bab1-f3860dd15098\TestUser1|/azuread/82bdde32-d5d9-4d64-b0ff-9876d4488d05\TestUser2. For more information, see this WEM article. https://docs.citrix.com/en-us/workspace-environment-management/service/manage/configuration-sets/citrix-profile-management.html#app-access-control."
                    write-host $command -ForegroundColor Green
                    [string]$newData = (Read-Host  'Enter users').Trim()
               
                    $tmpDataList = $newData.split('|')
                    foreach ($t in $tmpDataList) {
                        $tmpData = $t.ToString().Trim()
                        if ($tmpData -eq '') {
                            continue
                        }
                        #check if duplicates
                        $dup = $Global:assList  | Where-Object Type -EQ 'User' | Select-Object Name
                        if (($dup -ne $null) -and ($dup.Name -ccontains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        }
                        try {
                            if ($tmpData -like '/*')
                            {
                                $tmpInput = $tmpData.split('\')

                                $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'User'; 'SID' = $tmpInput[0]; 'Name' = $tmpInput[1]; 'Scope' = 'NDJ' }) | Out-Null
                            }
                            else
                            {
                                $curusersid = (New-Object System.Security.Principal.NTAccount($tmpData)).Translate([System.Security.Principal.SecurityIdentifier]).value
                                $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'User'; 'SID' = $curusersid; 'Name' = $tmpData }) | Out-Null
                            }

                        }
                        catch {
                            write-host 'Invalid item skipped:' $tmpData -ForegroundColor Yellow
                        }                    
                    }
                    
                    break
                      
                }
                '6' {  
                     $command =  "Enter user groups you want to add, separated by pipe.`r`n`    - For AD groups, enter <Domain name>\<Group name 1>|<Domain name>\<Group name 2>.`r`n`    - For AAD/NDJ groups, use the AAD/NDJ object selector in the WEM web console to collect their names and OIDs, and then enter <OID>\<Group name1>|<OID>\<Group name2>. Example: /azuread/989c2938-6527-4133-bab1-f3860dd15098\TestGroup1|/azuread/82bdde32-d5d9-4d64-b0ff-9876d4488d05\TestGroup2. For more information, see this WEM article, https://docs.citrix.com/en-us/workspace-environment-management/service/manage/configuration-sets/citrix-profile-management.html#app-access-control."
                    write-host $command -ForegroundColor Green
                    [string]$newData = (Read-Host  'Enter groups').Trim()
                    #we only support normal path/assignments that themselves does not contains '|'
                    $tmpDataList = $newData.split('|')
                    foreach ($t in $tmpDataList) {
                        $tmpData = $t.ToString().Trim()
                        if ($tmpData -eq '') {
                            continue
                        }
                        #check if duplicates
                        $dup = $Global:assList  | Where-Object Type -EQ 'Group' | Select-Object Name
                        if (($dup -ne $null) -and ($dup.Name -ccontains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        }
                        try {

                            if($tmpData -like '/*')
                            {
                                $tmpInput = $tmpData.split('\')
                                $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'Group'; 'SID' = $tmpInput[0]; 'Name' = $tmpInput[1]; 'Scope' = 'NDJ' }) | Out-Null
                            }
                            else
                            {
                                $curusersid = (New-Object System.Security.Principal.NTAccount($tmpData)).Translate([System.Security.Principal.SecurityIdentifier]).value
                                $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'Group'; 'SID' = $curusersid; 'Name' = $tmpData }) | Out-Null
                            }

                        }
                        catch {
                            write-host 'Invalid item skipped:' $tmpData -ForegroundColor Yellow
                        }                    
                    }
                    
                    break
                      
                }				
                '7' {
                    $command = "Enter OUs you want to add, separated by pipe.`r`n`    Example: <OU name1>|<OU name2>`r`n"
                    write-host $command -ForegroundColor Green
                    [string]$newData = (Read-Host  'Enter OUs').Trim()
                    $tmpDataList = $newData.split('|')
                    foreach ($t in $tmpDataList) {
                        $tmpData = $t.ToString().Trim()
                        if ($tmpData -eq '') {
                            continue
                        }
                        $dup = $Global:assList  | Where-Object Type -EQ 'OU' | Select-Object Name
                        if (($dup -ne $null) -and ($dup.Name -ccontains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        }                   

                        $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'OU'; 'SID' = ''; 'Name' = $tmpData }) | Out-Null
                    }
                    
                    break
                }
                '8' {
                    $command = "Enter AAD/NDJ machine catalogs you want to add, separated by pipe.`r`n`    Example: <Machine catalog name 1>|<Machine catalog name 2>`r`n"
                    write-host $command -ForegroundColor Green
                    [string]$newData = (Read-Host  'Enter machine catalogs').Trim()
                    $tmpDataList = $newData.split('|')
                    foreach ($t in $tmpDataList) {
                        $tmpData = $t.ToString().Trim()
                        if ($tmpData -eq '') {
                            continue
                        }
                        $dup = $Global:assList  | Where-Object Type -EQ 'Machine catalog' | Select-Object Name
                        if (($dup -ne $null) -and ($dup.Name -ccontains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        }                   

                        $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'Machine catalog'; 'SID' = ''; 'Name' = $tmpData; 'Scope' = 'NDJ' }) | Out-Null
                    }
                    
                    break
                }
                '9' {
                    $command = "Enter AD machines you want to add, separated by pipe.`r`n`    - Example: <FQDN of machine 1>|<FQDN of machine 2>`r`n`    - To add all AD machines, enter AD*."
                    write-host $command -ForegroundColor Green
                    [string]$newData = (Read-Host  'Enter computers').Trim()
                
                    $tmpDataList = $newData.split('|')

                    foreach ($t in $tmpDataList) { 
                        $tmpData = $t.ToString().Trim()
                        if ($tmpData -eq '') {
                            continue
                        }
                        $dup = $Global:assList  | Where-Object {$_.Type -EQ 'AD machine'}| Select-Object Name 
                        if (($dup -ne $null) -and ($dup.Name -ccontains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        }
                        try {  
                            if($tmpData -EQ 'AD*')
                            {
                                $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'AD machine'; 'SID' = ''; 'Name' = $tmpData }) | Out-Null
                            }
                            else
                            {
                                $queryString = '(DNSHostName=' + $tmpData + ')'
                                $pcObj = Get-ADComputer -LDAPFilter $queryString
                                if ($pcObj -eq $null) {
                                    write-host 'Invalid computer name skipped:' $tmpData  -ForegroundColor Yellow
                                }
                                else {
                                    $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'AD machine'; 'SID' = $pcObj.SID; 'Name' = $tmpData }) | Out-Null
                                }
                            }

                                                 
                        }
                        catch {
                            write-host 'Invalid computer name skipped:' $tmpData  -ForegroundColor Yellow
                        } 

                    }
                    
                    break          
                }
                '10' {
                    $command = "Enter AAD/NDJ machines you want to add, separated by pipe.`r`n`    - Use the AAD/NDJ object selector in the WEM web console to collect AAD/NDJ machine names. For more information, see this WEM article, https://docs.citrix.com/en-us/workspace-environment-management/service/manage/configuration-sets/citrix-profile-management.html#app-access-control.`r`n`    - Wildcard * and ? are supported for NDJ machine names.`r`n`    - To add all AAD/NDJ machines, enter NDJ*."
                    write-host $command -ForegroundColor Green
                    [string]$newData = (Read-Host  'Enter computers').Trim()
                
                    $tmpDataList = $newData.split('|')

                    foreach ($t in $tmpDataList) { 
                        $tmpData = $t.ToString().Trim()
                        if ($tmpData -eq '') {
                            continue
                        }
                        $dup = $Global:assList  | Where-Object Type -EQ 'AAD/NDJ machine' | Select-Object Name 
                        if (($dup -ne $null) -and ($dup.Name -ccontains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        }
                        $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'AAD/NDJ machine'; 'SID' = ''; 'Name' = $tmpData; 'Scope' = 'NDJ' }) | Out-Null

                    }
                    
                    break          
                }
                '11' {
                    write-host 'Enter the names of the processes you want to add. Separate them with pipe. Example: powershell.exe|cmd.exe.' -ForegroundColor Green
                    [string]$newData = (Read-Host  'Enter processes').Trim()
                
                    $tmpDataList = $newData.split('|')

                    foreach ($t in $tmpDataList) {
                        $tmpData = $t.ToString().Trim()
                        if ($tmpData -eq '') {
                            continue
                        }
                        $dup = $Global:assList  | Where-Object Type -EQ 'process' | Select-Object Name
                        if (($dup -ne $null) -and ($dup.Name -ccontains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        }                    
                        $Global:assList.Add([PsCustomObject]@{'Index' = $Global:assList.Count + 1; 'Type' = 'Process'; 'SID' = ''; 'Name' = $tmpData }) | Out-Null
                    }
                    
                    break              
                }
                '12' {

                    write-host 'To delete items, enter their indexes. Separate them with commas.' -ForegroundColor Green
                    [string]$deleteData = (Read-Host  'Enter index').Trim()
                    if ($deleteData -eq '') {
                        write-host 'Invalid item:' $deleteData -ForegroundColor Yellow
                    }
                    else {
                        Remove-CTXMultpleItems -deleteData $deleteData -sourceList $Global:assList
                    }
                    break
                        
                }			
                '13' {
                    $Global:assList.Clear()
                    break
                }

            }
            Show-CTXCurrentAssignments
            if ($Global:assList.Count -eq 0) {
                $curCommand = "`r`nDo you want to add an assignment for this app?`r`n`r`n[1] Discard the changes you made to the app and continue adding rules for other apps`r`n[2] Save your changes and continue adding rules for other apps`r`n[3] Edit files and resgistries`r`n[4] Generate the rules for deployment to machines`r`n    If no assignments are configured, this app is not visible`r`n------------------------------------------------------------`r`n[5] Add users`r`n[6] Add user groups`r`n[7] Add OUs `r`n[8] Add AAD/NDJ machine catalogs`r`n    AAD: Azure AD; NDJ: Non-Domain-Joined`r`n[9] Add AD machines`r`n[10] Add AAD/NDJ machines`r`n[11] Add processes`r`n"                
                $choiceList = @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11')
            }
            else {
                $curCommand = "`r`nDo you want to add an assignment for this app? Or want to delete one? `r`n`r`n[1] Discard the changes you made to the app and continue adding rules for other apps`r`n[2] Save your changes and continue adding rules for other apps`r`n[3] Edit files and resgistries`r`n[4] Generate the rules for deployment to machines`r`n    If no assignments are configured, this app is not visible`r`n------------------------------------------------------------`r`n[5] Add users`r`n[6] Add user groups`r`n[7] Add OUs `r`n[8] Add AAD/NDJ machine catalogs`r`n    AAD: Azure AD; NDJ: Non-Domain-Joined`r`n[9] Add AD machines`r`n[10] Add AAD/NDJ machines`r`n[11] Add processes`r`n[12] Delete specific assignments`r`n[13] Delete all assignments`r`n"     
                $choiceList = @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13')  
            }
            write-host $curCommand -ForegroundColor Green
            $tmpchoice = (Read-Host  'Enter value').Trim()
        }
    }


}
function Test-CTXIsGuid {
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$StringGuid
    )
 
    $curObjectGuid = [System.Guid]::empty
    return [System.Guid]::TryParse($StringGuid, [System.Management.Automation.PSReference]$curObjectGuid) 
}

function Show-CTXWholeAppList {
    Write-Host "`r`n`r`nList of apps to manage:" -ForegroundColor green 
    if ($Global:appList.Count -gt 1) {
        #Sort-Object returns list in fixed size 
        $Global:tmpList = $Global:appList | Sort-Object -Property Status, Name
        $Global:appList.Clear()
        for ($i = 0; $i -lt $Global:tmpList.Count; $i++) {
            $Global:tmpList[$i].Index = $i + 1
            if (!($Global:tmpList[$i].Status.contains(' '))) {
                $Global:tmpList[$i].Status = $Global:tmpList[$i].Status + '  '
            }
            
        }
        $Global:appList.AddRange($Global:tmpList) | Out-Null
    }
    elseif ($Global:appList.Count -eq 1) {
        $Global:appList[0].Index = 1
        $Global:appList[0].Status = $Global:tmpList[0].Status
    }



    $appListTable = $Global:tmpList | Select-object Index, Status, Name | Format-Table -AutoSize | Out-String
    if (![string]::IsNullOrWhiteSpace($appListTable)) {
        #split the string on newlines and loop through each line
        $appListTable -split '\r?\n' | ForEach-Object {
            # do not process empty or whitespace-only strings
            if (!([string]::IsNullOrWhiteSpace($_))) {
                if (($_.ToString().Contains('Configured & applied  ') -eq $true) -and ($_.ToString().Contains('Not configured  ') -eq $false)) {
                    Write-Host $_ -ForegroundColor Green
                }

                elseif ($_.ToString().Contains('Configured  ') -eq $true) {
                    Write-Host $_ -ForegroundColor yellow
                }
                else {
                    Write-Host $_
                }
            }
        }
    }
}

function Get-CTXAppAccessControlRules {

    Set-CTXGlobalVars

    Get-CTXWindowsAppx
    Get-CTXInstallApps
    Get-CTXMergedApps


    # retrieve exsting rules from above reg, filter all hidden apps there. Also add rules from reg to $Global:existingRuleList	
    Get-CTXHiddenApps


    Show-CTXWholeAppList

    Write-Host "`r`nConfigured & applied: rules are configured for the app and applied to a GPO or the local registry.`r`n`r`nConfigured: rules are configured for the app but not applied to a GPO or the local registry. Warning: Rules will be lost if you exit the tool.`r`n`r`nNot configured: no rules are configured for the app. " -ForegroundColor green
   
    # get target app from admin, and collect info for it
    Get-CTXTargetApp
}

#show admin app paths
function Get-CTXAppRelatedInfo {
    for ($i = 0; $i -lt $Global:fileRegList.Count; $i++) {
        if (($Global:fileRegList[$i].Path -ne '') -and ($Global:fileRegList[$i].Path -ne $null)) {
            $Global:fileRegList[$i].Path = ( $Global:fileRegList[$i].Path).Replace($Global:seperatorReplacingSlash, '|')
            $Global:fileRegList[$i].Path = ( $Global:fileRegList[$i].Path).Replace('\REGISTRY\MACHINE', 'HKEY_LOCAL_MACHINE')
            if (( $Global:fileRegList[$i].Path).contains('\REGISTRY\USER\CU\')) {
                $Global:fileRegList[$i].Path = ( $Global:fileRegList[$i].Path).Replace('\REGISTRY\USER\CU', 'HKEY_CURRENT_USER')
            }
            elseif (( $Global:fileRegList[$i].Path).contains('\REGISTRY\USER\')) {
                $Global:fileRegList[$i].Path = ( $Global:fileRegList[$i].Path).Replace('\REGISTRY\USER', 'HKEY_USERS')
            }

            			
        }
        
        if (($Global:fileRegList[$i].Value -ne '') -and ($Global:fileRegList[$i].Value -ne $null)) {
            $Global:fileRegList[$i].Value = ( $Global:fileRegList[$i].Value).Replace($Global:seperatorReplacingSlash, '|')
        }
        
    }
    
    for ($i = 0; $i -lt $Global:assList.Count; $i++) {
        if (($Global:assList[$i].Name -ne '') -and ($Global:assList[$i].Name -ne $null)) {
            $Global:assList[$i].Name = ($Global:assList[$i].Name).Replace($Global:seperatorReplacingSlash, '|')
        }

                
    }
    write-host "`r`n`r`n************************************************************" -ForegroundColor Yellow
    write-host "`r`nApp details:" -ForegroundColor Yellow
    Show-CTXCurrentFileRegs
    Show-CTXCurrentAssignments
    write-host "`r`n************************************************************`r`n`r`n" -ForegroundColor Yellow
}
function Test-CTXAppPath {
    param(
        [string]$path
    )
    if (($path -eq $null) -or ($path -eq '')) {
        return $false
    }
    $charCount = ($path. ToCharArray() | Where-Object { $_ -eq ':' } | Measure-Object). Count
    $charCount2 = ($path. ToCharArray() | Where-Object { $_ -eq '%' } | Measure-Object). Count
    # check for invalid charcters,eg, /:'<>| 
    # allow wildcard * and ? 
    $invalidList = @('/', '"', '<', '>', '|')
    foreach ($invalidinput in $invalidList) {
        if ($path.Contains($invalidinput) -or ($charCount -gt 1) -or ($path.Length -lt 4)) {
            return $false
        }
        if (($path.Contains('%') -eq $false) -and ($path.Contains(':') -eq $false)) {
            return $false
        }
        if ( $path.Contains('\\') -eq $true) {
            return $false
        }
        #path with drive
        if ($charCount -eq 1) {
            if (($path[1] -eq ':') -and ((($path[0] -ige 'a') -and ($path[0] -le 'z')) -or (($path[0] -ige 'A') -and ($path[0] -le 'Z')))) {

            }
            else {
                return $false
            }
        }



    }

    return $true
}
function Test-CTXAppName {
    param(
        [string]$path
    )
    if (($path -eq $null) -or ($path -eq '')) {
        return $false
    }

    # check for invalid charcters,eg, /\:*?"<>|
    $invalidList = @('/', '\', ':', '*', '?', '"', '<', '>', '|')
    foreach ($invalidinput in $invalidList) {
        if ($path.Contains($invalidinput)) {
            return $false
        }

    }

    return $true
}
function Get-CTXUserInteractions {

    Get-CTXAppRelatedInfo
    $curQuestion = ''
    $curCommand = ''
    $choiceList = @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')
    if ($Global:fileRegList.Count -eq 0) {
        
        $curQuestion = "`r`nDo you want to add a file or registry entry for this app?`r`n"
        $curCommand = "`r`n[1] Discard the changes you made to the app and continue adding rules for other apps`r`n[2] Save your changes and continue adding rules for other apps`r`n[3] Generate the rules for deployment to machines`r`n    If no assignments are configured, this app is not visible`r`n------------------------------------------------------------`r`n[4] Add files `r`n[5] Add folders`r`n[6] Add registry keys`r`n[7] Add registry values`r`n" 
        $choiceList = @('0', '1', '2', '3', '4', '5', '6', '7')
    }
    else {
        $curQuestion = "`r`nDo you want to add a file or registry entry for this app? Or want to delete one?`r`n"
        $curCommand = "`r`n[1] Discard the changes you made to the app and continue adding rules for other apps`r`n[2] Save your changes and continue adding rules for other apps`r`n[3] Generate the rules for deployment to machines`r`n    If no assignments are configured, this app is not visible`r`n------------------------------------------------------------`r`n[4] Add files `r`n[5] Add folders`r`n[6] Add registry keys`r`n[7] Add registry values`r`n[8] Delete specific entries`r`n[9] Delete all entries`r`n------------------------------------------------------------`r`n[0] Go to the next step to manage assignments`r`n"       
    }
    write-host $curQuestion -ForegroundColor Green
    write-host $curCommand -ForegroundColor Green

    $tmpchoice = (Read-Host  'Enter value').Trim()
    
    while ( ((Test-CTXInteger -curInput $tmpchoice) -ne $true) -or ([int]$tmpchoice -ne 0)) {
        if (($tmpchoice -eq $null) -or ($tmpchoice -eq '') -or ((Test-CTXInteger -curInput $tmpchoice) -ne $true) -or (($choiceList -Contains $tmpchoice) -ne $true)) {     
            $max = $choiceList.Count - 1      
            write-host 'Invalid value. Supported values: 0 -'$max "`r`n" -ForegroundColor yellow
            $tmpchoice = (Read-Host  'Enter value').Trim()
            continue
        }
        else {
 
            switch ([int]$tmpchoice) {
                '1' {
                    Get-CTXAppAccessControlRules
                    return
                }
                '2' {
                    #generate raw rules, add to existin $Global:existingRuleList
                    if (!($Global:RulesInMemoryAppList -contains $Global:targetApp)) {
                        $Global:RulesInMemoryAppList.Add($Global:targetApp) | Out-Null
                    }            
                    Format-CTXAppAccessControlRules -saveChangesAndReturnToBegining $true
                    Get-CTXAppAccessControlRules
                    return
                }
                '3' {
                    #go to generate rules
                    if (!($Global:RulesInMemoryAppList -contains $Global:targetApp)) {
                        $Global:RulesInMemoryAppList.Add($Global:targetApp) | Out-Null
                    } 
                    Format-CTXAppAccessControlRules -saveChangesAndReturnToBegining $false
                    return
                }
                '4' {
    
                    write-host 'Enter the paths of the files you want to add. Separate them with pipe. Example: c:\users\public\a.txt|c:\users\public\b.log. Wildcard * and ? are supported.'  -ForegroundColor Green    
                    [string]$newData = (Read-Host  'Enter paths').Trim()
                    $tmpDataList = $newData.split('|')
                    foreach ($t in $tmpDataList) {
                        $tmpData = $t.ToString().Trim().TrimEnd('\')
                        if ($tmpData -eq '') {
                            continue
                        }
                        if (Check-CTXImportantFileFolderPath -testPath $tmpData) {
                        }
                        elseif (Test-CTXAppPath -path $tmpData) {
                            $dup = $Global:fileRegList  | Where-Object Type -EQ 'File' | Select-Object Path
                            if (($dup -ne $null) -and ($dup.Path -contains $tmpData)) {
                                write-host 'Duplicated items skipped:' $tmpData -ForegroundColor yellow
                                continue
                            } 							
                            $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'File'; 'Path' = $tmpData; 'Value' = '' }) | Out-NUll
                        }

                        else {
                            write-host 'Invalid path:' $tmpData -ForegroundColor Yellow
                        }                       
                    }

                    break
                      
                }
                '5' {
    
                    write-host 'Enter the paths of the folders you want to add. Separate them with pipe. Example: c:\users\public\folder1|c:\users\public\folder2. Wildcard * and ? are supported.'  -ForegroundColor Green    
                    [string]$newData = (Read-Host  'Enter paths').Trim()
                    $tmpDataList = $newData.split('|')
                    foreach ($t in $tmpDataList) {
                        $tmpData = $t.ToString().Trim().TrimEnd('\')
                        if ($tmpData -eq '') {
                            continue
                        }
                        if (Check-CTXImportantFileFolderPath -testPath $tmpData) {
                        }
                        elseif (Test-CTXAppPath -path $tmpData) {
                            $dup = $Global:fileRegList  | Where-Object Type -EQ 'Folder' | Select-Object Path
                            if (($dup -ne $null) -and ($dup.Path -contains $tmpData)) {
                                write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                                continue
                            } 							
                            $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Folder'; 'Path' = $tmpData; 'Value' = '' }) | Out-NUll
                        }
                        else {
                            write-host 'Invalid path:' $tmpData -ForegroundColor Yellow
                        }                       
                    }

                    break
                      
                }				
                '6' {
                    write-host 'Enter the paths of the registry keys you want to add. Separate them with pipe. Example: HKLM:\software\key1|HKCU:\software\key2.' -ForegroundColor Green      
                    [string]$newData = (Read-Host  'Enter paths').Trim()
                    $tmpDataList = $newData.split('|')
                    foreach ($t in $tmpDataList) {
                        $tmpData = $t.ToString().Trim().TrimEnd('\')
                        if ($tmpData -eq '') {
                            continue
                        }
                        $dup = $Global:fileRegList  | Where-Object Type -EQ 'Registry key' | Select-Object Path
                        if (Check-CTXImportantRegPath -testPath $tmpData) {
                            continue
                        }
                        elseif (($dup -ne $null) -and ($dup.Path -contains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        } 
                        if (($tmpData.StartsWith('HKLM:\') -eq $false) -and ($tmpData.StartsWith('HKCU:\') -eq $false) -and ($tmpData.StartsWith('HKEY_LOCAL_MACHINE\') -eq $false) -and ($tmpData.StartsWith('HKEY_CURRENT_USER\') -eq $false) -and ($tmpData.StartsWith('HKEY_USERS\') -eq $false) -and ($tmpData.StartsWith('HKU:\') -eq $false)) {
                            write-host 'Invalid path:' $tmpData -ForegroundColor Yellow
                            continue
                        }					
                        $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry key'; 'Path' = $tmpData; 'Value' = '' }) | Out-NUll
                    }

                    break
                }
                '7' {
                    write-host 'Enter the paths of the registry values you want to add. Separate them with pipe.Example: HKLM:\software\key1\val|HKCU:\software\key2\val.'  -ForegroundColor Green     
                    [string]$newData = (Read-Host  'Enter paths').Trim()
                    $tmpDataList = $newData.split('|')
                    foreach ($t in $tmpDataList) {   
                        $tmpData = $t.ToString().Trim().TrimEnd('\')   
                        if ($tmpData -eq '') {
                            continue
                        }                                     
                        $val = $tmpData.Split('\')[-1]
                        $dup = $Global:fileRegList  | Where-Object Type -EQ 'Registry value' | Select-Object Path
                        if (Check-CTXImportantRegPath -testPath $tmpData) {
                            continue
                        }
                        elseif (($dup -ne $null) -and ($dup.Path -contains $tmpData)) {
                            write-host 'Duplicated items skipped:'$tmpData -ForegroundColor yellow
                            continue
                        } 
                        if (($tmpData.StartsWith('HKLM:\') -eq $false) -and ($tmpData.StartsWith('HKCU:\') -eq $false) -and ($tmpData.StartsWith('HKEY_LOCAL_MACHINE\') -eq $false) -and ($tmpData.StartsWith('HKEY_CURRENT_USER\') -eq $false) -and ($tmpData.StartsWith('HKEY_USERS\') -eq $false) -and ($tmpData.StartsWith('HKU:\') -eq $false)) {
                            write-host 'Invalid path:' $tmpData -ForegroundColor Yellow
                            continue
                        }                        						
                        $Global:fileRegList.Add([PsCustomObject]@{'Index' = $Global:fileRegList.Count + 1; 'Type' = 'Registry value'; 'Path' = $tmpData; 'Value' = $val.Trim().TrimEnd('\') }) | Out-NUll
                    }  
                    break            
                }
                '8' {
                    write-host 'To delete entries, enter their indexes. Separate them with commas.'  -ForegroundColor Green
                    [string]$deleteData = (Read-Host  'Enter index').Trim()
                    if ($deleteData -eq '') {
                        write-host 'Invalid item:' $deleteData -ForegroundColor Yellow
                        
                    }
                    else {
                        Remove-CTXMultpleItems -deleteData $deleteData -sourceList $Global:fileRegList
                    }
                    
                    break             
                }			
                '9' {
                    $Global:fileRegList.Clear()
                    break
                }

            }
            Show-CTXCurrentFileRegs       
            if ($Global:fileRegList.Count -eq 0) {
                $curQuestion = "`r`nDo you want to add a file or registry entry for this app?`r`n"
                $curCommand = "`r`n[1] Discard the changes you made to the app and continue adding rules for other apps`r`n[2] Save your changes and continue adding rules for other apps`r`n[3] Generate the rules for deployment to machines`r`n    If no assignments are configured, this app is not visible`r`n------------------------------------------------------------`r`n[4] Add files `r`n[5] Add folders`r`n[6] Add registry keys`r`n[7] Add registry values`r`n" 
                $choiceList = @('0', '1', '2', '3', '4', '5', '6', '7')
            }
            else {
                $curQuestion = "`r`nDo you want to add a file or registry entry for this app? Or want to delete one?`r`n"
                $curCommand = "`r`n[1] Discard the changes you made to the app and continue adding rules for other apps`r`n[2] Save your changes and continue adding rules for other apps`r`n[3] Generate the rules for deployment to machines`r`n    If no assignments are configured, this app is not visible`r`n------------------------------------------------------------`r`n[4] Add files `r`n[5] Add folders`r`n[6] Add registry keys`r`n[7] Add registry values`r`n[8] Delete specific entries`r`n[9] Delete all entries`r`n------------------------------------------------------------`r`n[0] Go to the next step to manage assignments`r`n"       
                $choiceList = @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')
    
            }
            write-host $curQuestion -ForegroundColor Green
            write-host $curCommand -ForegroundColor Green
            $tmpchoice = (Read-Host  'Enter value').Trim()
        }
    }


    Get-CTXAssignments

}

#region finally generated formatted rules
function Get-CTXRulesForApps {
    #eg, file rule 0|0|c:\users\public\aa.exe|*|User@CTXASSSEP@S-1-5-21-674278408-26188528-2146851469-1334@CTXASSSEP@fuser11|*|*|*
    #$Global:assList//ID Type SID Name
    #for group, user,computer,process, their name could not contains '|'
    #for reg key/value in $Global:fileRegList and for ou name in assignments, they could contain '|', replace with @CTXBARSEP@
    $Global:rulesList.Clear()	
    if ($Global:fileRegList.Count -eq 0) {
        return
    }

    $assFormated = '' 
    $userList = ''
    $processList = ''
    $ouList = ''
    $computerList = ''
    #in $Global:assList, scope field stores 'NDJ' to show this is for NDJ assignment
    #in raw rule data structure, above info are stored in its sid field for machine catalog and computer, for user/groups, sid field stores OID which itself shows it is a NDJ assignment

    $bIsADAllComputers = $false
    $bIsNDJAllComputers = $false

    $isADAll = $Global:assList | Where-Object {(($_.Type -eq 'AD machine') -and ($_.Name -eq 'AD*'))}
    $isNDJAll = $Global:assList | Where-Object {(($_.Type -eq 'AAD/NDJ machine') -and ($_.Name -eq 'NDJ*'))}
    if($isADAll -and $isNDJAll)
    {
        $bIsADAllComputers =  $true
        $bIsNDJAllComputers =  $true
    }
    elseif($isADAll)
    {
        $bIsADAllComputers =  $true
        $t = 'computer@CTXASSSEP@' + 'AD*' + '@CTXASSSEP@'             
        $computerList += $t
        $computerList += ':'  
    }
    
    elseif($isNDJAll)
    {
        $bIsNDJAllComputers =  $true
        $t = 'computer@CTXASSSEP@' + 'NDJ*' + '@CTXASSSEP@'           
        $computerList += $t
        $computerList += ':' 
    }

    foreach ($tmp in $Global:assList) {
        
        switch ($tmp.Type) {
            'User' {
                $userList += 'User@CTXASSSEP@' + $tmp.SID + '@CTXASSSEP@' + $tmp.Name         
                $userList += ':'
            
            }
            'Group' {

                $userList += 'Group@CTXASSSEP@' + $tmp.SID + '@CTXASSSEP@' + $tmp.Name
            
                $userList += ':'
            
            }           
            'Process' {
                $t = 'Process@CTXASSSEP@' + $tmp.SID + '@CTXASSSEP@' + $tmp.Name
            
                $processList += $t
            
                $processList += ':'           
            }
            'OU' {

                    $rep = ($tmp.Name).Replace('|', $Global:seperatorReplacingSlash)
                    $t = 'OU@CTXASSSEP@' + $tmp.SID + '@CTXASSSEP@' + $rep          
                    $ouList += $t
                    $ouList += ':'          
            
            }
            'Machine catalog'{
                    $rep = ($tmp.Name).Replace('|', $Global:seperatorReplacingSlash)
                    $t = 'OU@CTXASSSEP@' + $tmp.Scope + '@CTXASSSEP@' + $rep           
                    $ouList += $t
                    $ouList += ':'         
         
            
            }

            'AD machine' {


                if($bIsADAllComputers -ne $true)
                {
                    $t = 'computer@CTXASSSEP@' + $tmp.SID + '@CTXASSSEP@' + $tmp.Name          
                    $computerList += $t
                    $computerList += ':'  
                }        
            
            }
             'AAD/NDJ machine' {

                if($bIsNDJAllComputers -ne $true)
                {
                    $t = 'computer@CTXASSSEP@' + $tmp.Scope + '@CTXASSSEP@' + $tmp.Name           
                    $computerList += $t
                    $computerList += ':' 
                } 
          
                        
            }           
        }

    }
    
    $userList = $userList.Trim(':')
    $processList = $processList.Trim(':')
    $ouList = $ouList.Trim(':')
    $computerList = $computerList.Trim(':')


    if ($userList -eq '') {
        $assFormated += '*'
    }
    else {
        $assFormated += $userList
    }


    $assFormated += '|'

    if ($processList -eq '') {
        $assFormated += '*'

    }
    else {
        $assFormated += $processList
    }

    $assFormated += '|'

    if ($ouList -eq '') {
        $assFormated += '*'

    }
    else {
        $assFormated += $ouList
    }
    $assFormated += '|'

    if ($computerList -eq '') {
        $assFormated += '*'

    }
    else {
        $assFormated += $computerList
    }


    #$Global:fileRegList //ID Type Path Value
    #replace '|' with $Global:seperatorReplacingSlash
    foreach ($cur in $Global:fileRegList) {
        if ($cur.Type -eq 'File') {
            $currule = '0|0|' + $cur.Path + '|*|' + $assFormated + '|' + $Global:targetApp
            [void]$Global:rulesList.Add($currule)           
        }
        elseif ($cur.Type -eq 'Folder') {
            $currule = '0|3|' + $cur.Path.TrimEnd('\') + '|*|' + $assFormated + '|' + $Global:targetApp
            [void]$Global:rulesList.Add($currule)           
        }		
        elseif ($cur.Type -eq 'Registry key') {
            $rep = $cur.Path.TrimEnd('\')
            $rep = $rep.Replace('|', $Global:seperatorReplacingSlash)
            $rep = $rep.Replace('HKEY_LOCAL_MACHINE', '\REGISTRY\MACHINE')
            $rep = $rep.Replace('HKEY_CURRENT_USER', '\REGISTRY\USER\CU')
            $rep = $rep.Replace('HKEY_USERS', '\REGISTRY\USER')			
            $rep = $rep.Replace('HKLM:', '\REGISTRY\MACHINE')
            $rep = $rep.Replace('HKCU:', '\REGISTRY\USER\CU')			
            $rep = $rep.Replace('HKU:', '\REGISTRY\USER')						
            $currule = '0|1|' + $rep + '|*|' + $assFormated + '|' + $Global:targetApp  
            [void]$Global:rulesList.Add($currule)
        }
        elseif ($cur.Type -eq 'Registry value') {
            $rep = $cur.Path.TrimEnd('\')
            $rep = $rep.Replace('|', $Global:seperatorReplacingSlash)
            $rep = $rep.Replace('HKEY_LOCAL_MACHINE', '\REGISTRY\MACHINE')
            $rep = $rep.Replace('HKEY_CURRENT_USER', '\REGISTRY\USER\CU')
            $rep = $rep.Replace('HKEY_USERS', '\REGISTRY\USER')			
            $rep = $rep.Replace('HKLM:', '\REGISTRY\MACHINE')
            $rep = $rep.Replace('HKCU:', '\REGISTRY\USER\CU')
            $rep = $rep.Replace('HKU:', '\REGISTRY\USER')
            $repval = $cur.Value.TrimEnd('\')		
            $repval = $repval.Replace('|', $Global:seperatorReplacingSlash)
            $currule = '0|2|' + ($rep.Substring(0, $rep.Length - $repval.Length)).Trim().TrimEnd('\') + '|' + $repval + '|' + $assFormated + '|' + $Global:targetApp   
            [void]$Global:rulesList.Add($currule)
        }
    }
}
function Format-CTXAppAccessControlRules {
    param(
        [Parameter(Mandatory = $true)][bool]$saveChangesAndReturnToBegining,
        [Parameter(Mandatory = $false)][bool]$deleteAll = $false
    )
    if (!$deleteAll) {
        # generate rules fro current app
        Get-CTXRulesForApps



    
        #delete app related rules from $Global:existingRuleList
        for ($i = 0; $i -lt $Global:existingRuleList.Count; $i++) {
            if ($Global:existingRuleList[$i].Split('|')[-1] -eq $Global:targetApp) {
                $Global:existingRuleList.RemoveAt($i)
                $i--
            }
        }
    }


    #in normal workflow,the last step to generate raw rules,
    if ($saveChangesAndReturnToBegining -eq $false) {
        if ($deleteAll) {
            $Global:existingRuleList.Clear()
            $Global:RulesInMemoryAppList.Clear()
        }

        $tmpList = New-Object -TypeName 'System.Collections.ArrayList' 
        [void]$tmpList.AddRange($Global:existingRuleList)
        if ($Global:targetApp -ne '') {
        
            [void]$tmpList.AddRange($Global:rulesList)
        }
        else {
            #when admin just want to see existing rules for all apps, no current app specified, so ignore $Global:rulesList
        }
        $tmp = $tmpList | select -Unique 
        $tmpList.Clear()
        if ($tmp.Count -eq 1) {
            [void]$tmpList.Add($tmp)
        }
        elseif ($tmp.Count -gt 1) {
            [void]$tmpList.AddRange($tmp)
        }

        $Global:rulesReadyForRegGPO = ''
        foreach ($i in $tmpList) {
            $Global:rulesReadyForRegGPO += $i
            $Global:rulesReadyForRegGPO += "`n"
        } 
        $Global:existingRuleList.Clear()
        [void]$Global:existingRuleList.AddRange($tmpList) 
        Get-CTXAdminGPO
        write-host "`r`n[Y] Add more rules`r`n[N] Exit`r`n" -ForegroundColor Green
        $continueGeneratingRules = (Read-Host  'Enter input').Trim() 
        while (($continueGeneratingRules -ne 'Y') -and ($continueGeneratingRules -ne 'N')) {
            write-host 'Invalid input:'$continueGeneratingRules -ForegroundColor yellow
            $continueGeneratingRules = (Read-Host  'Enter input').Trim() 
        }                                         
        if ($continueGeneratingRules -eq 'Y') {
            Get-CTXAppAccessControlRules
        }
        else {
            Exit
        }

    }
    else {
        #return when modifying file/reg list and assignments and admin choose to save
        #add newly app related rules into $Global:existingRuleList
        for ($i = 0; $i -lt $Global:rulesList.Count; $i++) {
            if (($Global:existingRuleList -Contains $Global:rulesList[$i]) -eq $false) {
                [void]$Global:existingRuleList.Add($Global:rulesList[$i])
            }
        } 
        if (!($Global:RulesInMemoryAppList -contains $Global:targetApp)) {
            [void]$Global:RulesInMemoryAppList.Add($Global:targetApp)
        }
                
    }
}
function Check-CTXImportantRegPath {
    param(
        [Parameter(Mandatory = $true)][string]$testPath

    )
    $upperTestPath = $testPath.TrimEnd('\') + '\'
    $upperTestPath = $upperTestPath.ToUpper()
    foreach ($var in $Global:importantRegPath) {
        if ($var.contains($upperTestPath)) {
            write-host 'Protected path:' $testPath' skipped' -ForegroundColor Yellow
            return $true
        }
    }
    return $false
}
function Check-CTXImportantFileFolderPath {
    param(
        [Parameter(Mandatory = $true)][string]$testPath

    )
    $lowerTestPath = $testPath.TrimEnd('\') + '\'
    $lowerTestPath = $lowerTestPath.ToLower()
    foreach ($var in $Global:importantFileFolderPath) {
        if ($var.contains($lowerTestPath)) {
            write-host 'Protected path:' $testPath' skipped' -ForegroundColor Yellow
            return $true
        }
    }


    foreach ($var in $Global:importantAppPath) {
        if ($lowerTestPath -like $var) {
            write-host 'Protected path:' $testPath' skipped' -ForegroundColor Yellow
            return $true
        }
    }

    return $false
}
function Get-CTXAdminGPO {
    $choiceList = @('1', '2', '3')
    $forceApplySuc = $false
    write-host "`r`n[1] Apply rules to a GPO`r`n[2] Apply rules to a local registry`r`n[3] Save rules for future use" -ForegroundColor Green
    $apply = (Read-Host  'Enter value').Trim()

    while (((Test-CTXInteger -curInput $apply) -ne $true) -or (($choiceList -Contains $apply) -ne $true)) {
        write-host 'Invalid value. Enter a value of 1 -'$choiceList.Count "`r`n" -ForegroundColor yellow
        write-host "`r`nTo apply rules to GPO, enter 1.`r`nTo apply rules to local registry, enter 2.`r`nSave rules for future use, enter 3." -ForegroundColor Green
        $apply = (Read-Host  'Enter value').Trim()
    }





    if ($apply -eq '1') {

        #list exisiting GPOs
        write-host "`r`nIt will take a moment to query current domain. Please wait…" -ForegroundColor Yellow
        $tmp = (systeminfo | findstr /B /C:'Domain').split(':')
        #eg, ctxxa.local or workgroup
        $curDomainName = $tmp[1].TrimStart()
        
        try {
            write-host "`r`nIt will take a moment to query Group Policies in current domain. Please wait…" -ForegroundColor Yellow
            $allGposInDomain = (Get-GPO -All -Domain $curDomainName).DisplayName 

            $allGPOCnt = 0
            [System.Collections.ArrayList]$allGposInDomainList = @()
            foreach ($curGPO in $allGposInDomain) {
                $val = [PsCustomObject]@{'Index' = ++$allGPOCnt; 'GPO' = $curGPO }
                $allGposInDomainList.Add($val) | Out-NUll
            }
            
            $allGposInDomainList | Format-Table
            
            while ($True) {
                write-host "`r`nEnter the index of your GPO. To skip this step and continue, enter 0." -ForegroundColor Green
                $curID = (Read-Host  'Enter index').Trim()
                try {
                    if (Test-CTXInteger -curInput $curID) {
                        if ([INT]$curID -eq 0) {
                            Get-CTXAdminGPO
                            write-host "`r`n[Y] Add more rules`r`n[N] Exit`r`n" -ForegroundColor Green
                            $continueGeneratingRules = (Read-Host  'Enter input').Trim() 
                            while (($continueGeneratingRules -ne 'Y') -and ($continueGeneratingRules -ne 'N')) {
                                write-host 'Invalid input:'$continueGeneratingRules -ForegroundColor yellow
                                $continueGeneratingRules = (Read-Host  'Enter input').Trim() 
                            }                                         
                            if ($continueGeneratingRules -eq 'Y') {
                                Get-CTXAppAccessControlRules
                            }
                            else {
                                Exit
                            }
                        }
                        elseif (($allGposInDomainList | Select-Object Index).Index -Contains [INT]$curID) {              
                            $Global:targetGPO = Get-GPO -name $allGposInDomainList[[INT]$curID - 1].GPO
                            break
                        }
                        else {           
                            Write-Host 'Invalid index.' -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Host 'Invalid index.' -ForegroundColor Yellow
                    }				
                }
                catch {
                    Write-Host 'Invalid index.'  -ForegroundColor Yellow
                }


            }

               

            Set-GPRegistryValue  -Key 'HKLM\SOFTWARE\Policies\Citrix\UserProfileManager' -ValueName 'AppAccessControlRules' -Type String -Value $Global:rulesReadyForRegGPO -Guid $Global:targetGPO.Id  | Out-Null                       

            write-host  "`r`nIt will take a moment for Windows Group Policy Management to update the policy to the local machine. Please wait…" -ForegroundColor Yellow
            gpupdate /force

            $forceApplySuc = $true
            write-host "`r`nRules applied successfully."
            $Global:RulesInMemoryAppList.Clear()
        }
        catch {
            write-host 'Unable to find or update the GPO. Veirfy that the domain where the current machine resides is reachable and then try again.' -ForegroundColor Yellow
        
        } 
        if ($forceApplySuc -ne $true) {
            if ($emptyRule) {
                write-host 'An error occurred while applying the rules. Your changes have made the rules empty. To apply your changes, set the Profile Management group policy 'App access control' as empty. Or, you can locate the registry key HKLM\SOFTWARE\Policies\Citrix\UserProfileManager\UserConfigDriverActionRules, and set the registry value AppAccessControlRules as empty.' -ForegroundColor Yellow
            }
            else {
                write-host 'An error occurred while applying the rules. To apply your changes, set the Profile Management group policy 'App access control' with the string below. Or, you can locate the registry key HKLM\SOFTWARE\Policies\Citrix\UserProfileManager\UserConfigDriverActionRules, and set the registry value AppAccessControlRules to the string below.' -ForegroundColor Yellow
                $Global:rulesReadyForRegGPO
            }

        }

    }
    elseif ($apply -eq '2') {
        $serviceRestartStatus = $false
        try {
            $tmpString = ''
            $upmRegKeyPath = 'HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager'

            if ((Test-Path  $upmRegKeyPath) -eq $false) {
                New-Item -Path $upmRegKeyPath -Force | Out-Null
            }    
            if ((Get-Item -Path $upmRegKeyPath).GetValue('AppAccessControlRules') -ne $null) {
                Set-ItemProperty -Path $upmRegKeyPath -Name 'AppAccessControlRules' -Value $Global:rulesReadyForRegGPO
            }
            else {
                New-ItemProperty -Path $upmRegKeyPath -Name 'AppAccessControlRules' -Value $Global:rulesReadyForRegGPO -Force
            }

            write-host 'Rules applied successfully.'
            $Global:RulesInMemoryAppList.Clear()

            $serviceRestartStatus = $true

            Restart-Service -Name 'Citrix profile management' -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null


        }
        catch {
            if (!$serviceRestartStatus) {
                write-host 'An error occurred while applying the rules.' -ForegroundColor Yellow
            }
            else {
                write-host 'An error occurred while restarting user profile manager service, restart manually.' -ForegroundColor Yellow
            }
        }
    }
    else {
        if ($emptyRule) {
            $tmpString = "Your changes have made the rules empty. To apply your changes, set the Profile Management group policy 'App access control' as empty. Or, you can locate the registry key HKLM\SOFTWARE\Policies\Citrix\UserProfileManager\UserConfigDriverActionRules, and set the registry value AppAccessControlRules as empty."
            write-host $tmpString -ForegroundColor Yellow
        }
        else {
            Write-Host "Rules you have configured are saved at c:\users\<user name>\documents\hiding-rules-<date-time>.txt. To apply them using GPOs, copy the file's content and paste it to the Profile Management policy 'App access control'." -ForegroundColor Yellow
            $Global:rulesReadyForRegGPO

            $dateTime = Get-Date -Format "yyyyMMdd-HHmmss"
            $documentsPath = [Environment]::GetFolderPath('MyDocuments')
            $filePath = $documentsPath + '\' + "hiding-rules-$dateTime.txt"
            # Create a new file with the generated name
            New-Item -ItemType File -Path $filePath | Out-NUll
            Set-Content -Path $filePath -Value $Global:rulesReadyForRegGPO -NoNewline | Out-NUll
        }

    }

}


#endregion



if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    write-host ''Run as administrator' is required for this tool. Exiting ...' -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Exit    
}

#region define vars
$Global:importModulesCnt = 0
$Global:targetGPO = ''
$Global:targetApp = ''
$Global:rulesReadyForRegGPO = ''
#existing raw rule data that exists
$Global:existingRuleList = New-Object -TypeName 'System.Collections.ArrayList'
#rurrent app's raw rule data
$Global:rulesList = New-Object -TypeName 'System.Collections.ArrayList'

#app info got by uninstall key: Name, InstallDir
$Global:installedAppsFoundInUnInstallKey = @{}

$Global:existingHiddenAppNameList = New-Object -TypeName 'System.Collections.ArrayList'

#whole apps records
$Global:appList = New-Object -TypeName 'System.Collections.ArrayList'
$Global:manuallyAppList = New-Object -TypeName 'System.Collections.ArrayList'
$Global:RulesInMemoryAppList = New-Object -TypeName 'System.Collections.ArrayList'
 
$Global:assList = New-Object -TypeName 'System.Collections.ArrayList'
$Global:fileRegList = New-Object -TypeName 'System.Collections.ArrayList'
$Global:userList = New-Object -TypeName 'System.Collections.ArrayList'
$Global:ouList = New-Object -TypeName 'System.Collections.ArrayList'
$Global:computerList = New-Object -TypeName 'System.Collections.ArrayList'
$Global:processList = New-Object -TypeName 'System.Collections.ArrayList'

$Global:ShotcutList = New-Object -TypeName 'System.Collections.ArrayList'

$Global:seperatorReplacingSlash = '@CTXBARSEP@'    
# a list of known apps of winows which is not our targets
$Global:knownIgnoredAppsList = @('AddressBook', 'Connection Manager', 'DirectDrawEx', 'DXM_Runtime', 'Fontcore', 'IE40', 'IE4Data', 'IE5BAKEX', 'IEData', 'MPlayer2', 'SchedulingAgent', 'WIC'
    , 'MobileOptionPack', 'Citrix Profile Management', 'Citrix Workspace Environment Management Agent')

$Global:unisntallKeySearchScope = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)
$Global:ServiceORDriverInfoSearchScope = @('HKLM:\system\currentcontrolset\Services')

#the paths below, and their parent path all protected
$Global:importantRegPath = @(
    #upm
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Citrix\UserProfileManager\',
    'HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager\',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UserProfileManager\',
    'HKLM:\SOFTWARE\Citrix\UserProfileManager\',
    #wem
    'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Norskale\',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\WEM\',
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\',
    'HKLM:\SOFTWARE\Policies\Norskale\',
    'HKLM:\SOFTWARE\Citrix\WEM\',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Norskale\',
    #VDA
    'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\VirtualDesktopAgent\',
    'HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent\',
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Citrix Virtual Desktop Agent\'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Citrix Virtual Desktop Agent\'
    #others
    'HKCU:\',
    'HKEY_CURRENT_USER\',
    'HKU:\',
    'HKEY_USERS\'

)
#the paths below, and their parent paths all protected, ignore the corner case that c is not system drive, anyway, in UPM side, we protect [driver]:\windows\system32 and their parent paths [driver]:,[driver]:\windows
$Global:importantFileFolderPath = @(
    'c:\windows\system32\',
    '%windir%\system32\'
)
#just do the match, ignore corner case that user could hide the higher level of path below
$Global:importantAppPath = @(
    '*\Citrix\User Profile Manager\*',
    '*\Citrix\Workspace Environment Management Agent\*',
    '*\Citrix\XenDesktopVdaSetup\*'
)


#endregion

Write-Host "`r`nCitrix Profile Management App Access Control Config Tool`r`n" -ForegroundColor green
Write-Host "`r`nFor a better user experience, we recommend using the Rule Generator for App Access Control tool (GUI-based) to create, manage, and generate app access control rules. Get the tool in WEM Tool Hub, which is available for download in Citrix Cloud > WEM service > Utilities.`r`n" -ForegroundColor green
# prerequisite
$importRes = Import-CTXModules
if (!$importRes) {
    Import-CTXModules | Out-Null
}

#calling the main function
Get-CTXAppAccessControlRules 


# SIG # Begin signature block
# MIInHwYJKoZIhvcNAQcCoIInEDCCJwwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUy7xYukP8MQYx0/L/H1jIWD7Q
# J76ggiDPMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxM
# n17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2
# MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQk
# B+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtD
# mpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUu
# oZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4Us
# SKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHc
# reQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nB
# k+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD
# 1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshh
# WJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB
# 8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4
# GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZ
# MIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMw
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4
# SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ
# /Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZ
# gVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBg
# XPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0C
# FB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDw
# zMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8u
# pHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA
# 443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5uco
# P6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZ
# DW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurI
# r6n+lB3nYxs6hlZ4TjCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVowDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5NTla
# MEYxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMbRGln
# aUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAz+ylJjrGqfJru43BDZrboegUhXQzGias0BxVHh42bbySVQxh9J0J
# dz0Vlggva2Sk/QaDFteRkjgcMQKW+3KxlzpVrzPsYYrppijbkGNcvYlT4DotjIdC
# riak5Lt4eLl6FuFWxsC6ZFO7KhbnUEi7iGkMiMbxvuAvfTuxylONQIMe58tySSge
# TIAehVbnhe3yYbyqOgd99qtu5Wbd4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+JvK0
# jM1MuWbIu6pQOA3ljJRdGVq/9XtAbm8WqJqclUeGhXk+DF5mjBoKJL6cqtKctvdP
# bnjEKD+jHA9QBje6CNk1prUe2nhYHTno+EyREJZ+TeHdwq2lfvgtGx/sK0YYoxn2
# Off1wU9xLokDEaJLu5i/+k/kezbvBkTkVf826uV8MefzwlLE5hZ7Wn6lJXPbwGqZ
# IS1j5Vn1TS+QHye30qsU5Thmh1EIa/tTQznQZPpWz+D0CuYUbWR4u5j9lMNzIfMv
# wi4g14Gs0/EH1OG92V1LbjGUKYvmQaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqmgQ8J
# JVPxvzvpqwcOagc5YhnJ1oV/E9mNec9ixezhe7nMZxMHmsF47caIyLBuMnnHC1mD
# jcbu9Sx8e47LZInxscS451NeX1XSfRkpWQNO+l3qRXMchH7XzuLUOncCAwEAAaOC
# AYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAf
# BgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUYore0GH8
# jzEU7ZcLzT0qlBTfUpwwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFt
# cGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8deNP
# 1oUj8fz5lTmbJeb3coqYw3fUZPwV+zbCSVEseIhjVQlGOQD8adTKmyn7oz/AyQCb
# Ex2wmIncePLNfIXNU52vYuJhZqMUKkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ5ojO
# fRu4aqKbwVNgCeijuJ3XrR8cuOyYQfD2DoD75P/fnRCn6wC6X0qPGjpStOq/CUkV
# NTZZmg9U0rIbf35eCa12VIp0bcrSBWcrduv/mLImlTgZiEQU5QpZomvnIj5EIdI/
# HMCb7XxIstiSDJFPPGaUr10CU+ue4p7k0x+GAWScAMLpWnR1DT3heYi/HAGXyRkj
# gNc2Wl+WFrFjDMZGQDvOXTXUWT5Dmhiuw8nLw/ubE19qtcfg8wXDWd8nYiveQclT
# uf80EGf2JjKYe/5cQpSBlIKdrAqLxksVStOYkEVgM4DgI974A6T2RUflzrgDQkfo
# QTZxd639ouiXdE4u2h4djFrIHprVwvDGIqhPm73YHJpRxC+a9l+nJ5e6li6FV8Bg
# 53hWf2rvwpWaSxECyIKcyRoFfLpxtU56mWz06J7UWpjIn7+NuxhcQ/XQKujiYu54
# BNu90ftbCqhwfvCXhHjjCANdRyxjqCU4lwHSPzra5eX25pvcfizM/xdMTQCi2NYB
# DriL7ubgclWJLCcZYfZ3AYwwggcQMIIE+KADAgECAhAFkuT1RdFjPCIhHKIFdBy0
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjIwOTEzMDAwMDAwWhcNMjQw
# OTEyMjM1OTU5WjCBlDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0Zsb3JpZGExGDAW
# BgNVBAcTD0ZvcnQgTGF1ZGVyZGFsZTEdMBsGA1UEChMUQ2l0cml4IFN5c3RlbXMs
# IEluYy4xGzAZBgNVBAsTEkNpdHJpeCBTSEEyNTYgMjAyMjEdMBsGA1UEAxMUQ2l0
# cml4IFN5c3RlbXMsIEluYy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
# gQDUKxwyv1TU9wdkDjlEUp26oUC7rFJqXo9V+YnVqUxEKgR3Qe54mPLIQE3PC/N/
# 9lCFzeYRS2gvJhQJmiFEUaK8RpizZSowYETYyv4HqwDn8u+Mp908uTTWCvsavVGq
# ggjW5EDrdKJ8AkETFKATniikBcG8AzxCnknDkgsk8W0xu/z3HdhYHVqqPl3M2JYq
# CnY+Yf2Hfbrqy8Lw7RmC9iBhMG4ODMt11ESOTFJklBt5UNB0SnY4/JYlRPB57jM0
# R5huPNkwgvrwl75pXu8zZ7ace9bfea4wbtBScNUq8pW7tQ8jsZ08vOGAtTGQv0bu
# WmQH0KZ/Mh7xFKSSXGjeWBcK2jeMyYBHhe5tjuZoW3PYIds9YG1J9CVFvrTw4y2/
# V3PQyygcBZ5toVrDszqxJUBdRpJBQFsYY13+ZiMlKNf8sgLQCaF5BDe6XbnAF7Es
# XmAnJYoj5rsH6EKnPImLpn9nP0gRVUPmXtyJFGToKsn+13OJitBDIFIamz5fYIqd
# 9QMCAwEAAaOCAgYwggICMB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5C
# MB0GA1UdDgQWBBSsMrpVovJwHYdVTMqS7iX8yJiA4jAOBgNVHQ8BAf8EBAMCB4Aw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdS
# U0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4
# NDIwMjFDQTEuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEW
# G2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcw
# AoZQaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwDAYDVR0TAQH/BAIw
# ADANBgkqhkiG9w0BAQsFAAOCAgEAihsJdznjrVEYHNwSGKRjuA7qp7Q+sEUZoTea
# NzX5rHVdBfsJLZG6iKj8l+6e3D9B+J8x3sDXQTFgZbn8YjmTw/mDFZnBzG1M+jYr
# JpVf4NMWXDjXn8ZGY5/Tpfy7kib2JAEKLnf+Xa2KawzMAXhwccacL2iPv5oJn8Wt
# bAUArdPsyt2uuE2S0yDLyrizT4VsbPe1u9xIMMwUz9QmN1k3nE8cgLM0Uc/obkSl
# aMDIBO4e/aeQRSN5VApuH75/jiDOE+iP+oCqRq24KFJUH14ddTjSFiJ6xIrBY909
# rQOH7puEzXy9AHV3eVQtfVQAlNHkavqHl9kluoxm12g+W+SwRjEpwDmoQNPqcqqS
# eCOrTXgZXL16sZApxqoIK7lNR+Rge8IeviJ55TaYSv5OZikedSLIysP+0e1FtM21
# 7pLySbB1ZwsPdTMc1tbtbRixLHvX34wm+e4UUO2sgyDIOF3tcQsdWsr4RM3XqJMz
# 3b4Qx9awN9K4xzuBfEROG2EIDRGhAYraxsRq6NtV0MVqr5BQnLpaJl3p7Iy2GB9n
# UN5EOKZfOXA3yCCNYuBWzzkqiG8G/t+JiTx5kKt87MNZ96PxQ/xNNMwGunriKlTR
# t2UeVD7nYpoJXxRwK6m87sjK3u4uC1W4iI3LUPrxoyUEOrTdNAUX6xGOX+f0uqx8
# fm1wHjQxggW6MIIFtgIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNp
# Z25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEAWS5PVF0WM8IiEcogV0HLQw
# CQYFKw4DAhoFAKBwMBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgor
# BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3
# DQEJBDEWBBR5u+OIJboraeo7whWJ69qdVwx5oDANBgkqhkiG9w0BAQEFAASCAYDC
# NpohgN4XvaiSilSdO3PayiI6BG7qgM/7RltifPKCIekAHMF2jW+sGg1vD8o+4Y1U
# ScfI2WQ4EyS25TNPiMP00Pq217FQ7VmAwlcHcUx6fowV5PwbRKOOgD0VHegRJybP
# bmaEPMb07uWxGMnCAIs0lNCQ/oATpUKn+e2eXwroVuf2KjJhMidko9S0Kg+EodqD
# eej5XBSnuut4et34DzoOHTPq6Czgc3XsjTnyE5SwFoS4qV9QsOHYtk1Z+7alHTXV
# X5qCOAGXOG92iXiVLNtxkY7kZWa79YopZjin3RdljJhxGB3OfeMH0nCAl7rKxgKy
# xe8TJoS8CoHbv0hjxhldyx8laSXOl+al5U3bF3ryG4MPaPhQcIFnPV2KhlU9m5xx
# Z4trDSIAyCx9m2tDWPTIl/E2yRXJtn7fQD4CduZdRyCRxEIc8S0pL4aI0EyzmWkZ
# UJzTLR1vZArzSHOGqwT1FR90yWhYY07fpvneHr5YxHFK+he4bGnBM0QUHMiuoG+h
# ggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAMTWlyS5T6PCpK
# PSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEH
# ATAcBgkqhkiG9w0BCQUxDxcNMjMwNzEzMDIxMDAwWjAvBgkqhkiG9w0BCQQxIgQg
# Co8iToYxbcYHCbYsxcQFckpsaDzTVzxxlx3CVJA5jcUwDQYJKoZIhvcNAQEBBQAE
# ggIABxfYb3kKpgDLnM7p+/rm9jX0Fab6lCfXbqp+/9ouzqoe2r06RjXi8NZ5IBi5
# W82jbnljpgEPu1J+n+loUh2oqP25dedbGZTA2DTdq3Os15pqkdVuizoMz3UMuMX9
# fIok9RSWDkYAQmeQAEztEQLlOJQXejl2xDwBjLp3+gk4f9W8EV0L/3utfOvsxy2P
# 0yAJMyi1krmsq+wrnLyCuwHfM6nWFSnAPEaw+GydBacU/OLI/M7Dj6j6tbaMZS8G
# SLydbrZvreOfVKYKB9bWRBCqOVInozdA7s8atK7FdNJIsHcskEspVQDnMKMGZykk
# ZsMd0oOibbPO+7yO/63gYb+2aRp1C4p4C9MsPAp5BVHiv49ZtmYqdvzcCZS0Xlus
# DNNc2GCGjVnpUwGZTivKsOGxN2zpaXOpBUTfAd6X9gs+1iuzi56BqifNrdQwKRPd
# pYHIcrQ6MhHxEYqijTpkaP4okUbP9frZt9Gx4/4nvwtsG8aWRkTgBi/JUgRw/da1
# BcE/DdZvVZ4MHf6oNmXvo/8+giVHhUjuUTq44VHjXDOW92c6fgB5u6FUiXJXo0jC
# XgPvKuRYYiG3l70QFXkS21zs/VlWmHqVzkTr7MYomSPrtC01MBJSAqsxlwrv73rw
# 1zH0M6UdN9JM7UFHSuXzQ6cw29fWHaMzpu9y693YJgBV9yY=
# SIG # End signature block
