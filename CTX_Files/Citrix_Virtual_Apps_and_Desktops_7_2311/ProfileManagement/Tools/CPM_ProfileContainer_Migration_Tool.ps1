<# 
.SYNOPSIS
    Citrix Profile Management Migration Tool

.DESCRIPTION 
    This script should be ran as administrator.
 
.NOTES 
    This PowerShell script was developed to help users migration from other profile scenaro to UPM Profile Container.

.COMPONENT 
    Required Module AD

.LINK 
    It is released with UPM
 
.Parameter ParameterName 
    NA 
#>

$Global:importModulesCnt = 0

function WriteLog {
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string] $Message
    )

    $logfilePath = "C:\ProgramData\Citrix\ProfileManagement\Logs\ScriptTool\MigrationScriptTool.log"

    try {
        if (-not (Test-Path -Path $logfilePath)) {
            $logfileDirectory = Split-Path $logfilePath -Parent
            if (-not (Test-Path $logfileDirectory)) {
                New-Item -ItemType Directory -Path $logfileDirectory -Force | Out-Null
            }

            New-Item -ItemType File -Path $logfilePath | Out-Null
        }
    } catch {
        Write-Host "Create log file: $logfilePath failed, the reason is: $_"
        return
    }

    $timestamp = Get-Date -Format "yyyy-mm-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"

    Add-Content -Path $logfilePath -Value $logEntry
}

function CreateJunctionPoints {
	param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string] $BaseDirectory
    )

    $BaseDirectory = Join-Path -Path $BaseDirectory -ChildPath "Profiles"

    $sourceDocumentsPath = Join-Path -Path $BaseDirectory -ChildPath "My Documents"
    $destDocumentsPath = Join-Path -Path $BaseDirectory -ChildPath "Documents"

    $sourcePicturesPath = Join-Path -Path $BaseDirectory -ChildPath "Documents\My Pictures"
    $destPicturesPath = Join-Path -Path $BaseDirectory -ChildPath "Pictures"

    $sourceMusicPath = Join-Path -Path $BaseDirectory -ChildPath "Documents\My Music"
    $destMusicPath = Join-Path -Path $BaseDirectory -ChildPath "Music"

    $sourceVideosPath = Join-Path -Path $BaseDirectory -ChildPath "Documents\My Videos"
    $destVideosPath = Join-Path -Path $BaseDirectory -ChildPath "Videos"

    $sourceAppdataPath = Join-Path -Path $BaseDirectory -ChildPath "Application Data"
    $destAppdataPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming"

    $sourceCookiesPath = Join-Path -Path $BaseDirectory -ChildPath "Cookies"
    $destCookiesPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\Cookies"

    $sourcePrintHoodPath = Join-Path -Path $BaseDirectory -ChildPath "PrintHood"
    $destPrintHoodPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\Printer Shortcuts"

    $sourceNetHoodPath = Join-Path -Path $BaseDirectory -ChildPath "NetHood"
    $destNetHoodPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\Network Shortcuts"

    $sourceRecentPath = Join-Path -Path $BaseDirectory -ChildPath "Recent"
    $destRecentPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\Recent"

    $sourceSendToPath = Join-Path -Path $BaseDirectory -ChildPath "SendTo"
    $destSendToPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\SendTo"

    $sourceTemplatesPath = Join-Path -Path $BaseDirectory -ChildPath "Templates"
    $destTemplatesPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\Templates"

    $sourceStartMenuPath = Join-Path -Path $BaseDirectory -ChildPath "Start Menu"
    $destStartMenuPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu"

    $sourceStartMenuProgramsPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Program Files"
    $destStartMenuProgramsPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs"

    $sourceLocalSettingsPath = Join-Path -Path $BaseDirectory -ChildPath "Local Settings"
    $destLocalSettingsPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Local"

    $sourceAppDataLocalPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Local\Application Data"
    $destAppDataLocalPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Local"

    $sourceTempIEPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Local\Temporary Internet Files"
    $destTempIEPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Local\Microsoft\Windows\Temporary Internet Files"

    $sourceHistoryPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Local\History"
    $destHistoryPath = Join-Path -Path $BaseDirectory -ChildPath "AppData\Local\Microsoft\Windows\History"

    if (Test-Path $destDocumentsPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceDocumentsPath`" `"$destDocumentsPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceDocumentsPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destPicturesPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourcePicturesPath`" `"$destPicturesPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourcePicturesPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destMusicPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceMusicPath`" `"$destMusicPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceMusicPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destVideosPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceVideosPath`" `"$destVideosPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceVideosPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destAppdataPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceAppdataPath`" `"$destAppdataPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceAppdataPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destCookiesPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceCookiesPath`" `"$destCookiesPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceCookiesPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destPrintHoodPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourcePrintHoodPath`" `"$destPrintHoodPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourcePrintHoodPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destNetHoodPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceNetHoodPath`" `"$destNetHoodPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceNetHoodPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destRecentPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceRecentPath`" `"$destRecentPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceRecentPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destSendToPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceSendToPath`" `"$destSendToPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceSendToPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destTemplatesPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceTemplatesPath`" `"$destTemplatesPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceTemplatesPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destStartMenuPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceStartMenuPath`" `"$destStartMenuPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceStartMenuPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destStartMenuProgramsPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceStartMenuProgramsPath`" `"$destStartMenuProgramsPath`"" -NoNewWindow -RedirectStandardOutput ".\NUL"
        icacls $sourceStartMenuProgramsPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destLocalSettingsPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceLocalSettingsPath`" `"$destLocalSettingsPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceLocalSettingsPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destAppDataLocalPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceAppDataLocalPath`" `"$destAppDataLocalPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceAppDataLocalPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destTempIEPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceTempIEPath`" `"$destTempIEPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceTempIEPath /deny "Everyone:(RD)" | Out-Null
    }

    if (Test-Path $destHistoryPath) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink /J `"$sourceHistoryPath`" `"$destHistoryPath`"" -NoNewWindow -Wait -RedirectStandardOutput ".\NUL"
        icacls $sourceHistoryPath /deny "Everyone:(RD)" | Out-Null
    }	
}

function ImportModules {
    WriteLog("Enter into the ImportModules")
    $Global:importModulesCnt++

    #Already installed and imported
    $moduleADAvailable = Get-Module *activedirectory*
    if ($null -ne $moduleADAvailable) {
        return
    }

    #Not imported but already installed
    try {
        if ($Global:importModulesCnt -eq 1) {
            write-host "`r`nPlease wait while PowerShell is importing the necessary Windows modules. " -ForegroundColor Yellow
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        return
    } catch {
 
    }

    #Uninstalled
    #Check OS Version
    $curOS = ''
    try {
        if ($Global:importModulesCnt -eq 1) {
            write-host "`r`nPlease wait while PowerShell is installing the necessary Windows additional features. " -ForegroundColor Yellow
        }
        
        $curOS = wmic os get Caption
        if ($curOS[2].Contains('Server')) {
            Import-Module ServerManager
            if ($null -eq $moduleADAvailable) {
                Add-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null           
            }    			
        } elseif ($curOS[2].Contains('Windows 11')) {
            if ($null -eq $moduleADAvailable) {
                Add-WindowsCapability –online –Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0  -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null	
            }	
        } else {#win10	
            if ($null -eq $moduleADAvailable) {
                try {
                    Add-WindowsCapability –online –Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop -WarningAction SilentlyContinue  | Out-Null
                } catch {
                    #Old versions up to 1803
                    Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell  -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                } 
            }     
        }

        Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue  | Out-Null
    } catch {
        if ($Global:importModulesCnt -eq 1) {
            return $false
        } else {
            if ($curOS[2].Contains('Server')) {
                write-host 'Unable to use this tool because imports for the following modules failed: Active Directory.' -ForegroundColor Yellow		
            } else {
                write-host 'Unable to use this tool because imports for the following modules failed:Active Directory.' -ForegroundColor Yellow		
            }

            write-host 'If it does not work, restart the machine, make sure the Windows update service is running, and then run this tool again.' -ForegroundColor Yellow
            Start-Sleep -Seconds 30
            Exit
        }
    }

    return $true
}

function MigrateLocalProfile {
    param (
        [Parameter(Mandatory=$true)]
        [array] $userMembers,
    
        [Parameter(Mandatory=$true)]
        [string] $upmVhdxStorePath,

        [Parameter(Mandatory=$true)]
        [string] $osShortName
    )

    WriteLog("Enter into the MigrateLocalProfile")

    $computerName = $env:COMPUTERNAME
    $wmi = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computerName
    $domain = $wmi.Domain

    if ($upmVhdxStorePath.EndsWith("%USERNAME%")) {
        $upmVhdxStorePath = $upmVhdxStorePath.Replace("%USERNAME%", "")
    }

    if (-not (Test-Path $upmVhdxStorePath)) {
        Write-Host "$upmVhdxStorePath is not accessed, exit the migration work"
        WriteLog("$upmVhdxStorePath is not accessed, exit the migration work")
        return
    }

    $successCount = 0
    $totalCount = $userMembers.Length
    $destinationVhdxFolder = $null
    $destinationVhdxPath = $null
    $destinationVhdxAccountFolder = $null

    ForEach ($user in $userMembers) {
        $samAccountName = $user.SamAccountName

        $sid = (New-Object System.Security.Principal.NTAccount($samAccountName)).translate([System.Security.Principal.SecurityIdentifier]).Value
        $localProfilePath = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" | Select-Object -ExpandProperty "ProfileImagePath"

        WriteLog("LocalProfilePath is $localProfilePath")
        WriteLog("User sid is $sid")

        if (Test-Path $localProfilePath) {
            $destinationVhdxFolder = Join-Path -Path (Join-Path -Path (Join-Path -Path "$upmVhdxStorePath" -ChildPath "$samAccountName") -ChildPath "ProfileContainer") -ChildPath "$osShortName"
            WriteLog("DestinationVhdxFolder is $destinationVhdxFolder")
            if (-not (Test-Path $destinationVhdxFolder)) {
                New-Item -Path $destinationVhdxFolder -ItemType Directory | Out-Null
            }

            # Set permissions from destination folder
            try {
                $destinationVhdxAccountFolder = Join-Path -Path "$upmVhdxStorePath" -ChildPath "$samAccountName"
                #Recursively set owner, so only icacls the outermost directory
                icacls $destinationVhdxAccountFolder /setowner $domain\$samAccountName /T /C | Out-Null
                #After changing owner, need reset the acl
                icacls $destinationVhdxAccountFolder /reset /T | Out-Null
            } catch {
                WriteLog("Set the $destinationVhdxAccountFolder folder permission failed")
                WriteLog("Error: $_")
            }

            # Define destination file path
            $destinationVhdxPath = Join-Path -Path $destinationVhdxFolder -ChildPath "ProfileContainer.VHDX"
            WriteLog("DestinationVhdxPath is $destinationVhdxPath")
            Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 10

            $scriptBlockCreate = {
                param($vhdxPath)
                "create vdisk file=`"$vhdxPath`" maximum 50000 type=expandable" | diskpart
            }
    
            $scriptBlockAttach = {
                param($vhdxPath)
                "select vdisk file=`"$vhdxPath`"`r`nattach vdisk" | diskpart
            }
    
            $scriptBlockFormatAndAssign = {
                param($vhdxPath)
                "select vdisk file=`"$vhdxPath`"`r`ncreate partition primary`r`nformat quick`r`nassign letter=V" | diskpart
            }
    
            $scriptBlockDetach = {
                param($vhdxPath)
                "select vdisk file`"$vhdxPath`"`r`ndetach vdisk" | diskpart
            }

            try {
                if (-not (test-path $destinationVhdxPath)) {
                    $jobCreate = Start-Job -ScriptBlock $scriptBlockCreate -ArgumentList $destinationVhdxPath
                    Wait-Job $jobCreate | Out-Null
                    $jobAttach = Start-Job -ScriptBlock $scriptBlockAttach -ArgumentList $destinationVhdxPath
                    Wait-Job $jobAttach | Out-Null
                    $jobFormatAndAssign = Start-Job -ScriptBlock $scriptBlockFormatAndAssign -ArgumentList $destinationVhdxPath
                    Wait-Job $jobFormatAndAssign | Out-Null
                    & label V: $samAccountName-Profile
                    New-Item -Path V:\Profiles -ItemType directory | Out-Null
                    icacls "V:\Profiles" /inheritance:r | Out-Null
                    icacls "V:\Profiles" /grant "Administrators:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /grant "$domain\$samAccountName`:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /grant "SYSTEM:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /setowner $domain\$samAccountName | Out-Null
                } else {
                    WriteLog("$destinationVhdxPath already existed, we don't need to do the migration")
                    return
                }

                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 50

                $startTime = get-date
                & robocopy $localProfilePath V:\Profiles /MIR /R:2 /W:1 /MT:8 /COPY:DATSOU /DCOPY:DAT /XJD | Out-Null
                $endTime = get-date
                WriteLog("Finish copying from local profile to vhdx profile")
                $baseDirectory = (Get-WmiObject Win32_Volume | Where-Object { ($_.Label -eq "$samAccountName-Profile") -and ($_.DriveLetter -eq "V:") } | Select-Object DeviceID).DeviceID
                WriteLog("baseDirectory is $baseDirectory")
				CreateJunctionPoints("$baseDirectory")
                $timeConsumed = ($endTime - $startTime).TotalMilliseconds/1000
                WriteLog("Consumed total $timeConsumed seconds")
                $jobDetach = Start-Job -ScriptBlock $scriptBlockDetach -ArgumentList $destinationVhdxPath
                Wait-Job $jobDetach | Out-Null
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 90

                icacls $destinationVhdxPath /setowner $domain\$samAccountName /C | Out-Null
                icacls $destinationVhdxPath /reset | Out-Null
                Write-Progress -Activity "Processing $samAccountName" -Status "Completed" -PercentComplete 100
                $successCount++
                Write-Host "The migration for user $samAccountName has been successfully executed." -ForegroundColor Green
                WriteLog("The migration for user $samAccountName has been successfully executed.")
            } catch {
                WriteLog("$samAccountName migration failed, try the next user")
                WriteLog("Error: $_")
            }                      
        } else {
            WriteLog("$localProfilePath is not accessed, skip this user")
            continue
        }
    }

    $failedCount = $totalCount - $successCount
    Write-Host ("`r`nMigration results:") -ForegroundColor Green
    Write-Host ("`r`n$successCount users were migrated successfully.") -ForegroundColor Green
    Write-Host ("`r`n$failedCount users were migrated failed.") -ForegroundColor Red
    Write-Host ("`r`nFor more information, see the log file at C:\ProgramData\Citrix\ProfileManagement\Logs\ScriptTool\MigrationScriptTool.log.") -ForegroundColor Green

    WriteLog("There are a total of $totalCount users.Migration is successful for $successCount users and failed for $failedCount users.")
    WriteLog("Leave the MigrateLocalProfile")
}

function MigrateUPMProfile {
    param (
        [Parameter()]
        [array] $userMembers,
    
        [Parameter(Mandatory=$true)]
        [string] $upmProfileStorePath,

        [Parameter(Mandatory=$true)]
        [string] $upmVhdxStorePath,

        [Parameter(Mandatory=$true)]
        [string] $osShortName
    )
    WriteLog("Enter into the MigrateUPMProfile")
    $computerName = $env:COMPUTERNAME
    $wmi = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computerName
    $domain = $wmi.Domain

    if ($upmVhdxStorePath.EndsWith("%USERNAME%")) {
        $upmVhdxStorePath = $upmVhdxStorePath.Replace("%USERNAME%", "")
    }

    if ($upmProfileStorePath.EndsWith("%USERNAME%")) {
        $upmProfileStorePath = $upmProfileStorePath.Replace("%USERNAME%", "")
    }

    if (-not (Test-Path $upmVhdxStorePath)) {
        Write-Host "$upmVhdxStorePath is not accessed, exit the migration work"
        WriteLog("$upmVhdxStorePath is not accessed, exit the migration work")
        return
    }

    $successCount = 0
    $totalCount = $userMembers.Length
    $destinationVhdxFolder = $null
    $destinationVhdxPath = $null
    $destinationVhdxContainerFolder = $null

    foreach ($user in $userMembers) {
        $samAccountName = $user.SamAccountName
        $sid = (New-Object System.Security.Principal.NTAccount($samAccountName)).translate([System.Security.Principal.SecurityIdentifier]).Value
        $sourceProfileFolder = Join-Path -Path (Join-Path -Path "$upmProfileStorePath" -ChildPath "$samAccountName") -ChildPath "UPM_Profile"
        WriteLog("SourceProfileFolder is $sourceProfileFolder")
        WriteLog("User sid is $sid")       

        if (Test-Path $sourceProfileFolder) {
            $destinationVhdxFolder = Join-Path -Path (Join-Path -Path (Join-Path -Path "$upmVhdxStorePath" -ChildPath "$samAccountName") -ChildPath "ProfileContainer") -ChildPath "$osShortName"
            WriteLog("DestinationVhdxFolder is $destinationVhdxFolder")
            if (-not (Test-Path $destinationVhdxFolder)) {
                New-Item -Path $destinationVhdxFolder -ItemType Directory | Out-Null
            }

            # Set permissions from destination folder
            try {
                $destinationVhdxContainerFolder = Join-Path -Path (Join-Path -Path "$upmVhdxStorePath" -ChildPath "$samAccountName") -ChildPath "ProfileContainer"
                #Recursively set owner, so only icacls the outermost directory
                icacls $destinationVhdxContainerFolder /setowner $domain\$samAccountName /T /C | Out-Null
                #After changing owner, need reset the acl
                icacls $destinationVhdxContainerFolder /reset /T | Out-Null
            } catch {
                WriteLog("Set the $destinationVhdxFolder folder permission failed")
                WriteLog("Error: $_")
            }

            # Define destination file path
            $destinationVhdxPath = Join-Path -Path $destinationVhdxFolder -ChildPath "ProfileContainer.VHDX"
            WriteLog("DestinationVhdxPath is $destinationVhdxPath")
            Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 10

            $scriptBlockCreate = {
                param($vhdxPath)
                "create vdisk file=`"$vhdxPath`" maximum 50000 type=expandable" | diskpart
            }
    
            $scriptBlockAttach = {
                param($vhdxPath)
                "select vdisk file=`"$vhdxPath`"`r`nattach vdisk" | diskpart
            }
    
            $scriptBlockFormatAndAssign = {
                param($vhdxPath)
                "select vdisk file=`"$vhdxPath`"`r`ncreate partition primary`r`nformat quick`r`nassign letter=V" | diskpart
            }
    
            $scriptBlockDetach = {
                param($vhdxPath)
                "select vdisk file`"$vhdxPath`"`r`ndetach vdisk" | diskpart
            }

            try {
                if (-not (test-path $destinationVhdxPath)) {
                    $jobCreate = Start-Job -ScriptBlock $scriptBlockCreate -ArgumentList $destinationVhdxPath
                    Wait-Job $jobCreate | Out-Null
                    $jobAttach = Start-Job -ScriptBlock $scriptBlockAttach -ArgumentList $destinationVhdxPath
                    Wait-Job $jobAttach | Out-Null
                    $jobFormatAndAssign = Start-Job -ScriptBlock $scriptBlockFormatAndAssign -ArgumentList $destinationVhdxPath
                    Wait-Job $jobFormatAndAssign | Out-Null
                    & label V: $samAccountName-Profile
                    New-Item -Path V:\Profiles -ItemType directory | Out-Null
                    icacls "V:\Profiles" /inheritance:r | Out-Null
                    icacls "V:\Profiles" /grant "Administrators:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /grant "$domain\$samAccountName`:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /grant "SYSTEM:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /setowner $domain\$samAccountName | Out-Null
                } else {
                    WriteLog("$destinationVhdxPath already existed, we don't need to do the migration")
                    return
                }

                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 50

                $startTime = get-date
                & robocopy $sourceProfileFolder V:\Profiles /MIR /R:2 /W:1 /MT:8 /COPY:DATSOU /DCOPY:DAT /XJD | Out-Null
                $endTime = get-date
                WriteLog("Finish copying from upm file-based profile to vhdx profile")
                $baseDirectory = (Get-WmiObject Win32_Volume | Where-Object { ($_.Label -eq "$samAccountName-Profile") -and ($_.DriveLetter -eq "V:") } | Select-Object DeviceID).DeviceID
                WriteLog("baseDirectory is $baseDirectory")
				CreateJunctionPoints("$baseDirectory")
                $timeConsumed = ($endTime - $startTime).TotalMilliseconds/1000
                WriteLog("Consumed total $timeConsumed seconds")
                $jobDetach = Start-Job -ScriptBlock $scriptBlockDetach -ArgumentList $destinationVhdxPath
                Wait-Job $jobDetach | Out-Null
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 90

                icacls $destinationVhdxPath /setowner $domain\$samAccountName /C | Out-Null
                icacls $destinationVhdxPath /reset | Out-Null
                Write-Progress -Activity "Processing $samAccountName" -Status "Completed" -PercentComplete 100
                $successCount++
                Write-Host "The migration for user $samAccountName has been successfully executed." -ForegroundColor Green
                WriteLog("The migration for user $samAccountName has been successfully executed.")
            } catch {
                WriteLog("$samAccountName migration failed, try the next user")
                WriteLog("Error: $_")
            }                      
        } else {
            WriteLog("$sourceProfileFolder is not accessed, return")
            return
        }
    }

    $failedCount = $totalCount - $successCount
    Write-Host ("`r`nMigration results:") -ForegroundColor Green
    Write-Host ("`r`n$successCount users were migrated successfully.") -ForegroundColor Green
    Write-Host ("`r`n$failedCount users were migrated failed.") -ForegroundColor Red
    Write-Host ("`r`nFor more information, see the log file at C:\ProgramData\Citrix\ProfileManagement\Logs\ScriptTool\MigrationScriptTool.log.") -ForegroundColor Green
    WriteLog("There are a total of $totalCount users.Migration is successful for $successCount users and failed for $failedCount users.")
    WriteLog("Leave the MigrateUPMProfile.")
}

function MigrateFSLogixVHD {
    param (
        [Parameter()]
        [array] $userMembers,
    
        [Parameter(Mandatory=$true)]
        [string] $fslogixVhdStorePath,

        [Parameter(Mandatory=$true)]
        [string] $upmVhdxStorePath,

        [Parameter(Mandatory=$true)]
        [string] $osShortName
    )
    WriteLog("Enter into the MigrateFSLogixVHD")
    $computerName = $env:COMPUTERNAME
    $wmi = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computerName
    $domain = $wmi.Domain

    $successCount = 0
    $totalCount = $userMembers.Length

    $fslogixUserFlag = $false
    if ($fslogixVhdStorePath.EndsWith("%USERNAME%")) {
        $fslogixVhdStorePath = $fslogixVhdStorePath.Replace("%USERNAME%", "")
        $fslogixUserFlag = $true
    }

    if ($upmVhdxStorePath.EndsWith("%USERNAME%")) {
        $upmVhdxStorePath = $upmVhdxStorePath.Replace("%USERNAME%", "")
    }

    if (-not (Test-Path $upmVhdxStorePath)) {
        Write-Host "$upmVhdxStorePath is not accessed, exit the migration work"
        WriteLog("$upmVhdxStorePath is not accessed, exit the migration work")
        return
    }

    foreach ($user in $userMembers) {
        # User from the file corresponds to SAM
        $samAccountName = $user.SamAccountName
        # Read SID based on SamAccountName
        $sid = (New-Object System.Security.Principal.NTAccount($samAccountName)).translate([System.Security.Principal.SecurityIdentifier]).Value
        # Defining the path to the fslogix vhdx path

        $sourceVhdPath = $null
        $destinationVhdxFolder = $null
        $destinationVhdxAccountFolder = $null
        $sidAndAccount = "$sid" + "_$samAccountName"

        if ($fslogixUserFlag) {
            $sourceVhdPath = Join-Path -Path (Join-Path -Path (Join-Path -Path "$fslogixVhdStorePath" -ChildPath "$samAccountName") -ChildPath "$sidAndAccount") -ChildPath "Profile_$samAccountName.VHD"
        } else {
            $sourceVhdPath = Join-Path -Path (Join-Path -Path "$fslogixVhdStorePath" -ChildPath "$sidAndAccount") -ChildPath "Profile_$samAccountName.VHD"
        }       
        WriteLog("The source vhd path is $SourceVhdPath")

        if (Test-Path $SourceVhdPath) {  
            if (Test-Path $upmVhdxStorePath) {
                $destinationVhdxFolder = Join-Path -Path (Join-Path -Path (Join-Path -Path "$upmVhdxStorePath" -ChildPath "$samAccountName") -ChildPath "ProfileContainer") -ChildPath "$osShortName"
                if (-not (Test-Path $destinationVhdxFolder)) {
                    New-Item -Path $destinationVhdxFolder -ItemType Directory | Out-Null
                }
            }

            # Set permissions from destination folder
            try {
                $destinationVhdxAccountFolder = Join-Path -Path "$upmVhdxStorePath" -ChildPath "$samAccountName"
                #Recursively set owner, so only icacls the outermost directory
                icacls $destinationVhdxAccountFolder /setowner $domain\$samAccountName /T /C | Out-Null
                #After changing owner, need reset the acl
                icacls $destinationVhdxAccountFolder /reset /T | Out-Null
            } catch {
                WriteLog("Set the $destinationVhdxFolder folder permission failed")
                WriteLog("Error: $_")
            }
    
            # Define destination file path
            $destinationVhdxPath = Join-Path -Path $destinationVhdxFolder -ChildPath "ProfileContainer.VHDX"
            WriteLog("DestinationVhdxPath is $destinationVhdxPath")
            Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 10

            $scriptBlockCreate = {
                param($vhdxPath)
                "create vdisk file=`"$vhdxPath`" maximum 50000 type=expandable" | diskpart
            }
    
            $scriptBlockAttach = {
                param($vhdxPath)
                "select vdisk file=`"$vhdxPath`"`r`nattach vdisk" | diskpart
            }
    
            $scriptBlockFormatAndAssign = {
                param($vhdxPath)
                "select vdisk file=`"$vhdxPath`"`r`ncreate partition primary`r`nformat quick`r`nassign letter=V" | diskpart
            }
    
            $scriptBlockDetach = {
                param($vhdxPath)
                "select vdisk file`"$vhdxPath`"`r`ndetach vdisk" | diskpart
            }

            try {
                if (-not (test-path $destinationVhdxPath)) {
                    $jobCreate = Start-Job -ScriptBlock $scriptBlockCreate -ArgumentList $destinationVhdxPath
                    Wait-Job $jobCreate | Out-Null
                    $jobAttach = Start-Job -ScriptBlock $scriptBlockAttach -ArgumentList $destinationVhdxPath
                    Wait-Job $jobAttach | Out-Null
                    $jobFormatAndAssign = Start-Job -ScriptBlock $scriptBlockFormatAndAssign -ArgumentList $destinationVhdxPath
                    Wait-Job $jobFormatAndAssign | Out-Null
                    & label V: $samAccountName-Profile
                    New-Item -Path V:\Profiles -ItemType directory | Out-Null
                    icacls "V:\Profiles" /inheritance:r | Out-Null
                    icacls "V:\Profiles" /grant "Administrators:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /grant "$domain\$samAccountName`:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /grant "SYSTEM:(OI)(CI)F" /T | Out-Null
                    icacls "V:\Profiles" /setowner $domain\$samAccountName | Out-Null
                } else {
                    WriteLog("$destinationVhdxPath already existed, we don't need to do the migration")
                    return
                }
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 50

                # Mound Disk Image
                Mount-DiskImage -ImagePath $SourceVhdPath -NoDriveLetter | Out-Null
                Start-Sleep -Seconds 2
                # Get available drive letter
                $partition = Get-DiskImage -ImagePath $SourceVhdPath | Get-Disk | Get-Partition
                $usedDriveLetters = Get-WmiObject Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
                $availableDriveLetters = [char[]](67..90) | ForEach-Object { [string]([char]$_) } | Where-Object { $_ + ':' -notin $usedDriveLetters }
                $partition | Set-Partition -NewDriveLetter $availableDriveLetters[0]
                $driveLetter = (Get-DiskImage -ImagePath $SourceVhdPath | Get-Disk | Get-Partition).DriveLetter
                $mountPoint = ($driveLetter + ':\')
                WriteLog("Mountpoint is: $mountPoint")
                
                # Define path in the profile disk
                $fslogixDiskProfileFolder = "Profile"
                $fslogixDiskProfilePath = Join-Path -Path $MountPoint -ChildPath $fslogixDiskProfileFolder
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 60

                $startTime = get-date
                & robocopy $fslogixDiskProfilePath V:\Profiles /MIR /R:2 /W:1 /MT:8 /COPY:DATSOU /DCOPY:DAT /XJD | Out-Null
                $endTime = get-date
                $baseDirectory = (Get-WmiObject Win32_Volume | Where-Object { ($_.Label -eq "$samAccountName-Profile") -and ($_.DriveLetter -eq "V:") } | Select-Object DeviceID).DeviceID
                WriteLog("baseDirectory is $baseDirectory")
				CreateJunctionPoints("$baseDirectory")
                WriteLog("Finish copying from fslogix vhd profile to vhdx profile")
                $timeConsumed = ($endTime - $startTime).TotalMilliseconds/1000
                WriteLog("Consumed total $timeConsumed seconds")

                $jobDetach = Start-Job -ScriptBlock $scriptBlockDetach -ArgumentList $destinationVhdxPath
                Wait-Job $jobDetach | Out-Null
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 90
        
                # Short delay and unmount the disk image
                Start-Sleep -Seconds 2
                Dismount-DiskImage -ImagePath $SourceVhdPath | Out-Null

                icacls $destinationVhdxPath /setowner $domain\$samAccountName /C | Out-Null
                icacls $destinationVhdxPath /reset | Out-Null
                Write-Progress -Activity "Processing $samAccountName" -Status "Completed" -PercentComplete 100
                $successCount++
                Write-Host "The migration for user $samAccountName has been successfully executed." -ForegroundColor Green
                WriteLog("The migration for user $samAccountName has been successfully executed.")
            } catch {
                WriteLog("$samAccountName migration failed, try the next user")
                WriteLog("Error: $_")
            }            
        }
    }

    $failedCount = $totalCount - $successCount
    Write-Host ("`r`nMigration results:") -ForegroundColor Green
    Write-Host ("`r`n$successCount users were migrated successfully.") -ForegroundColor Green
    Write-Host ("`r`n$failedCount users were migrated failed.") -ForegroundColor Red
    Write-Host ("`r`nFor more information, see the log file at C:\ProgramData\Citrix\ProfileManagement\Logs\ScriptTool\MigrationScriptTool.log.") -ForegroundColor Green

    WriteLog("There are a total of $totalCount users.Migration is successful for $successCount users and failed for $failedCount users.")
    WriteLog("Leave the MigrateFSLogixVHD.")
}

function MigrateFSLogixVHDX {
    param (
        [Parameter()]
        [array] $userMembers,
    
        [Parameter(Mandatory=$true)]
        [string] $fslogixVhdxStorePath,

        [Parameter(Mandatory=$true)]
        [string] $upmVhdxStorePath,

        [Parameter(Mandatory=$true)]
        [string] $osShortName
    )
    WriteLog("Enter into the MigrateFSLogixVHDX")
    $computerName = $env:COMPUTERNAME
    $wmi = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computerName
    $domain = $wmi.Domain

    $successCount = 0
    $totalCount = $userMembers.Length
    $fslogixUserFlag = $false

    if ($fslogixVhdxStorePath.EndsWith("%USERNAME%")) {
        $fslogixVhdxStorePath = $fslogixVhdxStorePath.Replace("%USERNAME%", "")
        $fslogixUserFlag = $true
    }

    if ($upmVhdxStorePath.EndsWith("%USERNAME%")) {
        $upmVhdxStorePath = $upmVhdxStorePath.Replace("%USERNAME%", "")
    }

    if (-not (Test-Path $upmVhdxStorePath)) {
        Write-Host "$upmVhdxStorePath is not accessed, exit the migration work"
        WriteLog("$upmVhdxStorePath is not accessed, exit the migration work")
        return
    }

    foreach ($user in $userMembers) {
        $samAccountName = $user.SamAccountName
        $sid = (New-Object System.Security.Principal.NTAccount($samAccountName)).translate([System.Security.Principal.SecurityIdentifier]).Value

        $sourceVhdxPath = $null
        $destinationVhdxFolder = $null
        $destinationVhdxAccountFolder = $null
        $sidAndAccount = "$sid" + "_$samAccountName"

        if ($fslogixUserFlag) {
            $sourceVhdxPath = Join-Path -Path (Join-Path -Path (Join-Path -Path "$fslogixVhdxStorePath" -ChildPath "$samAccountName") -ChildPath "$sidAndAccount") -ChildPath "Profile_$samAccountName.VHDX"
        } else {
            $sourceVhdxPath = Join-Path -Path (Join-Path -Path "$fslogixVhdxStorePath" -ChildPath "$sidAndAccount") -ChildPath "Profile_$samAccountName.VHDX"
        }       
        WriteLog("The source vhdx path is $sourceVhdxPath")

        if (Test-Path $sourceVhdxPath) {
            if (Test-Path $upmVhdxStorePath) {
                $destinationVhdxFolder = Join-Path -Path (Join-Path -Path (Join-Path -Path "$upmVhdxStorePath" -ChildPath "$samAccountName") -ChildPath "ProfileContainer") -ChildPath "$osShortName"
                if (-not (Test-Path $destinationVhdxFolder)) {
                    WriteLog("Create Folder: $destinationVhdxFolder")
                    New-Item -Path $destinationVhdxFolder -ItemType Directory | Out-Null
                }
            }

            # Set permissions from destination folder
            try {
                $destinationVhdxAccountFolder = Join-Path -Path "$upmVhdxStorePath" -ChildPath "$samAccountName"
                #recursive set owner, so only icacls the outermost directory
                icacls $destinationVhdxAccountFolder /setowner $domain\$samAccountName /T /C | Out-Null
                icacls $destinationVhdxAccountFolder /reset /T | Out-Null
            } catch {
                WriteLog("Set the $destinationVhdxFolder folder permission failed")
                WriteLog("Error: $_")
            }
    
            # Define destination file path
            $destinationVhdxPath = Join-Path -Path $destinationVhdxFolder -ChildPath "ProfileContainer.VHDX"
            # Copy profile disk to new destination
            try {
                WriteLog("Copying $sourceVhdxPath to $destinationVhdxPath")
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 10
                Copy-Item -Path $sourceVhdxPath -Destination $destinationVhdxPath | Out-Null
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 30
                icacls $destinationVhdxPath /setowner $domain\$samAccountName /C | Out-Null
                icacls $destinationVhdxPath /reset | Out-Null
                # Mound Disk Image
                Mount-DiskImage -ImagePath $destinationVhdxPath -NoDriveLetter | Out-Null
                Start-Sleep -Seconds 5
                WriteLog("Mount-DiskImage $destinationVhdxPath success")
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 70

                # Get drive letter
                $partition = Get-DiskImage -ImagePath $destinationVhdxPath | Get-Disk | Get-Partition
                $usedDriveLetters = Get-WmiObject Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
                $availableDriveLetters = [char[]](67..90) | ForEach-Object { [string]([char]$_) } | Where-Object { $_ + ':' -notin $usedDriveLetters }
                $partition | Set-Partition -NewDriveLetter $availableDriveLetters[0]
                $driveLetter = (Get-DiskImage -ImagePath $destinationVhdxPath | Get-Disk | Get-Partition).DriveLetter
                $mountPoint = ($driveLetter + ':\')
                WriteLog("Mountpoint is: $mountPoint")
                
                # Define path in the profile disk
                $fslogixDiskProfileFolder = "Profile"
                $upmDiskProfileFolder = "Profiles"
                $fslogixDiskProfilePath = Join-Path -Path $MountPoint -ChildPath $fslogixDiskProfileFolder 
                $upmDiskProfilePath = Join-Path -Path $MountPoint -ChildPath $upmDiskProfileFolder
                Rename-Item -Path $fslogixDiskProfilePath -NewName $upmDiskProfilePath
                Write-Progress -Activity "Processing $samAccountName" -Status "In progress" -PercentComplete 90
                WriteLog("Rename from $fslogixDiskProfilePath to $upmDiskProfilePath")

                $fslogixRecycleBinPath = Join-Path -Path $MountPoint -ChildPath "PROFILE_RECYCLE.BIN"
                $upmRecycleBinPath = Join-Path -Path $MountPoint -ChildPath "`$RECYCLE.BIN"
                WriteLog("fslogixRecycleBinPath is $fslogixRecycleBinPath")
                WriteLog("upmRecycleBinPath is $upmRecycleBinPath")
                if ((Test-Path $fslogixRecycleBinPath) -and (HasValidateFileInRecyclebin($fslogixRecycleBinPath))) {
                    $currentUserName = "$env:USERNAME"
                    icacls $fslogixRecycleBinPath /remove:g users | Out-Null
                    icacls $fslogixRecycleBinPath /inheritance:d | Out-Null
                    icacls $fslogixRecycleBinPath /setowner "$domain\$currentUserName" | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g users | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g EVERYONE | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g SYSTEM | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g Administrators | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g "restricted" | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g "all application packages" | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g "CREATOR OWNER" | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g "$domain\$currentUserName" | Out-Null
                    icacls $fslogixRecycleBinPath /remove:g "$domain\$samAccountName" | Out-Null
                    icacls $fslogixRecycleBinPath /grant "SYSTEM:(OI)(CI)F" | Out-Null
                    icacls $fslogixRecycleBinPath /grant "Administrators:(OI)(CI)F" | Out-Null
                    icacls $fslogixRecycleBinPath /grant "$domain\$samAccountName`:(OI)(CI)F" | Out-Null
                    icacls $fslogixRecycleBinPath /setowner $domain\$samAccountName | Out-Null
                    Rename-Item -Path $fslogixRecycleBinPath -NewName $upmRecycleBinPath | Out-Null
                    WriteLog("We have set permission for the recycle bin")
                } else {
                    WriteLog("fslogix recycle bin not exist or have not available file")
                }
        
                # Short delay and unmount the disk image
                Start-Sleep -Seconds 2
                Dismount-DiskImage -ImagePath $destinationVhdxPath | Out-Null
                WriteLog("Dismount the $destinationVhdxPath")
                Write-Progress -Activity "Processing $samAccountName" -Status "Completed" -PercentComplete 100

                $successCount++
                Write-Host "The migration for user $samAccountName has been successfully executed." -ForegroundColor Green
                WriteLog("The migration for user $samAccountName has been successfully executed.")
            } catch {
                WriteLog("$samAccountName migration failed, try the next user")
                WriteLog("Error: $_")
            }
        } else {
            WriteLog("$SourceVhdxPath is not existed")
        }
    }

    $failedCount = $totalCount - $successCount
    Write-Host ("`r`nMigration results:") -ForegroundColor Green
    Write-Host ("`r`n$successCount users were migrated successfully.") -ForegroundColor Green
    Write-Host ("`r`n$failedCount users were migrated failed.") -ForegroundColor Red
    Write-Host ("`r`nFor more information, see the log file at C:\ProgramData\Citrix\ProfileManagement\Logs\ScriptTool\MigrationScriptTool.log.") -ForegroundColor Green
    
    WriteLog("Migration results:$successCount users were migrated successfully.")
    WriteLog("$failedCount users could not be migrated.")
}

function HasValidateFileInRecyclebin {
    param (
        [Parameter(Mandatory=$true)]
        [string]$fslogixRecycleBinPath
    )

    $files = Get-ChildItem -Path $fslogixRecycleBinPath -File -Force
    if ($files.Count -eq 1 -and $files.Name -eq "desktop.ini") {
        WriteLog("The directory contains only one file named desktop.ini.")
        return $False
    } else {
        WriteLog("The directory does not meet the specified conditions.")
        return $True
    }
}

function GetPendingMigrationUsers {
    param (
        [Parameter(Mandatory=$true)]
        [string]$userAndGroup
    )

    WriteLog("Enter into the GetPendingMigrationUsers")
    $usersAndGroups = $userAndGroup -Split(",")
    $usersAndGroups = $usersAndGroups.Trim()

    $userMembers = @()

    foreach ($item in $usersAndGroups) {
        if ($item -notmatch '^[^\\]+\\[^\\]+$') {
            WriteLog("$item is not the valid format")
            return $false
        }
        
        $domainObject = $item -split "\\"
        $domain = $domainObject[0]
        $objectName = $domainObject[1]
        
        if (Get-ADUser -Filter {SamAccountName -eq $objectName} -Server $domain) {
            $userMembers += Get-ADUser -Identity $objectName -Server $domain
        } elseif (Get-ADGroup -Filter {SamAccountName -eq $objectName} -Server $domain) {
            $groupMembers = Get-ADGroupMember -Identity $objectName -Server $domain
            $userMembers += $groupMembers | Where-Object {$_.objectClass -eq 'user'}
        } else {
            Write-Host "We can not find any domain user in $objectName" -ForegroundColor Red
            WriteLog("We can not find any domain user in $objectName")
        }
    }

    $usersCount = $userMembers.Length
    
    if ($usersCount -gt 0) {
        Write-Host "A total of $usersCount users will be migrated. Please refer to the log file(C:\ProgramData\ProfileManagement\Logs\ScriptTool\MigrationScriptTool.log) for the specific list of users." -ForegroundColor Green
        foreach ($userMember in $userMembers) {
            $samAccountName = $userMember.SamAccountName
            WriteLog("Will processing account: $samAccountName")
        }
    } else {
        Write-Host "0 user in the input users and groups" -ForegroundColor Yellow
        WriteLog("0 user in the input users and groups")
    }

    WriteLog("Leave the GetPendingMigrationUsers")
    return $userMembers
}

function DisplayWelcomeInfo {
    WriteLog("Enter into the DisplayWelcomeInfo")
    Write-Host "===============================================================================================================================================" -ForegroundColor Green
    Write-Host "Welcome to the Citrix Profile Container Migration Tool!`r`n" -ForegroundColor Green
    Write-Host "This tool lets you migrate user profiles from your current profile solution to Citrix container-based profile solution. It supports the following migration types:`r`n" -ForegroundColor Green
    Write-Host "- Local Profile Migration: Migrate Windows local profiles to Citrix container-based profile solution`r`n" -ForegroundColor Green
    Write-Host "- Citrix File-Based Profile Solution Migration: Migrate user profiles from Citrix file-based profile solution to Citrix container-based profile solution`r`n" -ForegroundColor Green
    Write-Host "- FSLogix Profile Container Migration: Migrate user profiles from FSLogix Profile Container to Citrix container-based profile solution`r`n" -ForegroundColor Green
    Write-Host "================================================================================================================================================`r`n" -ForegroundColor Green
    Write-Host "Before you begin, make sure you meet the following prerequisites:`r`n" -ForegroundColor Green
    Write-Host "    - Set up the Citrix user store and configure its Windows Access Control Lists (ACL). For more information, see https://docs.citrix.com/en-us/profile-management/current-release/install-and-set-up/create-user-store.html." -ForegroundColor Green
    Write-Host "    - Run this tool using a domain admin account.`r`n" -ForegroundColor Green
    Write-Host "Choose a migration type by entering the corresponding number (1-4):`r`n" -ForegroundColor Green
    Write-Host "[1] Local Profile Migration`r`n" -ForegroundColor Green
    Write-Host "[2] Citrix File-Based Profile Solution Migration`r`n" -ForegroundColor Green
    Write-Host "[3] FSLogix Profile Container (VHDX) Migration`r`n" -ForegroundColor Green
    Write-Host "[4] FSLogix Profile Container (VHD) Migration`r`n" -ForegroundColor Green
    WriteLog("Leave the DisplayWelcomeInfo")
}

function DisplayUserAndGroupPrompts {
    WriteLog("Enter into the DisplayUserAndGroupPrompts")
    Write-Host "`r`nSpecify users and groups you want to migrate, separated by commas. Use the following form: <DOMAIN NAME>\<USER NAME>,<DOMAIN NAME>\<GROUP NAME>" -ForegroundColor Green
    WriteLog("Leave the DisplayUserAndGroupPrompts")
}

function DisplayFslogixStorePrompts {
    WriteLog("Enter into the DisplayFslogixStorePrompts")
    Write-Host "`r`nSpecify the FSLogix VHDX location. Only %USERNAME% is supported among all variables." -ForegroundColor Green
}

function DisplayUPMStorePrompts {
    WriteLog("Enter into the DisplayUPMStorePrompts")
    Write-Host "`r`nSpecify the path to Citrix VHDX store.`r`n*Notes: You can use the Citrix user store as the Citrix VHDX store, or specify a different network path as the Citrix VHDX store. Only %USERNAME% is supported among all variables." -ForegroundColor Green
    WriteLog("Leave the DisplayUPMStorePrompts")
}

function DisplayOsnamePrompts {
    WriteLog("Enter into the DisplayOsnamePrompts")
    Write-Host "`r`nSpecify the Windows OS version of your machines by entering its short name." -ForegroundColor Green
    Write-Host "*Note: Only user profiles with the specified OS type will be migrated." -ForegroundColor Green
    Write-Host "Short names of commonly-used Windows OS versions:" -ForegroundColor Green
    Write-Host "|Long name              |Short name|" -ForegroundColor Green
    Write-Host "|Windows server 2022    |Win2022   |" -ForegroundColor Green
    Write-Host "|Windows server 2019    |Win2019   |" -ForegroundColor Green
    Write-Host "|Windows server 2016    |Win2016   |" -ForegroundColor Green
    Write-Host "|Windows 11             |Win11     |" -ForegroundColor Green
    Write-Host "|Windows 10 Redstone 6  |Win10RS6  |" -ForegroundColor Green
    Write-Host "|Windows 10 Redstone 5  |Win10RS5  |" -ForegroundColor Green
    Write-Host "To get short names of other Windows OS versions, see https://docs.citrix.com/en-us/profile-management/current-release/policies/settings.html." -ForegroundColor Green
    WriteLog("Leave the DisplayOsnamePrompts")
}

function DisplayFutureWork {
    WriteLog("Enter into the DisplayFutureWork")
    Write-Host "`r`nNext steps:" -ForegroundColor Green
    Write-Host "`r`nTo get started with Citrix container-based profile solution, configure the following settings:" -ForegroundColor Green
    Write-Host "`r`n- Enable Profile Management" -ForegroundColor Green
    Write-Host "`r`n- Path to user store" -ForegroundColor Green
    Write-Host "`r`n- Enable profile container" -ForegroundColor Green
    Write-Host "`r`n- (Optional) Customize storage path for VHD files" -ForegroundColor Green
    Write-Host "`r`nFor more information, see https://docs.citrix.com/en-us/profile-management/current-release.html." -ForegroundColor Green
    WriteLog("Leave the DisplayFutureWork")
}

function CheckOsShortNameFormat {
    param (
        [Parameter(Mandatory=$true)]
        [string]$osShortName
    )

    WriteLog("Enter into the CheckOsShortNameFormat")
    $osShortNameArray = @("Win10RS6","Win10RS5","Win10RS4","Win10RS3","Win10RS2","Win10RS1","Win11","Win10", "Win2022", "Win2019", "Win2016")

    foreach ($shortName in $osShortNameArray) {
        if ($osShortName -eq $shortName) {
            WriteLog("$osShortName is ok")
            return $true
        }
    }

    if (-not $osShortName.StartsWith("Win")) {
        WriteLog("$osShortName is not valid")
        return $false
    }

    WriteLog("Leave the CheckOsShortNameFormat")
    return $false
}

function CheckFslogixStorePath {
    param (
        [Parameter(Mandatory=$true)]
        [string]$fslogixStorePath
    )

    WriteLog("Enter into the CheckFslogixStorePath")
    if (Test-Path -Path $fslogixStorePath) {
        WriteLog("$fslogixStorePath can be accessed without variable")
        return $true
    }

    $removeUserPath = $fslogixStorePath.Replace("%USERNAME%", "")

    if (Test-Path -Path $removeUserPath) {
        WriteLog("$fslogixStorePath can be accessed after removing variable")
        return $true
    }

    WriteLog("Leave the CheckFslogixStorePath")
    return $false
}

function CheckUpmStorePath {
    param (
        [Parameter(Mandatory=$true)]
        [string]$upmStorePath
    )

    WriteLog("Enter into the CheckUpmStorePath")
    if (-not $upmStorePath.EndsWith("%USERNAME%")) {
        WriteLog("$upmStorePath does not ends with USERNAME")
        return $false
    }

    $removeUserPath = $upmStorePath.Replace("%USERNAME%", "")

    if (Test-Path -Path $removeUserPath) {
        WriteLog("$upmStorePath can be accessed")
        return $true
    }

    WriteLog("$upmStorePath can not be accessed, leave the CheckUpmStorePath")
    return $false
}

function MigrationProfiles {
    WriteLog("Enter into the MigrationProfiles")
    $choice = (Read-Host  "Enter number (1-4)").Trim()
    while (($choice -ne 1) -and ($choice -ne 2) -and ($choice -ne 3) -and ($choice -ne 4)) {
        Write-Host "`r`nInvalid value, make sure that you enter the right number 1-4" -ForegroundColor Yellow 
        Write-Host "`r`nIf you want to exit this tool, please input exit" -ForegroundColor Yellow
        $choice = (Read-Host  "`r`nEnter number (1-4)").Trim()
        if ($choice -eq "exit") {
            WriteLog("User input exit")
            exit
        }
    }

    WriteLog("User have choosed $choice")

    switch ($choice) {
        1 {
            DisplayUserAndGroupPrompts
            $userAndGroup = Read-Host "Enter users and groups"
            $users = GetPendingMigrationUsers -userAndGroup $userAndGroup
            while ($users -eq $false) {
                Write-Host "`r`nThe user or group format you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "`r`nIf you want to exit this tool, please enter exit" -ForegroundColor Yellow

                $userAndGroup = Read-Host "`r`nEnter users and groups"
                if ($userAndGroup -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
                $users = GetPendingMigrationUsers -userAndGroup $userAndGroup
            }


            DisplayUPMStorePrompts
            $upmVhdxStorePath = Read-Host "Enter path"
            while ((CheckUpmStorePath -upmStorePath $upmVhdxStorePath) -eq $false) {
                Write-Host "`r`nThe UPM VHDX store path you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "If you want to exit this tool, please enter exit" -ForegroundColor Green
                $upmVhdxStorePath = Read-Host "Please enter the UPM VHDX store path"
                if ($upmVhdxStorePath -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            DisplayOsnamePrompts
            $osShortName = Read-Host "Enter short OS name"      
            while ((CheckOsShortNameFormat -osShortName $osShortName) -eq $false) {
                Write-Host "`r`nThe vda machine's os short name you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "`r`nIf you want to exit this tool, please enter exit" -ForegroundColor Green
                $osShortName = Read-Host "Please enter the vda machine's os short name"
                if ($osShortName -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            MigrateLocalProfile -userMembers $users -upmVhdxStorePath $upmVhdxStorePath -osShortName $osShortName
            DisplayFutureWork
        }

        2 {
            DisplayUserAndGroupPrompts
            $userAndGroup = Read-Host "Enter users and groups"
            $users = GetPendingMigrationUsers -userAndGroup $userAndGroup
            while ($users -eq $false) {
                Write-Host "`r`nThe user or group format you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "`r`nIf you want to exit this tool, please enter exit" -ForegroundColor Yellow

                $userAndGroup = Read-Host "`r`nEnter users and groups"
                if ($userAndGroup -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
                $users = GetPendingMigrationUsers -userAndGroup $userAndGroup
            }

            Write-Host "`r`nThe Citrix store path only support path end with %USERNAME%.`r`n" -ForegroundColor Green
            $upmProfileStorePath = Read-Host "Enter path"
            while ((CheckUpmStorePath -upmStorePath $upmProfileStorePath) -eq $false) {
                Write-Host "`r`nThe UPM VHDX store path you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "If you want to exit this tool, please enter exit" -ForegroundColor Green
                $upmProfileStorePath = Read-Host "Enter path"
                if ($upmProfileStorePath -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            DisplayUPMStorePrompts
            $upmVhdxStorePath = Read-Host "Enter path"
            while ((CheckUpmStorePath -upmStorePath $upmVhdxStorePath) -eq $false) {
                Write-Host "`r`nThe Citrix VHDX store path you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "If you want to exit this tool, please enter exit" -ForegroundColor Green
                $upmVhdxStorePath = Read-Host "Enter path"
                if ($upmVhdxStorePath -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            DisplayOsnamePrompts
            $osShortName = Read-Host "Enter short OS name"
            while ((CheckOsShortNameFormat -osShortName $osShortName) -eq $false) {
                Write-Host "`r`nThe vda machine's os short name you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "`r`nIf you want to exit this tool, please enter exit" -ForegroundColor Green
                $osShortName = Read-Host "Enter short OS name"
                if ($osShortName -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }
            
            MigrateUPMProfile -userMembers $users -upmProfileStorePath $upmProfileStorePath -upmVhdxStorePath $upmVhdxStorePath -osShortName $osShortName
            DisplayFutureWork
        }

        3 {
            DisplayUserAndGroupPrompts
            $userAndGroup = Read-Host "Enter users and groups"
            $users = GetPendingMigrationUsers -userAndGroup $userAndGroup
            while ($users -eq $false) {
                Write-Host "`r`nThe user or group format you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "`r`nIf you want to exit this tool, please enter exit" -ForegroundColor Yellow

                $userAndGroup = Read-Host "`r`nEnter users and groups"
                if ($userAndGroup -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
                $users = GetPendingMigrationUsers -userAndGroup $userAndGroup
            }

            DisplayFslogixStorePrompts
            $fslogixVhdxStorePath = Read-Host "Enter path"
            while ((CheckFslogixStorePath -fslogixStorePath $fslogixVhdxStorePath) -eq $false) {
                Write-Host "`r`nThe FSLogix VHDX location you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "If you want to exit this tool, please enter exit" -ForegroundColor Green
                $fslogixVhdxStorePath = Read-Host "Enter path"
                if ($fslogixVhdxStorePath -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            DisplayUPMStorePrompts          
            $upmVhdxStorePath = Read-Host "Enter path"
            while ((CheckUpmStorePath -upmStorePath $upmVhdxStorePath) -eq $false) {
                Write-Host "`r`nThe Citrix Profile Management VHDX store path you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "If you want to exit this tool, please enter exit" -ForegroundColor Green
                $upmVhdxStorePath = Read-Host "Enter path"
                if ($upmVhdxStorePath -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            DisplayOsnamePrompts
            $osShortName = Read-Host "Enter short OS name"     
            while ((CheckOsShortNameFormat -osShortName $osShortName) -eq $false) {
                Write-Host "`r`nThe vda machine's os short name you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "`r`nIf you want to exit this tool, please enter exit" -ForegroundColor Green
                $osShortName = Read-Host "Enter short OS name"
                if ($osShortName -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }
            
            MigrateFSLogixVHDX -userMembers $users -fslogiXVhdxStorePath $fslogixVhdxStorePath -upmVhdxStorePath $upmVhdxStorePath -osShortName $osShortName
            DisplayFutureWork
        }

        4 {
            DisplayUserAndGroupPrompts
            $userAndGroup = Read-Host "`r`nEnter users and groups"
            $usersTobeProcessed = GetPendingMigrationUsers -userAndGroup $userAndGroup
            while ($usersTobeProcessed -eq $false) {
                Write-Host "`r`nThe user or group format you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "`r`nIf you want to exit this tool, please enter exit" -ForegroundColor Yellow

                $userAndGroup = Read-Host "`r`nEnter users and groups"
                if ($userAndGroup -eq "exit") {
                    WriteLog("User input exit")
                    exit
                }
                $usersTobeProcessed = GetPendingMigrationUsers -userAndGroup $userAndGroup
            }

            DisplayFslogixStorePrompts
            $fslogixVhdStorePath = Read-Host "Enter path"
            while ((CheckFslogixStorePath -fslogixStorePath $fslogixVhdStorePath) -eq $false) {
                Write-Host "`r`nThe FSLogix VHD location you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "If you want to exit this tool, please enter exit" -ForegroundColor Green
                $fslogixVhdStorePath = Read-Host "Enter path"
                if ($fslogixVhdStorePath -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            DisplayUPMStorePrompts
            $upmVhdxStorePath = Read-Host "Enter path"
            while ((CheckUpmStorePath -upmStorePath $upmVhdxStorePath) -eq $false) {
                Write-Host "`r`nThe UPM VHDX store path you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "If you want to exit this tool, please enter exit" -ForegroundColor Green
                $upmVhdxStorePath = Read-Host "Please enter the UPM VHDX store path"
                if ($upmVhdxStorePath -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            DisplayOsnamePrompts
            $osShortName = Read-Host "Enter short OS name" 
            while ((CheckOsShortNameFormat -osShortName $osShortName) -eq $false) {
                Write-Host "`r`nThe vda machine's os short name you enter is invalid, please enter again!" -ForegroundColor Red
                Write-Host "`r`nIf you want to exit this tool, please enter exit" -ForegroundColor Green
                $osShortName = Read-Host "Enter short OS name"
                if ($osShortName -eq "exit") {
                    WriteLog("User enter exit")
                    exit
                }
            }

            
            MigrateFSLogixVHD -userMembers $usersTobeProcessed -fslogixVhdStorePath $fslogixVhdStorePath -upmVhdxStorePath $upmVhdxStorePath -osShortName $osShortName
            DisplayFutureWork
        }

        default {
            Write-Host "Please input 1-4" -ForegroundColor Yellow
        }
    }

    WriteLog("Leave the MigrationProfiles")
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    write-host ''Run as administrator' is required for this tool. Exiting ...' -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Exit    
}

ImportModules

DisplayWelcomeInfo

MigrationProfiles
# SIG # Begin signature block
# MIInHwYJKoZIhvcNAQcCoIInEDCCJwwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUV8GSy68P/kPXsRXV/Z9BnXvv
# xNGggiDPMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
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
# DQEJBDEWBBRZBDr8Q+2kyXR79oLvILj48QROpTANBgkqhkiG9w0BAQEFAASCAYB4
# Dix23FHw1oA7TypryFB5d731loAy8CAwDSugdYBl3COsFyz2qowN+02s/W5ocBIK
# FSBS61Mf3u9SOMF+jwL6oeVNR4BMQGXYLwyHDmKail2qHa7gMGM2HRxhA2MTU4d5
# sC41o6/D7NuStFfm0iiCrg1XheA9gBprgikrSZtuG14HJfZMkg1H7RcdbRisuf/9
# bW7t0OJ7DEGzbnNkQN20gQqtVeH8cR5brbXQJp+fDJtLj2OpDMhZy4X0A/jRVNa6
# KPiTSSkCCvyPWh6/K1nvXgWvQnj9CMV1fmEeL74md22P56e8R3cUKMyQTLgRJ8UJ
# lImiI4QeStP/DWrFRrfZBH/fbad0YvbOwbzOLisHlI+Eavvsysc6QIUNmWLqEl64
# s+MA0DJmGkIz9WeqmnUbwBxVYNVLdM4O/YlKbhW3D35PdGqxCwvWyVx/HZs8yGhC
# KW6sasxDS8Fl73FJTzkdaNaeNh0KjUOyUaYsKgGkAY/TFrl/6RrqXcIWrsFafVKh
# ggMgMIIDHAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAMTWlyS5T6PCpK
# PSkHgD1aMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEH
# ATAcBgkqhkiG9w0BCQUxDxcNMjMwNzI3MDgxMDM2WjAvBgkqhkiG9w0BCQQxIgQg
# 9VidE2KPvIXws4Tk14K8gz5x5UomjyvtZLsjTyBo5FowDQYJKoZIhvcNAQEBBQAE
# ggIAwjnHcfKRlwxvPCNDg68inqcJVcP62ANu64OvYdKPCyR/8mvoyAsNzvbZEBBP
# UR7/p+5K+lf+XYVg5OcmMYEiNEjSqddJzNJYha2Rwhdj4ucKKRqeMt657DpUHVaY
# 3QEbPsQU5eWLo+FA9wSYfveTzvjoRSYKx8W4D/TA3eB106d2AMcBDSV+NXG49vs3
# IcJFKQ33wF+/9K4DU94/jkzHTxAvmVCfcUqk9GKPWjMV2hBjGudKvuvumuxIIDv4
# nVvTc0fec4y5i8Lg/9QY4R2Ka8yQsmEG3t8M9gJ9mNi43AmjA0HH/aOS1AYjDhL1
# mubMrPcPmAKfyPyP8T342Ct7oTIo7jCNnrVuxGBHzR0EFFP4ZeMmpukd8OwoEOeF
# osoDWXFI/cxlmsCe/ceu3a/CIh4DxTljS/bxIuB/pWoiVpmvGQLPpMnBz+iTqLdA
# 4sN4QmSyv0Z6qH2sqBrDb/8I1f/UaHUBZ/CzfjU2AWLFQId2cca0aFHYbbKjMEie
# FYcNP32Ub4P2BAoxDKbNz/A8UhW49ynyrBmkr8Ej9wku787daaKEbuQB78sgzhbu
# w9oxdS0U3Y+vg4hwQ5+k1vbDkq3gYn2n6HBx4qdEjBOknJ3l5mJZVvZYDuE9jFfi
# PEBb1dSaJ0D8hAUxrc2m0Echj9qZhP8AKIdWZySKt/jX7GQ=
# SIG # End signature block
