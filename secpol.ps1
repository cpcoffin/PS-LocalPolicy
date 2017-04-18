
Function Translate-SIDsToPrincipalNames($SIDs)
{
    If (($SIDs -eq '') -or ($SIDs -eq 'No One') -or ($SIDs -eq $Null))
    {
        return ''
    }
    return ($SIDs -Split ',' | ForEach {
        If ($_ -match '^\*?S-\d*-\d*-\d*[-\d]*$')  # note preceding * is optional in this one
        {
            $SID = $_.Trim('* ')
            Try
            {
                $Name = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value
                If ($Name.Contains('\'))
                {
                    $Name = ($Name -Split '\\')[1]
                }
                $Name
            }
            Catch
            {
                Write-Warning "Could not obtain name from $SID - will not be included with $($setting.ura_right)."
            }
        }
        Else
        {
            $_
        }
    }) -join ','
}

Function Translate-PrincipalNamesToSIDs($Principals)
{
    If (($Principals -eq '') -or ($Principals -eq 'No One') -or ($Principals -eq $Null))
    {
        return ''
    }
    return ($Principals -Split ',' | ForEach {
        If (($_ -ne '') -and ($_ -notmatch '^\*S-\d*-\d*-\d*[-\d]*$'))
        {
            $PrincipalName = $_.Trim()
            If ($PrincipalName -in @('Guest','Administrator'))
            {
                $PrincipalName = "$env:ComputerName\$PrincipalName"
            }
            Try
            {
                "*$((New-Object System.Security.Principal.NTAccount($PrincipalName)).Translate([System.Security.Principal.SecurityIdentifier]).Value)"
            }
            Catch
            {
                Try
                {   # sloppy!!
                    $Substitutions = @{"$env:ComputerName\Guest" = 'DisabledGuest';
                                       'DisabledGuest' = '$env:ComputerName\Guest';
                                       "$env:ComputerName\Administrator" = 'DisabledAdmin';
                                       'DisabledAdmin' = '$env:ComputerName\Administrator'
                                      }
                    "*$((New-Object System.Security.Principal.NTAccount($($Substitutions[$PrincipalName]))).Translate([System.Security.Principal.SecurityIdentifier]).Value)"
                }
                Catch
                {
                    Write-Warning "Could not obtain SID for $PrincipalName - will not be included with $($setting.ura_right)."
                }
            }
        }
        Else
        {
            $_
        }
    }) -join ','
}


# Applies or reverts the policy settings specified in a Policy Settings CSV.
# In order to revert settings, prior values must be included in the CSV (e.g. from New-PolicyRemediationFileForLocalSystem)
#
# Reg keys are applied directly, not updated in the local policy store. This is much faster and should be fine for
# troubleshooting, which is the primary purpose this function is intended for.
#
# But to support user settings we have to run a script at logon
#
# Skips all sanity checks and assumes settings are fully paresable. As such this should only be run against $SuccessFile
# from Get-LGPOFilesFromPolicySettingsCsv
Function Set-LocalPolicyFromSettingsPolicyCsv
{
    Param([Parameter(Mandatory)]
          [string]$CsvFile,
          [Parameter(Mandatory)]
          [ValidateSet('Apply','Revert')]
          [string]$Action
         )

    If (Test-Path ("$ProgramFolder\UserLogonSettings.csv"))
    {
        $script:UserSettings = Import-Csv "$ProgramFolder\UserLogonSettings.csv"
    }
    Else
    {
        $script:UserSettings = @()
    }
    $RunUserSettingsTask = $False
    
    Function Set-RegValue([Parameter(Mandatory)]$SettingID, $Hive, $Key, $Value, $Type, $Data, [switch]$Delete)
    {
        If ($Data -eq $Null)
        {
            $Data = ''
        }
        $Types = @{'number' = 'REG_DWORD'; 'string' = 'REG_SZ'; 'expandstring' = 'REG_EXPAND_SZ'; 'multistring' = 'REG_MULTI_SZ'}
        If (($Type -notin $Types.Keys) -and (-not $Delete))
        {
            throw "Bad registry type $Type for $Key : $Value"
        }
        If (($Hive -eq 'HKEY_CURRENT_USER') -or ($Hive -eq 'HKEY_USERS'))
        {
            # Update the list of per-user settings that are set by scheduled task
            Set-Variable -Name 'RunUserSettingsTask' -Value $True -Scope 1
            If ($Delete) { $Op = 'delete' } Else { $Op = 'equals' }
            $Matched = $False
            ForEach ($Setting In $script:UserSettings)
            {
                If (($Setting.Key -eq $Key) -and ($Setting.Value -eq $Value))
                {
                    $Matched = $True
                    $Setting.Type = $Type
                    $Setting.Data = $Data
                    $Setting.Op = $Op
                }
            }
            If (-not $Matched)
            {
                $script:UserSettings = @($script:UserSettings) +
                        @([pscustomobject]@{  'Key'   = $Key;
                                              'Value' = $Value;
                                              'Type'  = $Type;
                                              'Data'  = $Data
                                              'Op'    = $Op
                                           })
            }
        }
        Else
        {
            $Path = "HKLM:\$Key"
            If ($Delete)
            {
                Remove-ItemProperty -Path $Path -Name $Value -ErrorAction SilentlyContinue
            }
            Else
            {
                #Write-Host "Set $Path : $Value to $Data"
                If (-not (Test-Path $Path))
                {
                    New-Item -Path $Path -Force  -ErrorAction Stop | Out-Null
                }
                If ($Type -eq 'number')
                {
                    Set-ItemProperty -Path $Path -Name $Value -Value ([int]$Data) -Type DWord -ErrorAction Stop
                }
                ElseIf ($Type -eq 'string')
                {
                    Set-ItemProperty -Path $Path -Name $Value -Value ([string]$Data) -Type String -ErrorAction Stop
                }
                ElseIf ($Type -eq 'expandstring')
                {
                    Set-ItemProperty -Path $Path -Name $Value -Value ([string]$Data) -Type ExpandString -ErrorAction Stop
                }
                ElseIf ($Type -eq 'multistring')
                {
                    Set-ItemProperty -Path $Path -Name $Value -Value ([string[]]($Data.Replace('\0',"`0").Split("`0"))) -Type MultiString -ErrorAction Stop
                }
                Else
                {
                    throw "Bad registry type $Type"
                }
            }
        }
    }

    If (-not (Test-Path $CsvFile))
    {
        throw "$CsvFile does not exist."
    }
    If ($Action -eq 'Apply')
    {
        $CsvSavePath = "$ProgramFolder\LastAppliedSettings-SetToRemediated.csv"
        $CsvDeletePath = "$ProgramFolder\LastAppliedSettings-SetToPriorValues.csv"
    }
    Else
    {
        $CsvSavePath = "$ProgramFolder\LastAppliedSettings-SetToPriorValues.csv"
        $CsvDeletePath = "$ProgramFolder\LastAppliedSettings-SetToRemediated.csv"
    }
    
    If (-not (Test-Path "$ProgramFolder\LGPO.exe"))
    {
        Write-Host "Please create folder $ProgramFolder with LGPO.exe" -ForegroundColor Red
        return
    }

    Push-Location "$ProgramFolder"
    
    If (Test-Path $CsvDeletePath)
    {
        Remove-Item $CsvDeletePath -Force -ErrorAction Stop
    }
    If ((-not (Test-Path $CsvSavePath)) -or ((Get-Item $CsvFile).FullName -ne (Get-Item $CsvSavePath).FullName))
    {
        Copy-Item $CsvFile $CsvSavePath -Force
    }
    
    If (Test-Path "$ProgramFolder\Temp")
    {
        Remove-Item "$ProgramFolder\Temp" -Recurse -Force
    }
    New-Item "$ProgramFolder\Temp" -Type Directory | Out-Null
    
    $RegSet = 0
    If ($Action -eq 'Apply')
    {
        Import-Csv $CsvFile | ForEach {
            If ($_.type -eq 'Registry')
            {
                If ($_.reg_op -eq 'delete')
                {
                    Set-RegValue -SettingID $_.cis_idref -Hive $_.reg_hive -Key $_.reg_key -Value $_.reg_value -Delete -WarningAction SilentlyContinue -ErrorAction Stop
                }
                Else
                {
                    Set-RegValue -SettingID $_.cis_idref -Hive $_.reg_hive -Key $_.reg_key -Value $_.reg_value -Type $_.reg_type -Data $_.reg_data -WarningAction SilentlyContinue -ErrorAction Stop
                }
                $RegSet++
            }
            Else
            {
                $_ | Add-Member -NotePropertyName 'Purpose' -NotePropertyValue 'Include' -Force -PassThru
            }
        } | Export-Csv "$ProgramFolder\Temp\Local-SettingsToProcess.csv"
    }
    Else
    {
        $AuditSetting = $false
        Import-Csv $CsvFile | ForEach {
            If (($_.PriorCompliance -eq $Null) -or ($_.ValueExistedPrior -eq $Null))
            {
                throw "No prior info for $($_.cis_idref)"
            }
            If ($_.type -eq 'SecurityOption')
            {
                $_ | Add-Member -NotePropertyName 'so_value' -NotePropertyValue $_.PriorValue -Force -PassThru | Add-Member -NotePropertyName 'Purpose' -NotePropertyValue 'Include' -Force -PassThru
            }
            ElseIf ($_.type -eq 'UserRightsAssignment')
            {
                $_ | Add-Member -NotePropertyName 'ura_principals' -NotePropertyValue $_.PriorValue -Force -PassThru | Add-Member -NotePropertyName 'Purpose' -NotePropertyValue 'Include' -Force -PassThru
            }
            ElseIf ($_.type -eq 'AdvancedAudit')
            {
                $AuditSetting = $true
            }
            ElseIf ($_.type -eq 'Registry')
            {
                <# Apply with LGPO
                If ($_.ValueExistedPrior -eq 'FALSE')
                {
                    $_ | Add-Member -NotePropertyName 'reg_op' -NotePropertyValue 'delete' -Force -PassThru | Add-Member -NotePropertyName 'Purpose' -NotePropertyValue 'Include' -Force -PassThru
                }
                Else
                {
                    $_ | Add-Member -NotePropertyName 'reg_data' -NotePropertyValue $_.PriorValue -Force -PassThru | Add-Member -NotePropertyName 'Purpose' -NotePropertyValue 'Include' -Force -PassThru
                }
                #>
                # Apply directly (little trickier, much faster)
                If ($_.ValueExistedPrior -eq 'FALSE')
                {
                    Set-RegValue -SettingID $_.cis_idref -Hive $_.reg_hive -Key $_.reg_key -Value $_.reg_value -Delete -WarningAction SilentlyContinue -ErrorAction Stop
                }
                Else
                {
                    Set-RegValue -SettingID $_.cis_idref -Hive $_.reg_hive -Key $_.reg_key -Value $_.reg_value -Type $_.reg_type -Data $_.PriorValue -WarningAction SilentlyContinue -ErrorAction Stop
                }
                $RegSet++
            }
            Else
            {
                throw "Unexpected setting type $($_.type)"
            }
        } | Export-Csv "$ProgramFolder\Temp\Local-SettingsToProcess.csv"
    }

    If ($RunUserSettingsTask)
    {
        If (Test-Path "$ProgramFolder\UserPolicyProcessed.txt")
        {
            Remove-Item "$ProgramFolder\UserPolicyProcessed.txt" -Force -ErrorAction Stop
        }
        $UserSettings | Export-Csv "$ProgramFolder\UserLogonSettings.csv"

        # Load hives for any existing users and run the scheduled task to apply user reg
        # settings, eliminating the need for it to run after the users have logged on.
        If ('HKU' -notin (Get-PSDrive).Name)
        {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
        }
        $UserHivesLoaded = @()
        Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach {
            $SID = Split-Path $_.Name -Leaf
            $Profile = $_ | Get-ItemPropertyValue -Name ProfileImagePath
            If ($SID -match '^S-1-5-21-\d{9,10}-\d{9,10}-\d{9,10}-\d{4,5}$' -and (-not (Test-Path "HKU:\$SID")))
            {
                reg load "HKU\$SID" "$Profile\ntuser.dat" > "$env:Temp\regloadresult.txt" 2>&1
                If (Get-Content "$env:Temp\regloadresult.txt" | Select-String 'The operation completed successfully.')
                {
                    $UserHivesLoaded += $SID
                }
            }
        }
        
        & "$ProgramFolder\SchTask-UserSettings.ps1"
        
        [GC]::Collect()
        ForEach ($Hive In $UserHivesLoaded)
        {
            reg unload "HKU\$Hive"
        }
    }
    
    Write-Host "$RegSet reg settings applied."

    If ((Import-Csv "$ProgramFolder\Temp\Local-SettingsToProcess.csv" | Measure-Object).Count -gt 0)
    {
        Get-LGPOFilesFromPolicySettingsCsv -FilePrefix 'Local' -WorkingDir "$ProgramFolder\Temp" -WarningAction Continue
        If (Get-GpoBackupFromLGPOFiles -FilePrefix 'Local' -WorkingDir "$ProgramFolder\Temp")
        {
            Apply-GpoBackup -FolderPath "$ProgramFolder\Temp"
        }
    }
    
    # Give the system a chance to register changes - maybe not necessary now that we're setting reg keys directly
    #Start-Sleep -Seconds 5
    Pop-Location
    
}

# Compares the settings in a Policy Settings CSV to the local system. Outputs the settings with new fields ValueExistedPrior
# (always True except for Registry settings), PriorValue, and PriorCompliance (TRUE if the setting is already compliant).
# If PriorCompliance does not match the cis_outcome field, a warning is generated. This is for sanity checking if you were
# to run the CIS-CAT, generate a Settings CSV from the result, then run this function against the same system without making
# any changes. Otherwise these warnings should be ignored.
# This should only be run against $SuccessFile from Get-LGPOFilesFromPolicySettingsCsv, since those entries are
# guaranteed to be parseable.
Function Test-PolicySettingsCsvAgainstLocalSystem
{
    Param([Parameter(Mandatory)][string]$CsvFile)

    If (-not (Test-Path "$ProgramFolder\LGPO.exe"))
    {
        $LGPO = $Null
        If (Test-Path 'LGPO.exe')
        {
            $LGPO = 'LGPO.exe'
        }
        ElseIf (Test-Path (Join-Path (Split-Path $CsvFile) 'LGPO.exe'))
        {
            $LGPO = Join-Path (Split-Path $CsvFile) 'LGPO.exe'
        }
        If ($LGPO -ne $Null)
        {
            If (-not (Test-Path $ProgramFolder))
            {
                New-Item -Path $ProgramFolder -Type Directory -Force -ErrorAction Stop
            }
            Copy-Item $LGPO $ProgramFolder -ErrorAction Stop
        }
        Else
        {
            Write-Host "Can not find LGPO.exe" -ForegroundColor Red
            return
        }
    }
    
    Function Read-Inf($InfFile)
    {
        $Result = @{}
        $Section = ''
        Get-Content $InfFile | ForEach {
            If ($_ -match '\[(.*)\]')
            {
                $Section = $matches[1]
            }
            Else
            {
                If ($Result[$Section] -eq $null)
                {
                    $Result[$Section] = @{}
                }
                $Name,$Value = $_.Split('=').Trim(' ')
                $Result[$Section][$Name] = $Value
            }
        }
        return $Result
    }
    
    & "$ProgramFolder\LGPO.exe" /b "$ProgramFolder" > "$ProgramFolder\lgporesult.txt" 2>&1
    $Pattern = "$($ProgramFolder.Replace('\','\\'))\\\{.*\}"
    $PolicyBackup = (Get-Content "$ProgramFolder\lgporesult.txt" | Select-String -Pattern $Pattern).Matches[0]
    $LocalSecurityInfo = Read-Inf "$PolicyBackup\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
    Remove-Item -Path $PolicyBackup -Recurse -Force
    
    $HiveNames = @{'HKEY_LOCAL_MACHINE' = 'HKLM'; 'HKEY_USERS' = 'HKCU'; 'HKEY_CURRENT_USER' = 'HKCU'}
    $Settings = Import-Csv $CsvFile
    $Settings | ForEach {
        If ($_.type -eq 'AdvancedAudit')
        {
            Write-Warning "Ignoring audit policy setting - not implemented"
            return
        }
        If ($_.type -eq 'Registry')
        {
            $Key = "$($HiveNames[$_.reg_hive]):$($_.reg_key)"
            Try
            {
                $CurrentValue = Get-ItemPropertyValue -Path $Key -Name $_.reg_value -ErrorAction Stop
                $Exists = $True
                # Join multi-string values with the delimiter used by LGPO.exe
                If ($CurrentValue -is [array])
                {
                    $CurrentValue = $CurrentValue -join '\0'
                }
            }
            Catch
            {
                $CurrentValue = ''
                $Exists = $False
            }
            $Compliant = ($_.reg_op -eq 'delete' -and (-not $Exists)) -or ($Exists -and ($CurrentValue -eq $_.reg_data))

        }
        ElseIf ($_.type -eq 'SecurityOption')
        {
            If (($LocalSecurityInfo[$_.so_infsection] -eq $null) -or ($LocalSecurityInfo[$_.so_infsection][$_.so_name] -eq $null))
            {
                throw "No entry for security option $($_.so_infsection) - $($_.so_name) ...not sure how to proceed!!"
            }
            $Exists = $True
            $CurrentValue = $LocalSecurityInfo[$_.so_infsection][$_.so_name]
            $Compliant = $CurrentValue -eq $_.so_value
        }
        ElseIf ($_.type -eq 'UserRightsAssignment')
        {
            $Exists = $True
            $CurrentValue = Translate-SIDsToPrincipalNames $LocalSecurityInfo['Privilege Rights'][$_.ura_right] -WarningAction Continue
            $CurrentValueTranslated = Translate-PrincipalNamesToSIDs $LocalSecurityInfo['Privilege Rights'][$_.ura_right] -WarningAction Continue
            $ExpectedValueTranslated = Translate-PrincipalNamesToSIDs $_.ura_principals -WarningAction Continue
            $Compliant = [bool]((Compare-Object $ExpectedValueTranslated.Split(',') $CurrentValueTranslated.Split(',')) -eq $null)
        }
        
        If ($Compliant -and ($_.cis_outcome -eq 'Fail'))
        {
            Write-Warning "Setting listed as non-compliant by the CIS report is compliant on this system. ID: $($_.cis_idref)"
        }
        If ((-not $Compliant) -and ($_.cis_outcome -eq 'Pass'))
        {
            Write-Warning "Setting listed as compliant by the CIS report is non-compliant on this system. ID: $($_.cis_idref)"
        }
        # cast to strings so the output can be directly compared to objects created by import-csv
        $_ | Add-Member -NotePropertyName 'ValueExistedPrior' -NotePropertyValue ([string]$Exists) -Force -PassThru |
             Add-Member -NotePropertyName 'PriorValue' -NotePropertyValue ([string]$CurrentValue) -Force -PassThru |
             Add-Member -NotePropertyName 'PriorCompliance' -NotePropertyValue ([string]$Compliant) -Force -PassThru
    }
}


# Generate master policy file from the base policy file and any add-on policy files present in $AddonPoliciesFolder
Function Generate-MasterPolicyFile
{
    $OutFile = "$MasterPolicyFile.new"
    If (Test-Path $OutFile)
    {
        Remove-Item $OutFile -Force
    }
    If (Test-Path $AddonPoliciesFolder)
    {
        $PolicyFiles = @((Get-ChildItem -Path $AddonPoliciesFolder -Filter '*.csv').FullName)
    }
    Else
    {
        $PolicyFiles = @()
    }
    $PolicyFiles += @($BasePolicyFile)
    
    $Settings = @()
    $id = 0
    $PolicyFiles | ForEach {
        Import-Csv $_ | ForEach {
            $Summary = "$($_.type);$($_.ura_right);$($_.audit_category);$($_.so_cisname);$($_.so_infsection);$($_.so_name);$($_.reg_hive);$($_.reg_key);$($_.reg_value);$($_.reg_type)"
            If ($Summary -notin $Settings)
            {
                $Settings += $Summary
                $_ | Add-Member -NotePropertyName cis_idref -NotePropertyValue $id -Force -PassThru
                $id++
            }
        } | Export-Csv $OutFile -Append
    }
    
    If (Test-Path $MasterPolicyFile)
    {
        Remove-Item $MasterPolicyFile -Force
    }
    Rename-Item -Path $OutFile -NewName $MasterPolicyFile
}

# Revert the existing master policy, regenerate it from the base and add-on policy files, and reapply
Function Update-Policy
{
    # Since settings in UserLogonSettings.csv are not removed in any other scenario, we clear the file now.
    # If the call to Set-LocalPolicyFromSettingsPolicyCsv somehow failed to load and update an existing user's registry
    # hive, this means the setting will never be reverted for that user. But that should not normally be the case.
    If (Test-Path "$ProgramFolder\UserLogonSettings.csv")
    {
        Remove-Item "$ProgramFolder\UserLogonSettings.csv" -Force
    }
    Copy-Item -Path $MasterPolicyFile -Destination "$MasterPolicyFile.old"
    Write-Host 'Generating new master policy'
    Generate-MasterPolicyFile
    Write-Host 'Reverting old policy'
    Set-LocalPolicyFromSettingsPolicyCsv -CsvFile "$MasterPolicyFile.old" -Action 'Revert' -WarningAction SilentlyContinue
    Write-Host 'Applying new policy'
    Set-LocalPolicyFromSettingsPolicyCsv -CsvFile $MasterPolicyFile -Action 'Apply' -WarningAction SilentlyContinue
    Remove-Item "$MasterPolicyFile.old"
}

# Verify that Local Policy Testing is installed on this system. Otherwise exit with error 10.
Function Assert-Installed
{
    @($MasterPolicyFile,
      "$ProgramFolder\LGPO.exe",
      "$ProgramFolder\DPSSecurityPolicy.ps1",
      "$ProgramFolder\SchTask-UserSettings.ps1",
      "$env:SystemDrive\Install\Troubleshoot Local Policy.cmd"
    ) | ForEach {
        If (-not (Test-Path $_))
        {
            Write-Host 'Existing policy or supporting files not found.'
            Exit 10
        }
    }
    If ((schtasks /query /tn 'Local Policy Testing - User Settings' | Select-String 'Ready') -eq $Null)
    {
        Write-Host 'User settings task missing or disabled'
        Exit 10
    }
}


Function Troubleshoot-Policy
{
    $TroubleshootingStatusFile = "$ProgramFolder\TroubleshootingStatus.xml"
    $script:SuggestReboot = $True
    $script:WackyReverse = $False
    $ExpectedSettingStatus = $null
    $ActualSettingStatus = $null
    # These are overridden by GPO (and should have been excluded from the policy list for that reason). Ignore them.
    $SettingsOverriddenByGPO = @() <#'HKEY_LOCAL_MACHINE:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile : DisableNotifications',
                                 'HKEY_LOCAL_MACHINE:\Software\Policies\Microsoft\Windows NT\Rpc : EnableAuthEpResolution',
                                 'HKEY_LOCAL_MACHINE:\Software\Policies\Microsoft\Windows\EventLog\Security : MaxSize',
                                 'HKEY_LOCAL_MACHINE:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services : MinEncryptionLevel',
                                 'HKEY_LOCAL_MACHINE:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU : NoAutoUpdate',
                                 'HKEY_LOCAL_MACHINE:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile : DisableNotifications',
                                 'HKEY_LOCAL_MACHINE:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile : AllowLocalPolicyMerge',
                                 'HKEY_LOCAL_MACHINE:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU : ScheduledInstallDay',
                                 'HKEY_CURRENT_USER:\Software\Policies\Microsoft\Internet Explorer\Control Panel : FormSuggest')#>
    $IDsToIgnore = @()
    $MasterPolicy = Import-Csv $MasterPolicyFile | ForEach {
        If ("$($_.reg_hive):\$($_.reg_key) : $($_.reg_value)" -notin $SettingsOverriddenByGPO)
        {
            $_
        }
        Else
        {
            $IDsToIgnore += $_.cis_idref
        }
    }
    
    Function Get-TroubleshootingStatistics($Status)
    {
        $Statistics = @{'TotalSettings' = $Status.Count;
                        'AppliedFinal' = ($Status.Values | Where {$_ -eq 'Applied'}).Count;
                        'JustApplied' = ($Status.Values | Where {$_ -eq 'JustApplied'}).Count;
                        'TotalReverted' = ($Status.Values | Where {$_ -eq 'Reverted'}).Count
                       }
        $Statistics['TotalApplied'] = $Statistics['AppliedFinal'] + $Statistics['JustApplied']
        $Statistics['PercentApplied'] = [int]((($Statistics['TotalApplied'])/($Statistics.TotalSettings))*100)
        return $Statistics
    }

    Function Display-Setting($Setting)
    {
        If ($Setting.type -eq 'Registry')
        {
            Write-Host "Registry Hive:       $($Setting.reg_hive)"
            Write-Host "Registry Key:        $($Setting.reg_key)"
            Write-Host "Registry Value Name: $($Setting.reg_value)"
            Write-Host "Compliant Value:     $($Setting.reg_data)"
            If ($Setting.ExistedPrior -eq 'FALSE')
            {
                Write-Host "Original Value:      (Did not exist)"
            }
            Else
            {
                Write-Host "Original Value:      $($Setting.PriorValue)"
            }
        }
        ElseIf ($Setting.type -eq 'UserRightsAssignment')
        {
            Write-Host "User Right Name:     $($Setting.ura_right)"
            Write-Host "Compliant Value:     $($Setting.ura_principals)"
            Write-Host "Original Value:      $($Setting.PriorValue)"
        }
        ElseIf ($Setting.type -eq 'SecurityOption')
        {
            Write-Host "INF Section:         $($Setting.so_infsection)"
            Write-Host "Setting Name:        $($Setting.so_name)"
            Write-Host "Compliant Value:     $($Setting.so_value)"
            Write-Host "Original Value:      $($Setting.PriorValue)"
        }
    }

    Function Get-ActualSettingStatus
    {
        If ($MasterPolicy.Count -eq 0)
        {
            throw 'Master Policy Remediation CSV is empty.'
        }
        $CurrentSettingStatus = Test-PolicySettingsCsvAgainstLocalSystem $MasterPolicyFile -WarningAction SilentlyContinue | Where cis_idref -notin $IDsToIgnore
        #Write-Host "Get-actualsettingstatus... $($CurrentSettingStatus.Count) settings"
        #Write-Host "$(($CurrentSettingStatus | Where PriorCompliance -eq 'True').Count) compliant settings"
        $PolicyStatus = @{}
        ForEach ($i In 0..($MasterPolicy.Count-1))
        {
            If ($CurrentSettingStatus[$i].type -eq 'AdvancedAudit')
            {
                throw 'Audit settings are not supported.'
            }
            If ($MasterPolicy[$i].cis_idref -ne $CurrentSettingStatus[$i].cis_idref)
            {
                throw 'Somehow lost sync comparing master policy to Test-PolicySettingsCsvAgainstLocalSystem. Who wrote this script anyway?!?'
            }
            If ($CurrentSettingStatus[$i].PriorCompliance -eq 'True')
            {
                $PolicyStatus[$CurrentSettingStatus[$i].cis_idref] = 'Applied'
                If ($script:WackyReverse)
                {
                    $PolicyStatus[$CurrentSettingStatus[$i].cis_idref] = 'Reverted'
                }
            }
            ElseIf (($CurrentSettingStatus[$i].ValueExistedPrior -eq $MasterPolicy[$i].ValueExistedPrior) -and
                    (($CurrentSettingStatus[$i].PriorValue -eq $MasterPolicy[$i].PriorValue) -or
                     ($CurrentSettingStatus[$i].PriorValue.Replace('DisabledAdmin','Administrator').Replace('DisabledGuest','Guest') -eq
                      $MasterPolicy[$i].PriorValue.Replace('DisabledAdmin','Administrator').Replace('DisabledGuest','Guest'))))
            {
                $PolicyStatus[$CurrentSettingStatus[$i].cis_idref] = 'Reverted'
                If ($script:WackyReverse)
                {
                    $PolicyStatus[$CurrentSettingStatus[$i].cis_idref] = 'Applied'
                }
            }
            Else
            {
                Write-Host 'Unexpected value.' -ForegroundColor Red
                Display-Setting $MasterPolicy[$i]
                Write-Host 'Current Value:       ' -NoNewLine
                If ($CurrentSettingStatus[$i].ExistedPrior -eq 'FALSE')
                {
                    Write-Host '(Does not exist)' -ForegroundColor Red
                }
                Else
                {
                    Write-Host "$($CurrentSettingStatus[$i].PriorValue)" -ForegroundColor Red
                }
                throw 'Unexpected setting value'
            }
        }
        
        return $PolicyStatus
    }

    Function Get-ExpectedSettingStatus
    {
        If (-not (Test-Path $TroubleshootingStatusFile))
        {
            return $null
        }
        
        $Status = Import-CliXml $TroubleshootingStatusFile
        If ($Status.Count -ne $MasterPolicy.Count)
        {
            Write-Warning 'Deleting invalid status file.'
            Remove-Item $TroubleshootingStatusFile -Force
            return $null
        }
        ForEach ($Setting In $MasterPolicy)
        {
            If (($Status[$Setting.cis_idref] -eq $Null) -or
                ($Status[$Setting.cis_idref] -notin @('JustApplied','Applied','Reverted')))
            {
                Write-Warning 'Deleting invalid status file.'
                Remove-Item $TroubleshootingStatusFile -Force
                return $null
            }
        }
        
        return $Status
    }
    
    Function Suggest-Reboot
    {
        If ($script:SuggestReboot)
        {
            Write-Host 'Setting(s) applied. A reboot may be required for them to take effect.' -ForegroundColor Green
            Write-Host 'Would you to reboot now? This script will be scheduled to run at logon.'
            $Response = Read-Host 'Y/N'
            If (($Response -ne 'y') -and ($Response -ne 'yes'))
            {
                $script:SuggestReboot = $False
                Write-Host 'Reboot prompt suppressed for current run of this script.' -ForegroundColor Red
                Write-Host
                return
            }
            Perform-Reboot
        }
    }
    
    Function Perform-Reboot
    {
        Install-LocalPolicyTesting
        If (-not (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'))
        {
            New-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Force | Out-Null
        }
        New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'TroubleshootLocalPolicy' -Value "$env:SystemDrive\Install\Troubleshoot Local Policy.cmd" | Out-Null
        Restart-Computer -Force
    }
    
    Function Change-Settings($NewSettingStatus)
    {
        Remove-Item "$ProgramFolder\ToApply.csv" -Force -ErrorAction SilentlyContinue
        Remove-Item "$ProgramFolder\ToRevert.csv" -Force -ErrorAction SilentlyContinue
        $MasterPolicy | ForEach {
            If ($NewSettingStatus[$_.cis_idref] -like '*Applied')
            {
                $_ | Export-Csv "$ProgramFolder\ToApply.csv" -Append
            }
            ElseIf ($NewSettingStatus[$_.cis_idref] -eq 'Reverted')
            {
                $_ | Export-Csv "$ProgramFolder\ToRevert.csv" -Append
            }
        }
        Write-Host 'Setting local policy...' -ForegroundColor Yellow
        If (Test-Path "$ProgramFolder\ToApply.csv")
        {
            $Action = 'Apply'
            If ($script:WackyReverse)
            {
                $Action = 'Revert'
            }
            Set-LocalPolicyFromSettingsPolicyCsv "$ProgramFolder\ToApply.csv" -Action $Action -WarningAction SilentlyContinue
            Remove-Item "$ProgramFolder\ToApply.csv" -Force -ErrorAction SilentlyContinue
        }
        If (Test-Path "$ProgramFolder\ToRevert.csv")
        {
            $Action = 'Revert'
            If ($script:WackyReverse)
            {
                $Action = 'Apply'
            }
            Set-LocalPolicyFromSettingsPolicyCsv "$ProgramFolder\ToRevert.csv" -Action $Action -WarningAction SilentlyContinue
            Remove-Item "$ProgramFolder\ToRevert.csv" -Force -ErrorAction SilentlyContinue
        }
        Write-Host 'Complete' -ForegroundColor Yellow
        Write-Host
        Write-Host
        Suggest-Reboot
    }
    
    $Operations = @{'working' = {
                        $RemainingSettings = ($ExpectedSettingStatus.Keys | Where {$ExpectedSettingStatus[$_] -eq 'Reverted'})
                        If ($RemainingSettings.Count -eq 0)
                        {
                            Write-Host 'All settings are applied. Have you tried rebooting? If the problem still' -ForegroundColor Red
                            Write-Host 'is not occurring, there must be something else causing it.' -ForegroundColor Red
                            Set-Variable -Name 'Run' -Value $False -Scope 1
                            return
                        }
                        ElseIf ($RemainingSettings.Count -eq 1)
                        {
                            Write-Host 'Only one setting left to apply. Assuming there is a single setting that ' -ForegroundColor Green
                            Write-Host 'causes the problem, this must be it!' -ForegroundColor Green
                            Write-Host
                            Display-Setting ($MasterPolicy | Where cis_idref -eq $RemainingSettings)
                            Write-Host
                            Write-Host 'This setting will now be applied. Please verify that this makes the problem' -ForegroundColor Magenta
                            Write-Host 'reappear, then report the setting details to sccm@dps.ohio.gov, along with a' -ForegroundColor Magenta
                            Write-Host 'description of the problem and affected group of users.' -ForegroundColor Magenta
                        }
                        ElseIf ($RemainingSettings.Count -eq 2)
                        {
                            Write-Host 'Only two settings are left to try! Applying the following setting. If the' -ForegroundColor Green
                            Write-Host 'problem occurs again, this must be the cause:' -ForegroundColor Green
                            Write-Host
                            Display-Setting ($MasterPolicy | Where cis_idref -eq $RemainingSettings[1])
                            Write-Host
                            Write-Host 'If not, it must be the other one (you should still apply it to make sure):' -ForegroundColor Green
                            Write-Host
                            Display-Setting ($MasterPolicy | Where cis_idref -eq $RemainingSettings[0])
                            Write-Host
                            Write-Host 'Once you have verified, please report the setting details to' -ForegroundColor Magenta
                            Write-Host 'sccm@dps.ohio.gov, along with a description of the problem and' -ForegroundColor Magenta
                            Write-Host 'affected group of users.' -ForegroundColor Magenta
                        }
                        Else
                        {
                            Write-Host "Applying $([Math]::Ceiling($RemainingSettings.Count/2)) settings." -ForegroundColor Green
                        }
                        
                        $Changes = @{}
                        $SetToApplied = $ExpectedSettingStatus.Keys | Where {$ExpectedSettingStatus[$_] -eq 'JustApplied'}
                        $SetToApplied | ForEach {
                            $ExpectedSettingStatus[$_] = 'Applied'
                        }
                        @($RemainingSettings)[[Math]::Floor($RemainingSettings.Count/2)..$RemainingSettings.Count] | ForEach {
                            $ExpectedSettingStatus[$_] = 'JustApplied'
                            $Changes[$_] = 'Applied'
                        }
                        $ExpectedSettingStatus | Export-CliXml $TroubleshootingStatusFile
                        
                        Change-Settings $Changes
                        Write-Host 'Changes complete. You can start testing now.' -ForegroundColor Magenta
                        Write-Host
                    };
                    'broken' = {
                        $JustApplied = $ExpectedSettingStatus.Keys | Where {$ExpectedSettingStatus[$_] -eq 'JustApplied'}
                        If ($JustApplied.Count -eq 0)
                        {
                            Write-Host 'Not sure how you got here...all settings are already applied.' -ForegroundColor Red
                            Write-Host 'Please revert all settings and start over.' -ForegroundColor Red
                            Write-Host
                            return
                        }
                        
                        $Changes = @{}
                        $SetToApplied = $ExpectedSettingStatus.Keys | Where {$ExpectedSettingStatus[$_] -eq 'Reverted'}
                        $SetToApplied | ForEach {
                            $ExpectedSettingStatus[$_] = 'Applied'
                            $Changes[$_] = 'Applied'
                        }
                        
                        If ($JustApplied.Count -eq 1)
                        {
                            Write-Host 'Troubleshooting Complete! The following setting is causing the problem:' -ForegroundColor Green
                            Display-Setting ($MasterPolicy | Where cis_idref -eq $JustApplied)
                            Write-Host
                            Write-Host 'Please report the setting details to sccm@dps.ohio.gov, along with a' -ForegroundColor Magenta
                            Write-Host 'description of the problem and affected group of users.' -ForegroundColor Magenta
                            Write-Host
                            
                            If ($Changes.Keys.Count -gt 0)
                            {
                                Write-Host 'The final reverted setting is being reapplied...'
                                $ExpectedSettingStatus | Export-CliXml $TroubleshootingStatusFile
                                $script:SuggestReboot = $False
                                Change-Settings $Changes
                            }
                            Set-Variable -Name 'Run' -Value $False -Scope 1
                            return
                        }
                        ElseIf ($JustApplied.Count -eq 2)
                        {
                            Write-Host 'Only two settings are left to try! Reverting the following setting. If the' -ForegroundColor Green
                            Write-Host 'problem goes away, this must be the cause:' -ForegroundColor Green
                            Write-Host
                            Display-Setting ($MasterPolicy | Where cis_idref -eq $JustApplied[0])
                            Write-Host
                            Write-Host 'If not, it must be the other one (you should still apply it to make sure):' -ForegroundColor Green
                            Write-Host
                            Display-Setting ($MasterPolicy | Where cis_idref -eq $JustApplied[1])
                            Write-Host
                            Write-Host 'Once you have verified, please report the setting details to' -ForegroundColor Magenta
                            Write-Host 'sccm@dps.ohio.gov, along with a description of the problem and' -ForegroundColor Magenta
                            Write-Host 'affected group of users.' -ForegroundColor Magenta
                        }
                        $Cutoff = [Math]::Floor($JustApplied.Count/2)
                        $JustApplied[0..($Cutoff-1)] | ForEach {
                            $ExpectedSettingStatus[$_] = 'Reverted'
                            $Changes[$_] = 'Reverted'
                        }
                        #$JustApplied[$Cutoff..$JustApplied.Count] | ForEach {
                            #$ExpectedSettingStatus[$_] = 'JustApplied'
                        #}
                        $ExpectedSettingStatus | Export-CliXml $TroubleshootingStatusFile
                        Write-Host "Applying $($SetToApplied.Count) settings and removing from consideration;" -ForegroundColor Green
                        Write-Host "Applying $([Math]::Ceiling($JustApplied.Count/2)) settings still under consideration;" -ForegroundColor Green
                        Write-Host "Reverting $Cutoff settings." -ForegroundColor Green
                        Change-Settings $Changes
                        Write-Host 'Changes complete. You can start testing now.' -ForegroundColor Magenta
                        Write-Host
                    };
                    'apply' = {
                        If ($ExpectedSettingStatus)
                        {
                            Write-Host 'This will end the in-progress troubleshooting session. Continue?' -ForegroundColor Red
                            $Response = Read-Host 'Y/N'
                            If (($Response -ne 'y') -and ($Response -ne 'yes'))
                            {
                                Write-Host
                                return
                            }
                        }
                        Remove-Item $TroubleshootingStatusFile -Force -ErrorAction SilentlyContinue
                        Write-Host 'Setting local policy...' -ForegroundColor Yellow
                        $Action = 'Apply'
                        If ($script:WackyReverse) { $Action = 'Revert' }
                        Set-LocalPolicyFromSettingsPolicyCsv -CsvFile $MasterPolicyFile -Action $Action -WarningAction SilentlyContinue
                        Write-Host 'Complete' -ForegroundColor Yellow
                        Write-Host
                        Write-Host
                        Suggest-Reboot
                        Write-Host 'Changes complete. You can start testing now.' -ForegroundColor Magenta
                        Write-Host
                    };
                    'revert' = {
                        If ($ExpectedSettingStatus)
                        {
                            Write-Host 'This will end the in-progress troubleshooting session. Continue?' -ForegroundColor Red
                            $Response = Read-Host 'Y/N'
                            If (($Response -ne 'y') -and ($Response -ne 'yes'))
                            {
                                Write-Host
                                return
                            }
                        }
                        Remove-Item $TroubleshootingStatusFile -Force -ErrorAction SilentlyContinue
                        Write-Host 'Setting local policy...' -ForegroundColor Yellow
                        $Action = 'Revert'
                        If ($script:WackyReverse) { $Action = 'Apply' }
                        Set-LocalPolicyFromSettingsPolicyCsv -CsvFile $MasterPolicyFile -Action $Action -WarningAction SilentlyContinue
                        Write-Host 'Complete' -ForegroundColor Yellow
                        Write-Host
                        Write-Host
                        Suggest-Reboot
                        Write-Host 'Changes complete. You can start testing now.' -ForegroundColor Magenta
                        Write-Host
                    };
                    'fix' = {
                        # Set all settings to applied/reverted based on $ExpectedSettingStatus
                        Change-Settings $ExpectedSettingStatus
                    };
                    'start' = {
                        # Start a new troubleshooting session - prompt to confirm and initialize status file with $ActualSettingStatus
                        $Stats = Get-TroubleshootingStatistics $ActualSettingStatus
                        If ($Stats.TotalApplied -eq $Stats.TotalSettings)
                        {
                            Write-Host 'Can not start a troubleshooting session; all settings are already compliant.' -ForegroundColor Red
                            Write-Host 'Try "revert" first.'
                            Write-Host
                            return
                        }
                        If ($ExpectedSettingStatus)
                        {
                            Write-Host 'This will end the in-progress troubleshooting session. Continue?' -ForegroundColor Red
                            $Response = Read-Host 'Y/N'
                            If (($Response -ne 'y') -and ($Response -ne 'yes'))
                            {
                                Write-Host
                                return
                            }
                        }
                        
                        Write-Host 'Beginning a new troubleshooting session. First you should revert all (or' -ForegroundColor Yellow
                        Write-Host 'some) settings and verify that the problem is no longer occurring. This' -ForegroundColor Yellow
                        Write-Host 'script will apply the remaining settings in groups, allowing you to test' -ForegroundColor Yellow
                        Write-Host 'after each iteration until the problem is narrowed down to a single setting.' -ForegroundColor Yellow
                        Write-Host
                        Write-Host 'Have you verified that problem occurs when all settings are enabled, but' -ForegroundColor Cyan
                        Write-Host 'is not occurring now?' -ForegroundColor Cyan
                        $Response = Read-Host 'Y/N'
                        If (($Response -ne 'y') -and ($Response -ne 'yes'))
                        {
                            Write-Host
                            return
                        }
                        Write-Host 'New troubleshooting session started. Applying initial setting group...' -ForegroundColor Cyan
                        $ExpectedSettingStatus = $ActualSettingStatus
                        & $Operations['working']
                    };
                    'view' = {
                        Write-Host 'Settings currently under consideration:' -ForegroundColor Green
                        Write-Host
                        $MasterPolicy | Where {$ExpectedSettingStatus[$_.cis_idref] -in @('Reverted','JustApplied')} | ForEach {
                            Display-Setting $_
                            Write-Host 'Status:              ' -NoNewLine
                            If ($ExpectedSettingStatus[$_.cis_idref] -eq 'Reverted')
                            {
                                Write-Host 'Reverted' -ForegroundColor Yellow
                            }
                            Else
                            {
                                Write-Host 'Applied' -ForegroundColor Cyan
                            }
                            Write-Host
                        }
                    };
                    'export' = {
                        Try
                        {
                            $MasterPolicy | ForEach {
                                $_ | Add-Member -NotePropertyName 'CurrentStatus' -NotePropertyValue $ExpectedSettingStatus[$_.cis_idref] -Force -PassThru
                            } | Export-Csv "$env:userprofile\LocalPolicyTroubleshootingStatus.csv" -ErrorAction Stop
                        }
                        Catch
                        {
                            return
                        }
                        Write-Host "Settings status saved to '$env:userprofile\LocalPolicyTroubleshootingStatus.csv', view now?" -ForegroundColor Green
                        $Response = Read-Host 'Y/N'
                        If (($Response -eq 'y') -or ($Response -eq 'yes'))
                        {
                            & "$env:userprofile\LocalPolicyTroubleshootingStatus.csv"
                        }
                    };
                    'stop' = {
                        Remove-Item $TroubleshootingStatusFile -Force -ErrorAction SilentlyContinue
                        Write-Host 'Ending the current troubleshooting session. No changes are being made to the system.' -ForegroundColor Yellow
                        Write-Host 'The security policy will be automatically reapplied the next time it is updated. If ' -ForegroundColor Red
                        Write-Host 'you have identified a problematic setting, you should contact the SCCM team at' -ForegroundColor Red
                        Write-Host 'sccm@dps.ohio.gov to have the policy updated.' -ForegroundColor Red
                        Write-Host
                    }
                    'refresh' = {};
                    'reboot' = {Perform-Reboot};
                    'help' = {Write-Host @"
This script assists in troubleshooting issues that may arise due to the security policy in place on
this system. When you encounter a problem, you can quickly determine whether the security policy is
to blame by turning it off and trying to reproduce the problem. Type "revert" at the troubleshooter
menu to turn off all security settings.

Once the settings are reverted, the troubleshooter will offer to reboot the computer. Some settings
may require a reboot to take effect. You can leave the reboot prompt up while you test the behavior.
If it is still not working, try typing Y to reboot, then test the behavior again when the system
comes back up. If it STILL is not working, the security settings are not the cause. You should type
apply to reenable the security settings before moving on to other methods of troubleshooting.

Note: If you find you do not need to reboot to make the problem disappear, before continuing you may
want to double-check that you also don't need to reboot to make it reappear! Type apply to reenable
all security settings and test the behavior again. You will then need to revert the settings again
before you can start a troubleshooting session.

If reverting the settings does resolve the problem, you know the security settings are to blame.
Now you need to narrow down which setting is causing the problem. With all settings reverted, type
start to begin a troubleshooting session.

During the troubleshooting session, you will test the behavior several times as the script
automatically applies and reverts settings. If you found that you needed to reboot to enable/disable
the behavior, you will want to reboot before each test (the script will prompt you to do so). If not
you can skip this step.

After each test, you will simply type "working" if the problem is not occurring, and "broken" if it
is. After several rounds of testing, the script will narrow it down to a single setting that is
causing the problem. Be sure to share the details of the setting with the SCCM group
(sccm@dps.ohio.gov) to have the policy updated for the affected users.

WARNING: This script works for problems that are caused by a single setting. If more than one setting
can cause the issue, the script will not work correctly. In that case you will probably notice that
you are typing "broken" repeatedly until the script claims to have identified a setting that is
completely unrelated to the problem you are experiencing. If you run into this, contact the SCCM group.
We can assist with an alternate method of determining all problematic settings.


"@};
                    'quit' = {Set-Variable -Name 'Run' -Value $False -Scope 1}
                   }
    
    $Run = $True
    While ($Run)
    {
        Write-Host '>>> Local Policy Troubleshooting <<<' -ForegroundColor Green
        Write-Host
        $AllowedOps = @('quit')
        Try
        {
            Write-Host 'Checking settings...'
            $ExpectedSettingStatus = Get-ExpectedSettingStatus
            $ActualSettingStatus = Get-ActualSettingStatus

            If ($ExpectedSettingStatus)
            {
                If ($ActualSettingStatus.Count -ne $ExpectedSettingStatus.Count)
                {
                    throw 'Unexpected result from Check-TroubleshootingStatus'
                }
                ForEach ($Key In $ExpectedSettingStatus.Keys)
                {
                    If ((($ActualSettingStatus[$Key] -eq 'Applied') -and ($ExpectedSettingStatus[$Key] -eq 'Reverted')) -or 
                        (($ActualSettingStatus[$Key] -eq 'Reverted') -and ($ExpectedSettingStatus[$Key] -like '*Applied')))
                    {
                        Write-Host 'Unexpected value.' -ForegroundColor Red
                        Display-Setting ($MasterPolicy | Where cis_idref -eq $Key)
                        Write-Host 'Actual Status:       ' -NoNewLine
                        Write-Host "$($ActualSettingStatus[$Key])" -ForegroundColor Red
                        Write-Host "Expected Status:     $($ExpectedSettingStatus[$Key])"
                        throw 'In-progress session out of sync'
                    }
                }
                $Stats = Get-TroubleshootingStatistics $ExpectedSettingStatus
            }
            Else
            {
                $Stats = Get-TroubleshootingStatistics $ActualSettingStatus
            }
            
            
            Write-Host "Currently Applied: $($Stats.TotalApplied)/$($Stats.TotalSettings) settings ($($Stats.PercentApplied)%)"
            If ($ExpectedSettingStatus)
            {
                Write-Host 'A troubleshooting session is in progress.' -ForegroundColor Magenta
            }
            Write-Host
            
            $AllowedOps = 'apply','revert','refresh','reboot','help','quit'
            Write-Host 'Type a command:' -ForegroundColor Yellow
            If ($ExpectedSettingStatus)
            {
                Write-Host 'working ' -ForegroundColor Cyan -NoNewLine
                Write-Host ': If the problem did not reappear with the current configuration,'
                Write-Host '          we know none of the current settings cause the problem. Type '
                Write-Host '          working' -ForegroundColor Cyan -NoNewLine
                Write-Host ' to apply the next group of settings.'
                Write-Host 'broken  ' -ForegroundColor Cyan -NoNewLine
                Write-Host ': If the problem reappears with the current configuration, we'
                Write-Host '          know one of the applied settings is the cause. Type ' -NoNewLine
                Write-Host 'broken' -ForegroundColor Cyan -NoNewLine
                Write-Host ' to'
                Write-Host '          apply the settings that are currently reverted, and revert half'
                Write-Host '          of the most recently applied settings.'
                Write-Host 'view    ' -ForegroundColor Cyan -NoNewLine
                Write-Host ': View settings currently being tested.'
                Write-Host 'export  ' -ForegroundColor Cyan -NoNewLine
                Write-Host ': Save the current status of all settings to an Excel-readable CSV file.'
                Write-Host 'stop    ' -ForegroundColor Cyan -NoNewLine
                Write-Host ': Leave the system as-is and end the current troubleshooting session.'
                $AllowedOps = @('working','broken','view','export','stop') + $AllowedOps
            }
            Else
            {
                Write-Host 'start   ' -ForegroundColor Cyan -NoNewLine
                Write-Host ': Begin a new troubleshooting session. Before starting a session'
                Write-Host '          you should revert settings and verify the problem no longer occurs.'
                $AllowedOps = @('start') + $AllowedOps
            }
            Write-Host 'apply   ' -ForegroundColor Cyan -NoNewLine
            Write-Host ': Set all settings to be compliant with the new policy.'
            Write-Host 'revert  ' -ForegroundColor Cyan -NoNewline
            Write-Host ': Revert all settings to their original values (before the new'
            Write-Host '          policy was applied).'
            Write-Host 'refresh ' -ForegroundColor Cyan -NoNewline
            Write-Host ': Double check current setting values.'
            Write-Host 'reboot  ' -ForegroundColor Cyan -NoNewline
            Write-Host ': Schedule this script to run at logon and reboot.'
            Write-Host 'help    ' -ForegroundColor Cyan -NoNewline
            Write-Host ': Display information on using this script.'
            Write-Host 'quit    ' -ForegroundColor Cyan -NoNewline
            Write-Host ': Exit the script.'
            
        }
        Catch
        {
            If ($_.FullyQualifiedErrorId -eq 'Unexpected setting value' -or $_.FullyQualifiedErrorId -eq 'In-progress session out of sync')
            {
                $AllowedOps = 'apply','revert','refresh','reboot','help','quit'
                
                If ($_.FullyQualifiedErrorId -eq 'Unexpected setting value')
                {
                    Write-Host 'Error: To use this script, all settings must either be compliant' -ForegroundColor Red
                    Write-Host 'with DPS policy or reverted to their original value. One or more ' -ForegroundColor Red
                    Write-Host 'settings is currently set to an unexpected value.' -ForegroundColor Red
                }
                Else
                {
                    Write-Host 'Error: Current value for one or more settings does not match the value' -ForegroundColor Red
                    Write-Host 'saved for the in-progress troubleshooting session.' -ForegroundColor Red
                }
                
                Write-Host 'Type a command:' -ForegroundColor Yellow
                If ($ExpectedSettingStatus)
                {
                    $Stats = Get-TroubleshootingStatistics($ExpectedSettingStatus)
                    Write-Host 'fix     ' -ForegroundColor Cyan -NoNewline
                    Write-Host ": Revert settings to the in-progress troubleshooting session from "
                    Write-Host "          $((Get-Item $TroubleshootingStatusFile).LastWriteTime.ToShortDateString())" -NoNewLine
                    Write-Host " with $($Stats.TotalApplied)/$($Stats.TotalSettings) settings applied " -NoNewline
                    Write-Host "($($Stats.PercentApplied)%)."
                    
                    Write-Host 'view    ' -ForegroundColor Cyan -NoNewLine
                    Write-Host ': View settings the in-progress troubleshooting session is currently testing.'
                    Write-Host 'export  ' -ForegroundColor Cyan -NoNewLine
                    Write-Host ': Save the status of all values for the in-progress session to an Excel-readable'
                    Write-Host '          CSV file.'
                    Write-Host 'stop    ' -ForegroundColor Cyan -NoNewLine
                    Write-Host ': Leave the system as-is and end the in-progress troubleshooting session.'
                    $AllowedOps = @('fix','view','export','stop') + $AllowedOps
                }
                Write-Host 'apply   ' -ForegroundColor Cyan -NoNewLine
                Write-Host ': Set all settings to be compliant with the new policy.'
                Write-Host 'revert  ' -ForegroundColor Cyan -NoNewline
                Write-Host ': Revert all settings to their original values (before the new'
                Write-Host '          policy was applied).'
                Write-Host 'refresh ' -ForegroundColor Cyan -NoNewline
                Write-Host ': Double check current setting values.'
                Write-Host 'reboot  ' -ForegroundColor Cyan -NoNewline
                Write-Host ': Schedule this script to run at logon and reboot.'
                Write-Host 'help    ' -ForegroundColor Cyan -NoNewline
                Write-Host ': Display information on using this script.'
                Write-Host 'quit    ' -ForegroundColor Cyan -NoNewline
                Write-Host ': Exit the script.'
                
            }
            Else
            {
                throw $_
            }
        }
        
        Do
        {
            Write-Host "Available commands: $AllowedOps" -ForegroundColor Yellow
            $Selection = Read-Host ':'
            If ($Selection -eq 'wackyreverse')
            {
                Write-Host 'wink wink ;) ;)'
                $script:WackyReverse = $True
                Remove-Item $TroubleshootingStatusFile -Force -ErrorAction SilentlyContinue
                $ActualSettingStatus = Get-ActualSettingStatus
            }
            If ($script:WackyReverse)
            {
                If ($Selection -eq 'working') { $Selection = 'broken' }
                ElseIf ($Selection -eq 'broken') { $Selection = 'working' }
            }
        }
        While ($Selection -notin $AllowedOps)
        
        & $Operations[$Selection]
    }
    Write-Host
    Write-Host 'Exiting to PowerShell.' -ForegroundColor Cyan
    Write-Host
}





# Compares a Policy Settings CSV to the current system. Generates a new Policy Settings CSV containing only the settings
# that are non-compliant along with their current values. This Policy Remediation CSV can be used to remediate the non-compliant
# settings, and to undo that remediation for troubleshooting purposes. Audit settings are ignored (since they can not easily
# be set individually, and are not expected to have side effects that would require troubleshooting).
#
# The cis_idref field is regenerated to ensure uniqueness. Setting values are also checked for uniqueness with duplicates
# thrown out.
#
# The term Policy Remediation CSV refers to a Policy Settings Csv that includes the PriorValue, ValueExistedPrior, and
# PriorCompliance fields. 
Function New-PolicyRemediationFileForLocalSystem([Parameter(Mandatory)]$SourceFile, [Parameter(Mandatory)]$RemediationFileToCreate, [Parameter(Mandatory)]$AuditFileToCreate)
{
    $id = 0
    $Settings = @()
    $TestResult = Test-PolicySettingsCsvAgainstLocalSystem $SourceFile -WarningAction SilentlyContinue
    $TestResult |
            Where-Object {$_.type -ne 'AdvancedAudit' -and $_.PriorCompliance -eq 'False'} |
            ForEach {
                $Summary = "$($_.type);$($_.ura_right);$($_.audit_category);$($_.so_cisname);$($_.so_infsection);$($_.so_name);$($_.reg_hive);$($_.reg_key);$($_.reg_value);$($_.reg_type)"
                If ($Summary -notin $Settings)
                {
                    $Settings += $Summary
                    $_ | Add-Member -NotePropertyName cis_idref -NotePropertyValue $id -Force -PassThru
                    $id++
                }
            } | Export-Csv $RemediationFileToCreate
}
