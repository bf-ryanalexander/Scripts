<#
	.SYNOPSIS
		Enables BitLocker Drive Encryption
	.DESCRIPTION
		Checks to see if the device is utilizing BitLocker Drive Encryption with TPM as the Key Protector Type and saves the recovery key to the specified location
	.NOTES
		2025-07-15: V4.0 - Refactored to run backups immediately after post-reboot encryption process finishes,
							no longer requires running script from Ninja a second time or duplicating massive sections of code.
		2025-07-14: V3.2 - Fixed AD backup function, fixed Decryption check progress function, changed test function for saving to network path
		2025-06-20: V3.1.1 - Cleaned up server deployment; will no longer report an error if the BDE Feature isn't installed before the script runs
 		2025-05-14: V3.1 - Fixed regex matching on saving key to Ninja,
							confirmation for backing up key to Entra (sometimes it says backed up to Entra ID, sometimes it says backed up to Azure AD...),
							BitLocker folder deletion post-enablement,
							error cleanup in server portion,
							saving to network failed as it added "\\" to the network path even though "\\" is required
 		2025-05-13: V3.0.2 - Cleaned up "BitLocker already enabled" cleanup task
 		2025-05-06: V3.0.1 - Updated BitLockerRegistryKey variable to force create the path if it doesn't exist
		2025-05-06: V3.0 - Refactored drive testing to ensure all internal drives are encrypted with auto-unlock capability,
							added re-encryption process for improperly configured BitLocker,
							added backing up to Entra ID with confirmation,
							added checks to show progress of encryption during post-reboot process via log file,
							added an exclusion so iSCSI drives won't be encrypted
		2024-08-22: V2.4 - Added backing up all keys to On-Prem AD
		2024-08-21: V2.3 - Added backing up all keys to Ninja Multi-Line Custom Field "bitlockerKeys", now supports running as a recurring script with all checks
		2024-08-01: V2.2 - Added support for auto-unlocking non-system internal drives
		2024-07-31: V2.1 - Refactored to support Script Variables and be more efficient with fewer duplicate blocks of code
		2024-07-29: V2.0 - Fully revised what is classified as "Enabled", added new "Status" checks, better "Bad Scenario" checks
		2024-07-23: V1.0 - Initial version
	.FUNCTIONALITY
		Automates the encryption of managed devices to ensure consistent protection.
	.LINK
		https://github.com/bf-ryanalexander/Scripts/blob/main/Enable-BitLocker.ps1
	.NOTES
		Required Custom Fields: (Field Name - Type - Scope)
			bitlockerKeys - Multi-line - Device
			bitlockerNetworkPath - Text - Device, Location, Organization
			bitlockerSavedToAd - Checkbox - Device
			bitlockerSavedToEntra - Checkbox - Device
			bitlockerSavedToNetwork - Checkbox - Device
	.NOTES
		TODO: Fix logging post-reboot
		TODO: Add domain check before initiating backup of key to AD
		TODO: Network path doesn't work with non-domain joined saving to domain UNC; mount path, save, dismount?
		TODO: Check Windows Update scenario; BL is suspended for WU, possibly triggering Bad Scenario #3 "Drive is encrypted but protection is off"
		TODO: Clean up server deployment, still pretty noisy and a bit buggy.
#>

function StageOne_DefineFunctions { @'
	# -----------------Customization options------------------------ #

	$BitLockerRegistryKey = "HKLM:\Software\BrightFlow\BitLocker" # Which Registry key to save registry entries in
	$BitLockerDirectory = "C:\temp\BrightFlow\BitLocker" # Which folder in File Explorer to save the post-reboot script
	$BitLockerLogs = "C:\Temp\BrightFlow\logs" # Which folder in File Explorer to save the post-reboot logs
	$BitLockerTaskPath = "\BrightFlow\" # Which folder in Task Scheduler to save the task
	$TimeBetweenChecks = "300"	# Number of seconds before re-checking if the decryption/encryption process has finished.
								# Note, it will wait the full time before moving to the next drive even if the process finishes before then.
								# Don't set a crazy high time (Eg. 24 hours) if you have multiple drives to encrypt.

	# ---------------End customization options---------------------- #

	function Write-Log {
		param( [String]$LogMsg ) ; $Log = "[$(Get-Date -Format s)] $LogMsg"
		Write-Host $Log ; $Log | Out-File -FilePath "$BitLockerLogs\BitLockerUpdate.log" -Append
	}

	$osVersion = (Get-CimInstance win32_operatingsystem).Caption

	# Registry
	function New-BitLockerRegistryKey {
		if (-not (Test-Path $BitLockerRegistryKey)) {
			Write-Host "|| Creating BitLocker registry key..."

			New-Item $BitLockerRegistryKey -Force | Out-Null

			if (Test-Path $BitLockerRegistryKey) { Write-Host "|| - Successfully created BitLocker registry key." }
			else { Write-Host ">> - Failed to create BitLocker registry key." }
		}
	}
	function Search-blRegistry { Test-Path $BitLockerRegistryKey }
	$DateMinusThirty = ([datetime](Get-Date)).AddDays(-30)
	function Search-blEncryptionRebootStatus { (Get-ItemProperty $BitLockerRegistryKey -ErrorAction SilentlyContinue).EncryptionRebootStatus }
	function Search-blEncryptionDatePending { (Get-ItemProperty $BitLockerRegistryKey -ErrorAction SilentlyContinue).EncryptionDatePending }

	# Task and Script
	$blTaskName = "BitLocker Post-Reboot Encryption"
	$BitLockerTaskPath = "\BrightFlow\"
	function Search-blInstallTask { Get-ScheduledTask -TaskPath $BitLockerTaskPath | Where-Object TaskName -eq $blTaskName -ErrorAction SilentlyContinue }
	function Search-blDeployScript { Test-Path "$BitLockerDirectory\Deploy-BitLocker.ps1" -ErrorAction SilentlyContinue }

	# Drive Testing
	function Test-SystemDrive {
		# Drive is encrypted, a recovery key exists, uses TPM, and protection is enabled
		((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).VolumeStatus -eq "FullyEncrypted") -and
		(-not ([string]::IsNullOrWhitespace((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).KeyProtector))) -and
		((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).KeyProtector -like "*Tpm*") -and
		((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).ProtectionStatus -eq "On")
	}
	function Test-NonSystemDrives {
		if ([string]::IsNullOrWhitespace($NonSystemDrives)) { return $true } else {
			foreach ($drive in $NonSystemDrives) {
				$driveKeyProtector = Get-BitLockerVolume -MountPoint $drive | Select-Object -ExpandProperty KeyProtector

				(Get-BitLockerVolume -MountPoint $drive).VolumeStatus -eq "FullyEncrypted" -and
				(Get-BitLockerVolume -MountPoint $drive).AutoUnlockEnabled -eq $true -and
				-not ([string]::IsNullOrWhitespace(($driveKeyProtector | Where-Object KeyProtectorType -eq "RecoveryPassword" | Select-Object -ExpandProperty RecoveryPassword))) -and
				-not ([string]::IsNullOrWhitespace(($driveKeyProtector | Where-Object KeyProtectorType -eq "ExternalKey" | Select-Object -ExpandProperty KeyFileName)))
			}
		}
	}
'@ }
function StageTwo_EncryptSystemDrive { @'
	function Enable-BitLockerOnSystemDrive {
		Write-Host "|| Enabling BitLocker on system drive..."

		Get-BitLockerVolume -MountPoint $ENV:SystemDrive | Enable-BitLocker -EncryptionMethod AES256 -RecoveryPasswordProtector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

		# Create Registry Key for Properties
		if (!(Search-blRegistry)) { New-Item -Type Registry $BitLockerRegistryKey | Out-Null }
		
		Write-Host "|| Creating pending reboot registry values..."

		New-ItemProperty -Path $BitLockerRegistryKey -Name "EncryptionRebootStatus" -Value "PendingReboot" -Force | Out-Null
		New-ItemProperty -Path $BitLockerRegistryKey -Name "EncryptionDatePending" -Value $(Get-Date -Format s) -Force | Out-Null

		if ((Search-blEncryptionRebootStatus) -and (Search-blEncryptionDatePending)) { Write-Host "|| - Successfully created pending reboot registry entries." }
		else { Write-Host ">> - Failed to create pending reboot registry values." }

		# Create post-reboot task
		if (!(Search-blInstallTask)) {
			Write-Host "|| Creating $blTaskName task..."

			$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoProfile -NoLogo -NonInteractive -WindowStyle hidden -ExecutionPolicy Bypass -File $BitLockerDirectory\Deploy-BitLocker.ps1"
			$Trigger = @( $(New-ScheduledTaskTrigger -AtStartup) )
			$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
			$Settings.CimInstanceProperties.Item('MultipleInstances').Value = 3
			$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings

			Register-ScheduledTask -TaskPath $BitLockerTaskPath -TaskName $blTaskName -InputObject $Task -User 'NT AUTHORITY\SYSTEM' | Out-Null

			if (Search-blInstallTask) {
				Write-Host "|| - Successfully created $blTaskName task."
			} else { Write-Host ">> - Failed to create $blTaskName task." }

			# Create a script with the contents of the Stage 1-4 functions and the words "Test-BitLocker" so it will execute the "Test-BitLocker function
			function blDeployScript {
				StageOne_DefineFunctions
				StageTwo_EncryptSystemDrive
				StageThree_TestBitLocker
				StageFour_BackupKeys
				"`n"
				'Test-BitLocker'
			}

			$blDeployScript = ([string]$(blDeployScript)) -replace "Write-Host","Write-Log"

			if (!(Search-blDeployScript)) {
				New-Item "$BitLockerDirectory\Deploy-BitLocker.ps1" -ItemType File -Value $blDeployScript -Force | Out-Null

				if (Search-blDeployScript) { Write-Host "|| - Successfully created BitLocker Post-Reboot script." }
				else { Write-Host ">> - Failed to create BitLocker Post-Reboot script." }

			}

			if (Search-blInstallTask) {
				Write-Host "|| - Successfully created $blTaskName task."

				if ((Get-CimInstance -ClassName Win32_EncryptableVolume  -Namespace "Root\CIMV2\Security\MicrosoftVolumeEncryption").IsVolumeInitializedForProtection -eq $True) {
					Write-Host "|| - Successfully enabled BitLocker on system drive. Reboot to begin encryption."
				} else { Write-Host ">> - Failed to enable BitLocker on system drive." }
			} else { Write-Host ">> - Failed to create $blTaskName task." }
		}
	}
'@ }
function StageThree_TestBitLocker { @'
	function Test-BitLocker {
		New-BitLockerRegistryKey

		$NonSystemDrives = Get-Disk | Where-Object { ($_.bustype -ne 'USB') -and ($_.bustype -ne 'iSCSI') } | Get-Partition | Where-Object { $_.DriveLetter } | Where-Object {"$($_.DriveLetter):" -ne $ENV:SystemDrive} | Select-Object -ExpandProperty DriveLetter | ForEach-Object {"$_`:"}
		$BitLockerDrives = (Get-BitLockerVolume | Where-Object {($_.MountPoint -eq $ENV:SystemDrive) -or ($_.MountPoint -in $NonSystemDrives)})

		# Drive is encrypted, a recovery key exists, uses TPM, and protection is enabled
		if ((Test-SystemDrive) -eq $true) {
			if ((Test-NonSystemDrives) -notcontains $false) {
				Write-Host "BitLocker already enabled."

				# Backup key to Ninja, AD, Entra, network location, or a combination
				Test-BitLockerBackups

				# Cleanup
				# if (Get-ScheduledTask -TaskPath $BitLockerTaskPath) { Get-ScheduledTask -TaskPath $BitLockerTaskPath | Where-Object TaskName -eq "BitLocker Post-Reboot Encryption" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false }
				# if (Test-Path $BitLockerDirectory) {
				# 	Remove-Item $BitLockerDirectory -Recurse -Force -ErrorAction SilentlyContinue

				# 	if (!(Test-Path $BitLockerDirectory)) { Write-Host "|| - Successfully removed BitLocker Post-Reboot script." }
				# 	else { Write-Host ">> - Failed to remove BitLocker Post-Reboot script." }
				# }

				# if ((Search-blEncryptionRebootStatus) -or (Search-blEncryptionDatePending)) {
				# 	Write-Host "|| Removing registry entries..."

				# 	Remove-ItemProperty -Path $BitLockerRegistryKey -Name *

				# 	if (-not ((Search-blEncryptionRebootStatus) -or (Search-blEncryptionDatePending))) { Write-Host "|| - Successfully removed registry entries." }
				# 	else { Write-Host ">> - Failed to remove registry entries." }
				# }
			} else {
				Write-Host "|| BitLocker already enabled on system drive."
				
				if (-not ([string]::IsNullOrWhitespace($NonSystemDrives))) {
					Write-Host "Enabling BitLocker on all non-system drives..."

					$NonSystemDrives | ForEach-Object {
						$counter = 0
						$driveKeyProtector = Get-BitLockerVolume -MountPoint $_ | Select-Object -ExpandProperty KeyProtector

						if ([string]::IsNullOrWhitespace($driveKeyProtector)) {
							Get-BitLockerVolume -MountPoint $_ | Enable-BitLocker -EncryptionMethod AES256 -RecoveryPasswordProtector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Enable-BitLockerAutoUnlock | Out-Null

							while (((Get-BitLockerVolume -MountPoint $_).VolumeStatus -ne "FullyEncrypted") -and ($counter -lt 288)) { # 288 tries translates to 24 hours
								$counter++
								Write-Host "|| - Encrypting drive $_...$(Get-BitLockerVolume -MountPoint $_ | Select-Object -ExpandProperty EncryptionPercentage)% complete. [Check #$counter]"

								Start-Sleep $TimeBetweenChecks
							}

							if (-not ([string]::IsNullOrWhitespace((Get-BitLockerVolume -MountPoint $_ | Select-Object -ExpandProperty KeyProtector)))) {
								Write-Host "|| - Successfully enabled BitLocker on drive $_"
							} else { Write-Host ">> - Failed to enable BitLocker on drive $_"$Error[0].Exception.message }
						}
					}

					if ((Test-NonSystemDrives) -notcontains $false) {
						Write-Host "|| - Successfully enabled BitLocker on all non-system drives."

						Remove-Item $BitLockerDirectory -Recurse -Force
						Get-ScheduledTask -TaskPath $BitLockerTaskPath | Where-Object TaskName -eq "BitLocker Post-Reboot Encryption" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

						if (!(Test-Path $BitLockerDirectory)) { Write-Host "|| - Successfully removed BitLocker Post-Reboot script." }
						else { Write-Host ">> - Failed to remove BitLocker Post-Reboot script." }

						# Backup key to Ninja, AD, Entra, network location, or a combination
						Test-BitLockerBackups
					}
					else { Write-Host ">> - Failed to enable BitLocker on all non-system drives." }
				} else { Test-BitLockerBackups }
			}
		} else {
			if ( # Check for bad scenarios
				( (-not ([string]::IsNullOrWhitespace((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).KeyProtector))) -and (([string]::IsNullOrWhitespace(((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).KeyProtector | Where-Object KeyProtectorType -eq Tpm)))) ) -or	#Bad Scenario #1: Key exists, but not setup to use TPM
				( (([string]::IsNullOrWhitespace((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).KeyProtector))) -and ((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).VolumeStatus -eq "FullyEncrypted") ) -or	#Bad Scenario #2: Key does not exist, but drive is encrypted
				( ((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).VolumeStatus -eq "FullyEncrypted") -and ((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).ProtectionStatus -eq "Off") ) -or	#Bad Scenario #3: Drive is encrypted but protection is off
				( (Get-BitLockerVolume -MountPoint $ENV:SystemDrive) | Where-Object {($_.EncryptionMethod -ne "Aes256") -and ($_.EncryptionMethod -ne "none")} )	#Bad Scenario #4: Drive is not encrypted with AES256 (typically AES-128 instead)
			) {
				Write-Host "|| BitLocker is enabled, but not configured properly. Disabling BitLocker so it can be reconfigured..."

				# Decrypt non-system drives if they exist before attempting to decrypt system drive
				if ($null -ne $NonSystemDrives) {
					$NonSystemDrives | ForEach-Object { Disable-BitLocker -MountPoint $_ | Out-Null }

					while ((Get-BitLockerVolume | Where-Object {($_.MountPoint -ne $ENV:SystemDrive) -and ($_.MountPoint -in $NonSystemDrives)}).VolumeStatus -ne "FullyDecrypted") {
						Write-Host "|| - Decrypting non-system drives..."
						Start-Sleep $TimeBetweenChecks
					}

					if ((Get-BitLockerVolume | Where-Object {($_.MountPoint -ne $ENV:SystemDrive) -and ($_.MountPoint -in $NonSystemDrives)}).VolumeStatus -eq "FullyDecrypted") {
						Write-Host "|| - Successfully decrypted non-system drives."
					} else {
						Write-Host ">> - Failed to decrypt non-system drives."
					}
				}

				# Decrypt system drive so it can be encrypted properly
				Get-BitLockerVolume -MountPoint $ENV:SystemDrive | Disable-BitLocker -ErrorAction SilentlyContinue | Out-Null
				$counter = 0

				while ((Get-BitLockerVolume -MountPoint $ENV:SystemDrive).VolumeStatus -ne "FullyDecrypted") {
					$counter++

					Write-Host "|| - Decrypting system drive...$(Get-BitLockerVolume -MountPoint $ENV:SystemDrive | Select-Object -ExpandProperty EncryptionPercentage)% complete. [Check #$counter]"
					Start-Sleep $TimeBetweenChecks
				}

				# Old recovery passwords are removed when drives are fully decrypted and BitLocker disabled, so best to remove them to avoid confusion
				if (Ninja-Property-Get bitlockerKeys) { Ninja-Property-Set bitlockerKeys $null }

				# Normal encryption process
				Enable-BitLockerOnSystemDrive
			} else {
				# Normal encryption process
				Enable-BitLockerOnSystemDrive
			}
		}
	}
'@ }
function StageFour_BackupKeys { @'
	#region Test if keys are saved to Ninja, Network Share, AD, Entra
	function Test-IfKeySavedToNinja {
		function Search-KeyInNinja {
			if (([string]::IsNullOrWhitespace((Ninja-Property-Get bitlockerKeys)))) { return $false }
			else {
				$BitLockerDrives | ForEach-Object {
					$DriveData = ([regex]::match((Ninja-Property-Get bitlockerKeys), "(?s)(Mount Point: $($_.MountPoint).*?)(?:Recovery Password:[^:\r\n]*$|KeyFileName.*.BEK)"))
					if (($DriveData -like "*Mount Point: $($_.MountPoint)*") -and (($DriveData -like "*Recovery Password:*") -or ($DriveData -like "*Drive not encrypted.*"))) { return $true } else { return $false }
				}
			}
		}
		if ((Search-KeyInNinja) -contains $false) {
			Write-Host "|| Saving BitLocker Key(s) to Ninja..."

			$Keys = ([string]$Keys = (Get-BitLockerVolume | Where-Object {($_.MountPoint -eq $ENV:SystemDrive) -or ($_.MountPoint -in $NonSystemDrives)}) | ForEach-Object {
				$KeyProtectorId = $_.KeyProtector.KeyProtectorId ; $KeyProtectorType = $_.KeyProtector.KeyProtectorType ; $RecoveryPassword = $_.KeyProtector.RecoveryPassword ; $AutoUnlockProtector = $_.KeyProtector.AutoUnlockProtector ; $KeyFileName = $_.KeyProtector.KeyFileName
				"Mount Point: $($_.MountPoint)`n"
				if (-not ([string]::IsNullOrWhitespace($KeyProtectorId))) { "Key Protector ID: $KeyProtectorId`n" }
				if (-not ([string]::IsNullOrWhitespace($KeyProtectorType))) { "Key Protector Type: $KeyProtectorType`n" }
				if (-not ([string]::IsNullOrWhitespace($RecoveryPassword))) { "Recovery Password: $RecoveryPassword`n" }
				if (-not ([string]::IsNullOrWhitespace($AutoUnlockProtector))) { "Auto Unlock Protector: $AutoUnlockProtector`n" }
				if (-not ([string]::IsNullOrWhitespace($KeyFileName))) { "KeyFileName: $KeyFileName`n" }
				if (([string]::IsNullOrWhitespace($KeyProtectorId)) -and ([string]::IsNullOrWhitespace($KeyProtectorType)) -and ([string]::IsNullOrWhitespace($RecoveryPassword)) -and ([string]::IsNullOrWhitespace($AutoUnlockProtector)) -and ([string]::IsNullOrWhitespace($KeyFileName))) {
					"Drive not encrypted.`n"
				}
				"`n`n"
			}).Substring(0, [System.Math]::Min(10000, $Keys.Length))

			Ninja-Property-Set bitlockerKeys $Keys

			if (Search-KeyInNinja) { Write-Host "|| - Successfully saved BitLocker Key to Ninja." }
			else { Write-Host ">> - Failed to save BitLocker Key to Ninja." }
		} else { Write-Host "BitLocker already backed up to Ninja." }
	}
	function Test-IfKeySavedToNetwork {
		$BitLockerNetworkPath = Ninja-Property-Get bitlockerNetworkPath # If using SYSVOL/NETLOGON share, create a folder, Share with Everyone, and restrict to Domain Computers with Write permissions; does not need Modify/Full Control

		if ($BitLockerNetworkPath) {
			$ServerName = $BitLockerNetworkPath.split("\\")[2] # Expects a result like "\\Server.company.com\Share" or "\\Server\Share$"; must start with "\\"
			
			if (Test-Path $BitLockerNetworkPath) {
				function Search-SavedBitLockerKey { Test-Path "$BitLockerNetworkPath\$env:computername.txt" }
				function Search-BitLockerSavedToNetworkCustomField {
					if ((Ninja-Property-Get BitlockerSavedToNetwork) -ne 1) {
						Write-Host "|| Updating ""BitlockerSavedToNetwork"" Ninja custom field..."
			
						Ninja-Property-Set BitlockerSavedToNetwork 1
			
						if ((Ninja-Property-Get BitlockerSavedToNetwork) -eq 1) { Write-Host "|| - Successfully updated the custom field." }
						else { Write-Host ">> - Failed to update the custom field." }
					}
				}

				if (!(Search-SavedBitLockerKey)) {
					Write-Host "|| Recovery key has not been saved yet, saving on $ServerName..."
			
					(Get-BitLockerVolume).KeyProtector | Out-File "$BitLockerNetworkPath\$env:computername.txt"
			
					if (Search-SavedBitLockerKey) {
						Write-Host "|| - Successfully saved BitLocker recovery key to ""$BitLockerNetworkPath\$env:computername.txt."""

						Search-BitLockerSavedToNetworkCustomField
					} else { Write-Host ">> - Failed to save BitLocker recovery key to ""$BitLockerNetworkPath\$env:computername.txt.""" }
				} else {
					Write-Host "BitLocker already backed up to network."

					Search-BitLockerSavedToNetworkCustomField
				}
			} else { Write-Host ">> Failed to connect to $ServerName, will try to save the key later." }
		}
	}
	function Test-IfKeySavedToAD {
		if ((Ninja-Property-Get BitLockerSavedToAD) -eq 1) {
			Write-Host "BitLocker already backed up to Active Directory."
		} else {
			$counter = 0
			function Search-FVEPath { Get-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue }
			function Search-FVEProperties {
				$Properties = [System.Collections.Generic.List[object]]::New()
				@(
					"OSActiveDirectoryBackup;1;DWORD",
					"OSActiveDirectoryInfoToStore;1;DWORD",
					"OSHideRecoveryPage;1;DWORD",
					"OSManageDRA;1;DWORD",
					"OSRecovery;1;DWORD",
					"OSRecoveryPassword;2;DWORD",
					"OSRecoveryKey;2;DWORD",
					"OSRequireActiveDirectoryBackup;1;DWORD"
				) | ForEach-Object {
					$property = New-Object PSObject
					$property | Add-Member -type NoteProperty -Name 'Name' -Value $_.split(";").trim()[0]
					$property | Add-Member -type NoteProperty -Name 'Value' -Value $_.split(";").trim()[1]
					$property | Add-Member -type NoteProperty -Name 'Type' -Value $_.split(";").trim()[2]

					$Properties.Add($property)
				}

				$Properties | ForEach-Object {
					function Search-FVEProperty { Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" $_.Name -ErrorAction SilentlyContinue }
					if (!(Search-FVEProperty)) {
						Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name $_.Name -Value $_.Value -Type $_.Type

						if (Search-FVEProperty) { Write-Host "|| - Successfully created property $($_.Name) with value $($_.Value) and type $($_.Type)" }
						else { Write-Host ">> - Failed to create property $($_.Name)" ; $counter++ }
					}
				}
			}
			function Invoke-BackupToAD {
				if ($counter -eq 0) {
					Write-Host "|| Backing up BitLocker to Active Directory..."
					$KeyProtectors = Get-BitLockerVolume -MountPoint $($ENV:SystemDrive) | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -ne "Tpm" | Select-Object -ExpandProperty KeyProtectorId
					foreach ($Protector in $KeyProtectors) {
						try {
							Backup-BitLockerKeyProtector $($ENV:SystemDrive) -KeyProtectorId $Protector 2>&1 >$null
							Set-Variable -Name "BackupError" -Value $Error[0] -Scope Script | Out-Null
							Throw
						} catch {
							if ($BackupError.Exception.Message -notlike "*The key protector specified cannot be used for this operation*") {
								Write-Host "|| - Successfully backed up KeyProtector ""$Protector"" to Active Directory."
								$counter++
							} else { Write-Host ">> - Failed to backup KeyProtector ""$Protector"" to Active Directory." }
						}
					}

					if ($counter -ne 0) {
						Ninja-Property-Set BitLockerSavedToAD 1

						if (Ninja-Property-Get BitLockerSavedToAD -eq 1) { Write-Host "|| - Successfully updated BitLockerSavedToAD Custom Field." }
						else { Write-Host ">> - Failed to update BitLockerSavedToAD Custom Field." }
					}
				} else { Write-Host ">> Failed to set all required properties, cannot back up to Active Directory" }
			}
			if (!(Search-FVEPath)) {
				Write-Host "|| Creating FVE registry key..."

				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null

				if (Search-FVEPath) {
					Write-Host "|| - Successfully created FVE Registry Key."

					Search-FVEProperties

					Invoke-BackupToAD
				} else { Write-Host ">> Failed to create FVE registry key, cannot back up to Active Directory." }
			} else {
				Search-FVEProperties

				Invoke-BackupToAD
			}
		}
	}
	function Test-IfKeySavedToEntra {
		if ((Ninja-Property-Get BitLockerSavedToEntra) -eq 1) {
			Write-Host "BitLocker already backed up to Entra."
		} else {
			$counter = 0
			$BitLockerDrives | ForEach-Object {
				foreach ($id in $_.KeyProtector | Where-Object KeyProtectorType -eq "RecoveryPassword") {
					Write-Host "|| Backing up Drive ""$($_.MountPoint)"" KeyProtectorId ""$($id.KeyProtectorId)""..."

					BackupToAAD-BitLockerKeyProtector -MountPoint $_.MountPoint -KeyProtectorId $id.KeyProtectorId | Out-Null

					Start-Sleep -Seconds 3 # Takes a second for the event log to be created; 1 second works but set to 3 for buffer

					function Get-LastEvent { Get-WinEvent -ProviderName Microsoft-Windows-BitLocker-API -FilterXPath "*[System[(EventID=845)] and EventData[Data[@Name='ProtectorGUID'] and (Data='$($id.KeyProtectorId)')]]" -MaxEvents 1 }
					if (((Get-LastEvent).TimeCreated -gt (Get-Date).AddHours(-1)) -and ((Get-LastEvent).Message -like "*BitLocker Drive Encryption recovery information for volume $($_.MountPoint) was backed up successfully*")) {
						Write-Host "|| - Successfully backed up BitLocker Key to Entra."
					} else { Write-Host ">> - Failed to backup BitLocker Key to Entra." ; $counter++ }
				}
			}

			if ($counter -eq 0) {
				Write-Host "|| Updating ""BitLockerSavedToEntra"" Ninja custom field..."

				Ninja-Property-Set BitLockerSavedToEntra 1

				if ((Ninja-Property-Get BitLockerSavedToEntra) -eq 1) { Write-Host "|| - Successfully updated the custom field." }
				else { Write-Host ">> - Failed to update the custom field." }
			} else { Write-Host ">> - Failed to backup all BitLocker Keys to Entra." }
		}
	}
	function Test-JoinStatus {
		$DSRegOutput = [PSObject]::New()
		& dsregcmd.exe /status | Where-Object { $_ -match ' : ' } | ForEach-Object {
			$Item = $_.Trim() -split '\s:\s'
			$DSRegOutput | Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]', '') -Value $Item[1] -ErrorAction SilentlyContinue
		}

		if (($DSRegOutput.AzureADJoined -eq "YES") -and ($DSRegOutput.EnterpriseJoined -eq "NO") -and ($DSRegOutput.DomainJoined -eq "NO")) {
			# Entra-Joined
			Test-IfKeySavedToEntra
		} elseif ( ($DSRegOutput.AzureADJoined -eq "YES") -and ($DSRegOutput.EnterpriseJoined -eq "NO") -and ($DSRegOutput.DomainJoined -eq "YES")) {
			# Hybrid-Joined
			Test-IfKeySavedToEntra
			Test-IfKeySavedToAD
		} elseif ( ($DSRegOutput.AzureADJoined -eq "NO") -and ($DSRegOutput.EnterpriseJoined -eq "NO") -and ($DSRegOutput.DomainJoined -eq "YES")) {
			# On-Prem-Joined
			Test-IfKeySavedToAD
		} elseif ( ($DSRegOutput.AzureADJoined -eq "NO") -and ($DSRegOutput.EnterpriseJoined -eq "NO") -and ($DSRegOutput.DomainJoined -eq "NO")) {
			# Not-Joined
			# No action needed, will only backup to Ninja and network location if specified
		}
	}
	function Test-BitLockerBackups {
		#Backup key to Ninja
		Test-IfKeySavedToNinja

		#Backup key to AD, Entra, or both
		Test-JoinStatus

		#Backup key to network location
		Test-IfKeySavedToNetwork
	}
	#endregion Test if keys are saved to Ninja, Network Share, AD, Entra
'@ }

Invoke-Expression $(StageOne_DefineFunctions)
Invoke-Expression $(StageTwo_EncryptSystemDrive)
Invoke-Expression $(StageThree_TestBitLocker)
Invoke-Expression $(StageFour_BackupKeys)


# Check if the device has been pending reboot for over 30 days
# Partially in case the "reboot pending" value doesn't get deleted after reboot
if ((Search-blEncryptionDatePending) -and ((Search-blEncryptionDatePending) -lt $DateMinusThirty)) {
	Write-Host "|| BitLocker has been pending reboot for over 30 days, removing registry value(s)..."

	Remove-ItemProperty -Path $BitLockerRegistryKey -Name *

	if (-not ( (Search-blEncryptionRebootStatus) -and (Search-blEncryptionDatePending) )) {
		Write-Host "|| - Successfully removed registry value(s)."
	} else { Write-Host ">> - Failed to remove registry value(s)" }
}

#region Check for currently running processes, if it's a server, or if it's ready for BitLocker
if ( ((Search-blEncryptionRebootStatus) -eq "PendingReboot") -and ((Search-blEncryptionDatePending) -gt $DateMinusThirty) ) {
	Write-Host ">> BitLocker is pending reboot since $(Search-blEncryptionDatePending) to begin encryption."
} elseif ($osVersion -like "*Server*") {
	if ((Get-CimInstance -ClassName win32_computersystem | Select-Object -ExpandProperty Model) -ne "Virtual Machine") {
		New-BitLockerRegistryKey
		
		function Search-BDEStatus { Get-WindowsFeature | Where-Object DisplayName -eq "BitLocker Drive Encryption" -ErrorAction SilentlyContinue }
		function Get-BDEFeatureStatusProperty { Get-ItemProperty -Path $BitLockerRegistryKey -Name "BDEFeatureStatus" -ErrorAction SilentlyContinue }
		function Get-BDEFeatureDatePendingProperty { Get-ItemProperty -Path $BitLockerRegistryKey -Name "BDEFeatureDatePending" -ErrorAction SilentlyContinue }
		if ((Search-BDEStatus).Installed -eq $false) {
			Write-Host "|| Installing BitLocker Drive Encryption feature..."

			Search-BDEStatus | Install-WindowsFeature -WarningAction SilentlyContinue | Out-Null

			if ((Search-BDEStatus).Installed -eq $true) {
				Write-Host "|| - Successfully installed BitLocker Drive Encryption feature."

				New-ItemProperty -Path $BitLockerRegistryKey -Name "BDEFeatureStatus" -Value "PendingReboot" -Force | Out-Null
				New-ItemProperty -Path $BitLockerRegistryKey -Name "BDEFeatureDatePending" -Value $(Get-Date -Format s) -Force | Out-Null

				if ((Get-BDEFeatureStatusProperty) -and (Get-BDEFeatureDatePendingProperty)) {
					Write-Host "|| - Successfully created registry entries. Ready for reboot."
				} else { Write-Host ">> - Failed to create registry entries." }
			} else { Write-Host ">> - Failed to install BitLocker Drive Encryption feature." }
		} else {
			# if the registry values have been created and the "BDEFeatureDatePending" value is less than 30 days ago
			if ( (Get-BDEFeatureStatusProperty) -and ( (Get-BDEFeatureDatePendingProperty) -and (([datetime](Get-BDEFeatureDatePendingProperty).BDEFeatureDatePending) -gt $DateMinusThirty) ) ) {
				Write-Host ">> Server is pending reboot to install the ""BitLocker Drive Encryption"" role."
			} else {
				if ((Get-BDEFeatureStatusProperty) -or (Get-BDEFeatureDatePendingProperty)) {
					Write-Host "|| Removing registry entries..."

					Remove-ItemProperty -Path $BitLockerRegistryKey -Name *
				}

				if ( (Get-BitLockerVolume).VolumeStatus -contains "EncryptionInProgress" ) {
					Write-Host "BitLocker encryption in progress."
				} elseif ( (Get-BitLockerVolume).VolumeStatus -contains "DecryptionInProgress" ) {
					Write-Host "BitLocker decryption in progress."
				} else {
					Test-BitLocker
				}
			}
		}
	} else { Write-Host "BitLocker not enabled on VMs." }
} elseif ( (Get-BitLockerVolume).VolumeStatus -contains "EncryptionInProgress" ) {
	Write-Host "BitLocker encryption in progress."
} elseif ( (Get-BitLockerVolume).VolumeStatus -contains "DecryptionInProgress" ) {
	Write-Host "BitLocker decryption in progress."
} else {
	Test-BitLocker
}
