<#
	.SYNOPSIS
		Enables BitLocker Drive Encryption
	.DESCRIPTION
		Checks to see if the device is utilizing BitLocker Drive Encryption with TPM as the Key Protector Type and saves the recovery key to the specified location
	.NOTES
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
		TODO: Detect if Entra and backup the key there as well https://github.com/homotechsual/Blog-Scripts/blob/main/Monitoring/DomainJoin.ps1
		TODO: Update Test-BitLockerEnabled function to check all internal drives, not just system drive
#>
function Search-BitLockerKey { (Get-BitLockerVolume).KeyProtector }
function Search-BitLockerVolumeStatus { (Get-BitLockerVolume -MountPoint $ENV:SystemDrive).VolumeStatus }
function Test-BitLockerEnabled { @(
	# Drive is encrypted, a recovery key exists, uses TPM, and protection is enabled
	((Search-BitLockerVolumeStatus) -eq "FullyEncrypted") -and
	($null -ne (Search-BitLockerKey)) -and
	((Get-BitLockerVolume).KeyProtector -like "*Tpm*") -and
	((Get-BitLockerVolume).ProtectionStatus -eq "On")
) }
function Test-IfKeySavedToNinja {
	function Search-KeyInNinja { (((Ninja-Property-Get bitlockerKeys) -like "*Key Protector ID*") -and ((Ninja-Property-Get bitlockerKeys) -like "*Recovery Password*")) }
	if (!(Search-KeyInNinja)) {
		Write-Host "|| Saving BitLocker Key to Ninja..."

		$Keys = (Get-BitLockerVolume).KeyProtector | ForEach-Object {
			if ($_.KeyProtectorId) { "Key Protector ID: $($_.KeyProtectorId)`n" }
			if ($_.KeyProtectorType) { "Key Protector Type: $($_.KeyProtectorType)`n" }
			if ($_.RecoveryPassword) { "Recovery Password: $($_.RecoveryPassword)`n" }
			if ($_.AutoUnlockProtector) { "Auto Unlock Protector: $($_.AutoUnlockProtector)`n" }
			if ($_.KeyFileName) { "KeyFileName: $($_.KeyFileName)`n" }
			"`n`n"
		}
		
		Ninja-Property-Set bitlockerKeys $Keys

		if (Search-KeyInNinja) { Write-Host "|| - Successfully saved BitLocker Key to Ninja." }
		else { Write-Host "|| - Failed to save BitLocker Key to Ninja." }
	}
}
function Test-IfSaveLocationSpecified {
	#if either field is specified
	if (($null -ne $env:serverFqdn) -or ($null -ne $env:fileShare)) {
		#if both fields aren't specified
		if ( ($null -eq $env:serverFqdn) -or ($null -eq $env:fileShare) ) {
			Write-Host ">> A location was specified to save the recovery key, but all server information was not provided."
			Write-Host ">> Try again after the device reboots and finishes the encryption process."
			#force function to result as $false, but don't print "False" to the console when testing
			return $false 2>&1 >$null
		} else { return $true }
	}
}
function Test-IfKeySavedToServer {
	switch ($env:privateShare) {
		"True" { $privateShare = "$" }
		default { $privateShare = "" }
	}
	
	$ConnectionTest = Test-NetConnection $env:serverFqdn -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PingSucceeded 2>&1
	if ($ConnectionTest -eq $false) {
		Write-Host "|| Failed to connect to $env:serverFqdn, will try to save the key later."
	} else {
		function Search-SavedBitLockerKey { Test-Path "\\$env:serverFqdn\$env:fileShare$privateShare\$env:computername.txt" }
		if (!(Search-SavedBitLockerKey)) {
			Write-Host "|| Recovery key has not been saved yet, saving on $env:serverFqdn..."
	
			Search-BitLockerKey | Out-File "\\$env:serverFqdn\$env:fileShare$privateShare\$env:computername.txt"
	
			if (Search-SavedBitLockerKey) { Write-Host "|| - Successfully saved BitLocker recovery key on $env:serverFqdn." }
			else { Write-Host "|| - Failed to save BitLocker recovery key on $env:serverFqdn." }
		}
	}
}
function Test-IfKeySavedToAD {
	if ((Ninja-Property-Get BitLockerSavedToAD) -eq 1) {
		Write-Host "BitLocker already backed up to Active Directory"
	} else {
		$counter = 0
		function Search-FVEPath { Get-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" }
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
					else { Write-Host "|| - Failed to create property $($_.Name)" ; $counter++ }
				}
			}
		}
		function Invoke-BackupToAD {
			if ($counter -eq 0) {
				Write-Host "|| Backing up BitLocker to Active Directory..."
				$KeyProtectors = Get-BitLockerVolume -MountPoint $($ENV:SystemDrive) | Select-Object -ExpandProperty KeyProtector | Select-Object -ExpandProperty KeyProtectorId
				$KeyProtectors | ForEach-Object {
					try {
						Backup-BitLockerKeyProtector $($ENV:SystemDrive) -KeyProtectorId $_ 2>&1 >$null
						Set-Variable -Name "BackupError" -Value $Error[0] -Scope Script | Out-Null
						Throw
					} catch {
						if ($BackupError.Exception.Message -notlike "*The key protector specified cannot be used for this operation*") {
							Write-Host "|| - Successfully backed up BitLocker to Active Directory."
						}
					}
				}
			} else {
				Write-Host ">> Failed to set all required properties, cannot back up to Active Directory"
			}
		}
		if (!(Search-FVEPath)) {
			Write-Host "|| Creating FVE registry key..."

			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

			if (Search-FVEPath) {
				Write-Host "|| - Successfully created FVE Registry Key."

				Search-FVEProperties

				Invoke-BackupToAD
			} else {
				Write-Host ">> Failed to create FVE registry key, cannot back up to Active Directory."
			}
		} else {
			Search-FVEProperties

			Invoke-BackupToAD
		}
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
		# Test-IfKeySavedToEntra
	} elseif ( ($DSRegOutput.AzureADJoined -eq "YES") -and ($DSRegOutput.EnterpriseJoined -eq "NO") -and ($DSRegOutput.DomainJoined -eq "YES")) {
		# Hybrid-Joined
		# Test-IfKeySavedToEntra
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
	if ((Test-IfSaveLocationSpecified) -eq $true) {
		Test-IfKeySavedToServer 2>&1 >$null
	}
}

if (Test-BitLockerEnabled) {
	Write-Host "BitLocker already enabled."
	
	#Backup key to Ninja, AD, Entra, network location, or a combination
	Test-BitLockerBackups
} elseif ( (Search-BitLockerVolumeStatus) -eq "DecryptionInProgress" ) {
	Write-Host "BitLocker is decrypting the drive to be reconfigured."
} elseif ( (Get-CimInstance -ClassName Win32_EncryptableVolume  -Namespace "Root\CIMV2\Security\MicrosoftVolumeEncryption").IsVolumeInitializedForProtection -eq $True ) {
	Write-Host "BitLocker is pending reboot to begin encrypting."
} elseif ( (Search-BitLockerVolumeStatus) -eq "EncryptionInProgress" ) {
	Write-Host "BitLocker is encrypting the drive."
} elseif ( ( ($null -ne (Search-BitLockerKey)) -and ($null -eq (Search-BitLockerKey | Where-Object KeyProtectorType -eq Tpm)) ) -or #Bad Scenario #1: Key exists, but not setup to use TPM
	( ($null -eq (Search-BitLockerKey)) -and ((Search-BitLockerVolumeStatus) -eq "FullyEncrypted") ) -or 							#Bad Scenario #2: Key does not exist, but drive is encrypted
	( ((Search-BitLockerVolumeStatus) -eq "FullyEncrypted") -and ((Get-BitLockerVolume).ProtectionStatus -eq "Off") ) -or 			#Bad Scenario #3: Drive is encrypted but protection is off
	( (Get-BitLockerVolume) | Where-Object {($_.EncryptionMethod -ne "Aes256") -and ($_.EncryptionMethod -ne "none")} ) 			#Bad Scenario #4: Drive is not encrypted with AES256 (typically AES-128 instead)
) {
	Write-Host "|| BitLocker is enabled, but not configured properly. Disabling BitLocker so it can be reconfigured..."

	Get-BitLockerVolume | Disable-BitLocker | Out-Null
} else {
	Write-Host "|| Enabling BitLocker Drive Encryption..."

	# Encrypt system drive
	Get-BitLockerVolume | Where-Object MountPoint -eq $ENV:SystemDrive | Enable-BitLocker -EncryptionMethod AES256 -RecoveryPasswordProtector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

	# Encrypt and auto-unlock non-system drives that aren't USB drives
	Get-Disk | Where-Object {$_.bustype -ne 'USB'} | Get-Partition | Where-Object { $_.DriveLetter } | Where-Object {"$($_.DriveLetter):" -ne $ENV:SystemDrive} | Select-Object -ExpandProperty DriveLetter | ForEach-Object {
		Get-BitLockerVolume | Where-Object MountPoint -eq "$_`:" | Enable-BitLocker -EncryptionMethod AES256 -RecoveryPasswordProtector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Enable-BitLockerAutoUnlock | Out-Null
	}

	# If there is a result when searching for the BitLocker key, it was successful
	if ($null -ne (Search-BitLockerKey)) {
		Write-Host "|| - Successfully enabled BitLocker Drive Encryption. Restart to begin the encryption process."

		Search-BitLockerKey
	
		#Backup key to Ninja, AD, Entra, network location, or a combination
		Test-BitLockerBackups
	} else {
		Write-Host "|| - Failed to enable BitLocker Drive Encryption"
	}
}
