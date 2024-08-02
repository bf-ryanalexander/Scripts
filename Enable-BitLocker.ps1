<#
	.SYNOPSIS
		Enables BitLocker Drive Encryption
	.DESCRIPTION
		Checks to see if the device is utilizing BitLocker Drive Encryption with TPM as the Key Protector Type and saves the recovery key to the specified location
	.NOTES
		2024-08-01: V2.2 - Added support for auto-unlocking non-system internal drives
		2024-07-31: V2.1 - Refactored to support Script Variables and be more efficient with fewer duplicate blocks of code
		2024-07-29: V2.0 - Fully revised what is classified as "Enabled", added new "Status" checks, better "Bad Scenario" checks
		2024-07-23: V1.0 - Initial version
	.FUNCTIONALITY
		Automates the encryption of managed devices to ensure consistent protection.
	.LINK
		https://github.com/bf-ryanalexander/Scripts/blob/main/Enable-BitLocker.ps1
	.NOTES
		TODO: Make more friendly for recurring scripts that utilize Custom Fields?
		TODO: Detect if AD/AAD and backup the key there as well https://github.com/homotechsual/Blog-Scripts/blob/main/Monitoring/DomainJoin.ps1
#>
function Search-BitLockerKey { (Get-BitLockerVolume -MountPoint $($ENV:SystemDrive)).KeyProtector }
function Search-BitLockerVolumeStatus { (Get-BitLockerVolume -MountPoint $ENV:SystemDrive).VolumeStatus }
function Search-BitLockerTypeIsTpm { (Get-BitLockerVolume).KeyProtector | Where-Object KeyProtectorType -eq Tpm }
function Test-BitLockerEnabled {
	@(
		# Drive is encrypted, a recovery key exists, uses TPM, and protection is enabled
		((Search-BitLockerVolumeStatus) -eq "FullyEncrypted") -and
		($null -ne (Search-BitLockerKey)) -and
		((Get-BitLockerVolume).KeyProtector -like "*Tpm*") -and
		((Get-BitLockerVolume).ProtectionStatus -eq "On")
	)
}
function Test-IfSaveLocationSpecified {
	$SaveLocationSpecified = @(
		($null -ne $env:serverFqdn),
		($null -ne $env:fileShare)
	)
	#if either field is specified
	if ($SaveLocationSpecified -eq $true) {
		#if both fields aren't specified
		if ( ($null -eq $env:serverFqdn) -or ($null -eq $env:fileShare) ) {
			Write-Host ">> A location was specified to save the recovery key, but all server information was not provided."
			Write-Host ">> Try again after the device reboots and finishes the encryption process."
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

if (Test-BitLockerEnabled) {
	Write-Host "BitLocker already enabled."

	if ((Test-IfSaveLocationSpecified) -eq $true) {
		Test-IfKeySavedToServer 2>&1 >$null
	}
} elseif ( (Get-CimInstance -ClassName Win32_EncryptableVolume  -Namespace "Root\CIMV2\Security\MicrosoftVolumeEncryption").IsVolumeInitializedForProtection -eq $True ) {
	Write-Host "BitLocker is pending reboot to begin encrypting."
} elseif ( ((Search-BitLockerVolumeStatus) -eq "EncryptionInProgress") ) {
	Write-Host "BitLocker is encrypting the drive."
} elseif ( ((Search-BitLockerVolumeStatus) -eq "DecryptionInProgress") ) {
	Write-Host "BitLocker is decrypting the drive to be reconfigured."
} elseif ( # Bad Scenarios
	#1: Key exists, but not setup to use TPM, #2: Key does not exist, but drive is encrypted, #3: Drive is encrypted but protection is off, #4: Drive is not encrypted with AES256 ( ($null -ne (Search-BitLockerKey)) -and ($null -eq (Search-BitLockerKey | Where-Object KeyProtectorType -eq Tpm)) ) -or
	( ($null -eq (Search-BitLockerKey)) -and ((Search-BitLockerVolumeStatus) -eq "FullyEncrypted") ) -or
	( ((Search-BitLockerVolumeStatus) -eq "FullyEncrypted") -and ((Get-BitLockerVolume).ProtectionStatus -eq "Off") ) -or
	( (Get-BitLockerVolume) | Where-Object {($_.EncryptionMethod -ne "Aes256") -and ($_.EncryptionMethod -ne "none")} )
) {
	Write-Host "|| BitLocker is enabled, but not configured properly. Disabling BitLocker..."

	Get-BitLockerVolume | Disable-BitLocker | Out-Null
} else {
	Write-Host "|| Enabling BitLocker Drive Encryption..."

	# Encrypt system drive
	Get-BitLockerVolume | Where-Object MountPoint -eq $ENV:SystemDrive | Enable-BitLocker -EncryptionMethod AES256 -RecoveryPasswordProtector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

	# Encrypt and auto-unlock non-system drives that aren't USB drives
	Get-Disk | Where-Object {$_.bustype -ne 'USB'} | Get-Partition | Where-Object { $_.DriveLetter } | Where-Object {"$($_.DriveLetter):" -ne $ENV:SystemDrive} | Select-Object -ExpandProperty DriveLetter | ForEach-Object {
		Get-BitLockerVolume | Where-Object MountPoint -eq "$_`:" | Enable-BitLocker -EncryptionMethod AES256 -RecoveryPasswordProtector -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Enable-BitLockerAutoUnlock | Out-Null
	}

	if ($null -ne (Search-BitLockerKey)) {
		Write-Host "|| - Successfully enabled BitLocker Drive Encryption. Restart to begin the encryption process."

		Search-BitLockerKey
	} else {
		Write-Host "|| - Failed to enable BitLocker Drive Encryption"
	}

	if ((Test-IfSaveLocationSpecified) -eq $true) {
		Test-IfKeySavedToServer 2>&1 >$null
	}
}
