<#
	.SYNOPSIS
		Get info about an installed application's registry locations
	.DESCRIPTION
		Checks for machine-wide and per-user locations for installation/uninstallation info
	.NOTES
		2024-08-13: V2.0 - Refactored for machine-wide and per-user searching, more efficient/programatic for future additions
		2024-03-21: V1.0 - Initial version
	.FUNCTIONALITY
		Helps find stubborn-to-uninstall applications and easier access to UninstallStrings
	.LINK
		https://github.com/bf-ryanalexander/Scripts/blob/main/Get-InstalledAppInfo.ps1
#>
Write-Host "Searching for $env:applicationName..."

$Paths = [System.Collections.Generic.List[object]]::New()

$MachinePaths = @{
	"HKLM:\SOFTWARE\Classes\Installer\Products" = "ProductName"
	"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" = "DisplayName"
	"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" = "DisplayName"
}

# Collect machine-wide installer/uninstaller locations
foreach ($MachinePath in $MachinePaths.keys) {
	# "$MachinePaths.$MachinePath" accesses the Value from the Key/Value pair for the current $path being queried
	$path = New-Object PSObject
	$path | Add-Member -type NoteProperty -Name 'Path' -Value $MachinePath
	$path | Add-Member -type NoteProperty -Name 'Property' -Value $MachinePaths.$MachinePath
	$path | Add-Member -type NoteProperty -Name 'Location' -Value "Machine-Wide Install"

	$Paths.Add($path)
}

# Collect per-user installer/uninstaller locations
$DefaultSIDs = @(".DEFAULT","S-1-5-18","S-1-5-19","S-1-5-20")
$SIDs = (Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { ($_.PSChildName -notin $DefaultSIDs) -and ($_.PSChildName -notlike "*_Classes") }).PSChildName
foreach ($sid in $sids) {
	$path = New-Object PSObject
	$path | Add-Member -type NoteProperty -Name 'Path' -Value "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"
	$path | Add-Member -type NoteProperty -Name 'Property' -Value "DisplayName"
	$path | Add-Member -type NoteProperty -Name 'Location' -Value "Per-User Install"

	$Paths.Add($path)
	
	$path = New-Object PSObject
	$path | Add-Member -type NoteProperty -Name 'Path' -Value "Registry::HKEY_USERS\$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
	$path | Add-Member -type NoteProperty -Name 'Property' -Value "DisplayName"
	$path | Add-Member -type NoteProperty -Name 'Location' -Value "Per-User Install"

	$Paths.Add($path)
}

$Paths | ForEach-Object {
	Write-Host "`n----------------------------`n"
	Write-Host "|| Searching $($_.Path) ($($_.Location))..."

	$programs = Get-ItemProperty "$($_.Path)\*"

	if ($programs | Where-Object $($_.Property) -like "*$env:applicationName*") {
		$programs | Where-Object $($_.Property) -like "*$env:applicationName*"
	} else { Write-Host "|| - No matches found." }
}
