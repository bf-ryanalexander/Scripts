<#
	.SYNOPSIS
    	Allows Ninja services to run in Safe Mode with Networking
	.DESCRIPTION
		Creates registry entries in the allow list for Safe Mode with Networking for the Ninja Agent and Ninja Remote services
	.NOTES
		2023-04-19: V1.0 - Initial version
	.FUNCTIONALITY
		Allows remote access to devices that have been started in Safe Mode for removal of EDR products and diagnosing boot issues
#>
$NinjaServices = @("NinjaRMMAgent","ncstreamer")
$counter = 0

function Search-SafeModeServices { Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\* | Where-Object PSChildName -in $NinjaServices }
function Search-PropertyValue { (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\$Service).'(default)' }
function Enable-ServiceSafeMode {
	Set-Item HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\$Service -Value Service

	if (($Service -in (Search-SafeModeServices).PSChildName) -and ((Search-PropertyValue) -eq "Service")) { Write-Host "|| - Successfully allowed $Service to run in Safe Mode." }
	else { Write-Host "|| - Failed to allow $Service to run in Safe Mode." }
}

foreach ($Service in $NinjaServices) {
	if ($Service -notin (Search-SafeModeServices).PSChildName) {
		Write-Host "|| Allowing $Service in Safe Mode..." ; $counter++

		New-Item HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\$Service | Out-Null

		Enable-ServiceSafeMode
	} else {
		if ((Search-PropertyValue) -ne "Service") {
			Write-Host "|| Updating registry property for $Service..." ; $counter++

			Enable-ServiceSafeMode
		}
	}
}
