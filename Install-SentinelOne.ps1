<#
	.SYNOPSIS
		SentinelOne installer
	.DESCRIPTION
		Installs the SentinelOne Agent on Windows devices.
	.NOTES
		2024-11-26: V1.0 - Initial version
	.FUNCTIONALITY
		Automatically deploys SentinelOne if it's not already installed on Windows devices.
#>
$Directory = "C:\temp"
$URL = "" # Insert your URL here
$SiteToken = "" # Insert your Site Token here
$filename = "SentinelOneInstaller.msi"
function Search-SentinelOne { Get-Service SentinelAgent -ErrorAction SilentlyContinue }

if (!(Search-SentinelOne)) {
	Write-Host "|| Downloading SentinelOne..."

	$client = new-object System.Net.WebClient
	$file = "$Directory\$filename"
	$client.DownloadFile($URL,$file)

	if (Test-Path "$Directory\$filename") {
		Write-Host "|| Installing SentinelOne..."

		msiexec /i "$Directory\$filename" /quiet /norestart SITE_TOKEN=$SiteToken
	
		Start-Sleep -Seconds 120
	
		if (Search-SentinelOne) { Write-Host "|| - Successfully installed SentinelOne." }
		else { Write-Host "|| - Failed to install SentinelOne." }
	} else { Write-Host "|| - Failed to download SentinelOne installer." }
} else { Write-Host "SentinelOne already installed." }
