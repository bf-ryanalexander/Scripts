# Establish directories
$hpiaDirectory = "C:\temp\HPIA"
$hpiaLogs = "C:\temp\Logs\HPIA"
if (-not(Test-Path $hpiaDirectory)) { New-Item -ItemType Directory $hpiaDirectory | Out-Null }
if (-not(Test-Path $hpiaLogs)) { New-Item -ItemType Directory $hpiaLogs | Out-Null }

if (Test-Path "$hpiaDirectory\HPImageAssistant.exe") {
	# Run HP Image Assistant if it's already installed
	Write-Host "|| Running HP Image Assistant..."
	& "$hpiaDirectory\HPImageAssistant.exe" /Operation:Analyze /Category:BIOS,Drivers,Firmware /Selection:All /Action:Install /SoftpaqDownloadFolder:$hpiaDirectory /Silent /ReportFolder:$hpiaLogs
} else {
	# Download HP Image Assistant
	#Retrieve newest installer
	$hpia_WR = Invoke-WebRequest -Uri "https://ftp.ext.hp.com/pub/caps-softpaq/cmit/HPIA.html" -UseBasicParsing
	$hpia_DownloadURL = $hpia_WR.Links | Where-Object href -Like "https://hpia.hpcloud.hp.com/downloads/hpia/*" | Select-Object -ExpandProperty href
	if (-not($hpia_DownloadURL)) { $hpia_DownloadURL = "https://hpia.hpcloud.hp.com/downloads/hpia/hp-hpia-5.3.4.exe" } # Fallback URL
	$hpia_InstallFileName = [System.IO.Path]::GetFileName($hpia_DownloadURL)

	#Download installer
	Write-Host "|| Downloading HPIA installer..."
	Add-Type -AssemblyName System.Web
	[Net.ServicePointManager]::SecurityProtocol = "Tls12"
	$hpia_installer = "$hpiaDirectory\$hpia_InstallFileName"
	(New-Object net.webclient).DownloadFile($hpia_DownloadURL,$hpia_installer)

	if (Test-Path $hpia_installer) {
		Write-Host "|| - Successfully downloaded installer."

		# Install HP Image Assistant
		Write-Host "|| Installing HPIA..."
		& $hpia_installer /s /e /f $hpiaDirectory

		Start-Sleep -Seconds 5

		if (Test-Path "$hpiaDirectory\HPImageAssistant.exe") {
			Write-Host "|| - Successfully installed HPIA."

			# Run HP Image Assistant
			Write-Host "|| Running HP Image Assistant..."
			& "$hpiaDirectory\HPImageAssistant.exe" /Operation:Analyze /Category:BIOS,Drivers,Firmware /Selection:All /Action:Install /SoftpaqDownloadFolder:$hpiaDirectory /Silent /ReportFolder:$hpiaLogs
		} else { Write-Host ">> - Failed to install HPIA." }
	} else { Write-Host ">> - Failed to download installer." }
}
