$LogPath = "C:\Temp\BrightFlow\Logs\Pings"

if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory $LogPath }

$Addresses = @(
	$env:firewallInternalIp
	$env:firewallExternalIp
	$env:ispGateway
	$env:internetIP
	$env:internetFQDN
	$env:other_1
	$env:other_2
	$env:other_3
	$env:other_4
)

if (-not ([string]::IsNullOrWhiteSpace($Addresses))) {
	foreach ($address in $Addresses) {
		if (-not ([string]::IsNullOrWhiteSpace($address))) {
			$Job = Start-Job -ScriptBlock { ping -t $using:address | Foreach {"{0} - {1}" -f (Get-Date),$_ } | Out-File "$using:LogPath\$(Get-Date -Format s)_$using:address.txt" -Append }

			Write-Host "Started ping to $address with job ID $($Job.Id)."
		}
	}
} else { Write-Host "No addresses were entered, please try again." }
