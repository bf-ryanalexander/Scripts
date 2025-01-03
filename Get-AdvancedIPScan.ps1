<#
  NAME:         Get-AdvancedIPScan
  DESCRIPTION:  Uses the Advanced IP Scan console utility to scan the network and save the results.
  EXPLANATION:  Checks if AIP is already downloaded,
                If no, downloads and extracts the portable Advanced IP Scan application
                  Uses a Ninja Parameter to pass a range specified when running the script, or scans the current network scope if one isn't specified
                  Saves the results of the scan to C:\temp\BrightFlow\AdvancedIPScanner\_aipresults.txt
                  Outputs the results of the scan to the Ninja Activity log
                If yes, runs the executable as described above
#>
param([String]$variable1='') #indicates range to scan (eg. 172.10.10.1-172.10.10.254)

# Customization options:
$aipURL = "https://YourWebsite.com/AdvancedIPScanner.zip" # Download link for Advanced IP Scanner || You can install AIP on a device then zip C:\Program Files (x86)\Advanced IP Scanner to upload to your server
$aipDirectory = "C:\YourDirectory" # Where to download and run Advanced IP Scanner

function Search-AIP { Test-Path "$aipDirectory\AdvancedIPScanner\advanced_ip_scanner_console.exe" }

$results = "$aipDirectory\AdvancedIPScanner\_AIPresults.txt"

function Invoke-AIP {
  if ($variable1 -eq '') {
    Write-Host "|| No Scope/CIDR was specified, requesting current network information..."

    $IPScope = ((Get-CimInstance -ClassName win32_networkadapterconfiguration -Filter ipenabled=1 | Where-Object {($_.DefaultIPGateway -ne $null) -and ($_.DefaultIPGateway -ne "")}).DefaultIPGateway | Select-Object -First 1) -replace '[^.]+$','0'
    $Subnet = (Get-CimInstance -ClassName win32_networkadapterconfiguration -Filter ipenabled=1 | Where-Object {($_.DefaultIPGateway -ne $null) -and ($_.DefaultIPGateway -ne "")} | Get-Unique).IPSubnet | Select-Object -First 1
    $CIDR = ( (-join ( $Subnet.ToString().split('.') | foreach {[convert]::ToString($_,2)} ) ).ToCharArray() | Where-Object {$_ -eq '1'} ).Count

    $variable1 = "$IPScope/$CIDR"
  }

  Write-Host "|| - Running scan on $variable1..."

  & "$aipDirectory\AdvancedIPScanner\advanced_ip_scanner_console.exe" /r:$variable1 /f:$results
  Get-Content $results
}

if (Search-AIP) {
  Write-Host "|| Advanced IP Scanner already downloaded."
  Invoke-AIP
} else {
  Write-Host "|| Downloading Advanced IP Scanner..."

  $clnt = new-object System.Net.WebClient
	$filename = "AdvancedIPScanner.zip"
	$file = "$aipDirectory\$filename"
	$clnt.DownloadFile($aipURL,$file)

	Expand-Archive -Path "$aipDirectory\$filename" -DestinationPath $aipDirectory -Force
	Remove-Item "$aipDirectory\$filename" -Confirm:$false -ErrorAction SilentlyContinue

  if (Search-AIP) {
    Invoke-AIP
  } else {
    Write-Host "|| - Failed to download Advanced IP Scanner."
  }
}
