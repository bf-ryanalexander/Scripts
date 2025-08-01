$DSUPath = "C:\temp"

if ($env:Path -notlike "*C:\Program Files\Dell\DELL System Update*") {
	try { dsu /v }
	catch {
		if ($_ -like "*The term 'dsu' is not recognized as the name of a cmdlet*") {
			Write-Host "|| Downloading and installing DSU..."

			$DellKBURL = 'https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=03gc8'
			$Headers = @{
				'accept'          = 'text/html'
				'accept-encoding' = 'gzip'
				'accept-language' = '*'
			}

			$ParsedURL = (([string](Invoke-WebRequest -UseBasicParsing -Uri $DellKBURL -Headers $Headers -ErrorAction Ignore) | Select-String 'https://dl\.dell\.com.+Systems-Management_Application_03GC8.+\.EXE').matches | Select-Object -First 1).Value
	
			if ($ParsedURL) { $url = $ParsedURL }
			else { $url = "https://dl.dell.com/FOLDER12418375M/1/Systems-Management_Application_03GC8_WN64_2.1.1.0_A00.EXE" }

			$file = "$DSUPath\dsu.exe"
			(New-Object net.webclient).Downloadfile($url,$file)
		
			if (Test-Path "$DSUPath\dsu.exe") {
				# Silently run the DSU executable and wait for it to be fully installed
				& $DSUPath\dsu.exe /i /s
				while (-not (Get-Package "Dell System Update" -ErrorAction SilentlyContinue)) { Start-Sleep 5 }
	
				# Refresh $env:Path for cmdlets
				$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
	
				if (dsu /v) {
					Write-Host "|| - Successfully installed DSU." 
					Write-Host "|| Running DSU now..."
	
					dsu
				} else { Write-Host "|| - Failed to install DSU." }
			} else { "|| - Failed to download DSU." }
		} else {
			Write-Host "DSU is already installed."
			Write-Host "|| Running DSU now..."
	
			dsu
		}
	}
} else {
	dsu
}
