function Search-McAfee { Get-Package | Where-Object Name -Like "*McAfee*" }
	if (Search-McAfee) {
		if ("McAfee Host Intrusion Prevention" -in (Search-McAfee).Name) {
			Write-Host ">> McAfee Host Intrusion Prevention detected. Boot into Safe Mode to uninstall."
			# https://www.framepkg.com/how-to-uninstall-mcafee-client-manually/uninstall-mcafee-host-intrusion-prevention-forget-the-password
		} else {
			Write-Host "|| Uninstalling McAfee products..."

      # Download MCPR from here, upload to your hosting provider https://www.mcafee.com/support/s/article/000001616?language=en_US
			$url = "https://yoururl.com/MCPR.zip"
			$file = "C:\temp\MCPR.zip"
			$download = New-Object net.webclient
			$download.Downloadfile($url,$file)

			Expand-Archive -LiteralPath "C:\temp\MCPR.zip" -DestinationPath "C:\temp" -Force
			Remove-Item "C:\temp\MCPR.zip"

			& "C:\temp\MCPR\Mccleanup.exe" -p StopServices,MFSY,PEF,MXD,CSP,Sustainability,MOCP,MFP,APPSTATS,Auth,EMproxy,FWdiver,HW,MAS,MAT,MBK,MCPR,McProxy,McSvcHost,VUL,MHN,MNA,MOBK,MPFP,MPFPCU,MPS,SHRED,MPSCU,MQC,MQCCU,MSAD,MSHR,MSK,MSKCU,MWL,NMC,RedirSvc,VS,REMEDIATION,MSC,YAP,TRUEKEY,LAM,PCB,Symlink,SafeConnect,MGS,WMIRemover,RESIDUE -v -s
			Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee.WPS" -Recurse -ErrorAction SilentlyContinue

			Write-Host "|| - Uninstall completed, please reboot and try again."
		}
	}
