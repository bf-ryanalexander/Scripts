: '
	.SYNOPSIS
		Installs Huntress System Extension
	.DESCRIPTION 
		Ensures the Huntress System Extension is installed, which may not happen automatically if Huntress is not preauthorized prior to install
	.NOTES
		2025-12-30: V1.0 - Initial version
	.FUNCTIONALITY
		Automates the installation of the Huntress System Extension to reduce manual intervention
	.LINK
		https://github.com/bf-ryanalexander/Scripts/blob/main/macOS/Install-HuntressExtension.sh
'
function HuntressStatus {
	sudo /Applications/Huntress.app/Contents/MacOS/Huntress extensionctl status
}

if command -v 'HuntressStatus' > /dev/null
then
	function ExtensionStatus {
		ExtensionStatusString=$('HuntressStatus' | grep "Extension Status") ; ExtensionStatusString=$([[ $ExtensionStatusString =~ ([^[:space:]]*$) ]] && echo "${BASH_REMATCH[1]}")
		echo $ExtensionStatusString # installed/notInstalled
	}

	if [[ $('ExtensionStatus') == "installed" ]]
	then echo "Huntress extension already installed."
	else
		# Huntress is installed, checking Full Disk Access Status
		function FDAStatus {
			FDAStatusString=$('HuntressStatus' | grep "Full Disk Access for Agent") ; FDAStatusString=$([[ $FDAStatusString =~ ([^[:space:]]*$) ]] && echo "${BASH_REMATCH[1]}")
			echo $FDAStatusString # true/false
		}

		if [[ $('FDAStatus') == "true" ]]
		then
			# Huntress has Full Disk Access, checking Preauthorization Status
			function PreauthorizationStatus {
				PreauthorizationStatusString=$('HuntressStatus' | grep "Preauthorization Status") ; PreauthorizationStatusString=$([[ $PreauthorizationStatusString =~ ([^[:space:]]*$) ]] && echo "${BASH_REMATCH[1]}")
				echo $PreauthorizationStatusString # granted/notGranted
			}

			function InstallExtension {
				echo "|| Installing Huntress extension..."

				sudo /Applications/Huntress.app/Contents/MacOS/Huntress extensionctl install > /dev/null

				if [[ $('ExtensionStatus') == "installed" ]]
				then echo "|| - Successfully installed Huntress extension."
				else echo ">> - Failed to install Huntress extension."
				fi
			}

			if [[ $('PreauthorizationStatus') == "granted" ]]
			then
				# Huntress is preauthorized, check extension status
				if [[ $('ExtensionStatus') == "installed" ]]
				then echo "Huntress extension already installed."
				else 'InstallExtension'
				fi
			else
				# The extension needs to be preauthorized and installed
				echo "|| Authorizing Huntress extension..."

				sudo /Applications/Huntress.app/Contents/MacOS/Huntress extensionctl install --preauthorize > /dev/null

				if [[ $('PreauthorizationStatus') == "granted" ]]
				then
					echo "|| - Successfully authorized Huntress extension."

					'InstallExtension'
				else echo ">> - Failed to authorize Huntress extension. Check if the Huntress PPPC Profile is installed and try again."
				fi
			fi
		else echo ">> Huntress does not have Full Disk Access."
		fi
	fi
else echo ">> Huntress install not found."
fi
