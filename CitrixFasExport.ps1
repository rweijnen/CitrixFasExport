function Test-Admin
{
	$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize()
{
	if (-not (Test-Admin))
	{
		# Restart with elevated privileges
		Start-Process powershell.exe "-File `"$PSCommandPath`"" -Verb RunAs
	}
	
	# your FAS server name here (or Localhost)
	$global:CitrixFasAddress = 'localhost'
	
	# load Citrix FAS PowerShell SnapIn
	Add-PSSnapin Citrix.Authentication.FederatedAuthenticationService.V1 -ErrorAction:SilentlyContinue
	
	# Add some .NET Types that we need
	Add-Type -Path "c:\Program Files\Citrix\Federated Authentication Service\Citrix.Authentication.UserCredentialServices.PkiCore.dll"
	Add-Type -Path 'c:\Program Files\Citrix\Federated Authentication Service\Citrix.Authentication.UserCredentialServices.Service.dll'
}


<#
	.SYNOPSIS
		Export FAS User Certificate to PFX with Private Key
	
	.DESCRIPTION
		This function will either retrieve the FAS User Certificate or create a new one if none is found and export it as a PFX file with private key.
		
		If the Username parameter is omitted, it will export the certificates for all Active Directory users.
		
		Note that it's not possible to obtain a FAS certificate for a disabled account or for accounts with a userPrincipal name.
	
	.PARAMETER Path
		Folder where the PFX file(s) will be stored, they will be saved with the username as filename and the PFX extension
	
	.PARAMETER Username
		The username for which you want to export the FAS User Certiticate. If omitted, will attempt to export the certificates for all AD accounts
	
	.PARAMETER Password
		Password to be used for protecting the PFX file(s), default value is Passw0rd
	
	.EXAMPLE
		PS C:\> Export-FasUserCertificate -Path "C:\temp"
	
	.NOTES
		Additional information about the function.
#>
function Export-FasUserCertificate
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				   Position = 1)]
		[System.IO.FileInfo]$Path,
		[Parameter(Mandatory = $false)]
		[string]$Username,
		[string]$Password = 'Passw0rd'
	)
	
	begin
	{
		$domain = New-Object System.DirectoryServices.DirectoryEntry
		Write-Verbose "Using domain: $($domain.Name.ToUpper())"
		
		$ruleName = Get-FasRule | select -ExpandProperty Name
		Write-Verbose "Using Fas Rule: $ruleName"
		$definitionName = Get-FasCertificateDefinition | select -ExpandProperty Name
		Write-Verbose "Using Certificate Definition: $definitionName"
		
		$searcher = New-Object System.DirectoryServices.DirectorySearcher($domain)
		if ([String]::IsNullOrEmpty($Username))
		{
			Write-Verbose "Enumerating AD Users..."
			$samAccountName = "*"
		}
		else
		{
			$samAccountName = $Username
		}
		
		# only retrieve accounts with a valid UPN
		$searcher.Filter = "(&(objectCategory=User)(sAMAccountName=$samAccountName)(userPrincipalName=*))"
		[Void]$searcher.PropertiesToLoad.Add("sAMAccountName")
		[Void]$searcher.PropertiesToLoad.Add("userPrincipalName")
		[Void]$searcher.PropertiesToLoad.Add("userAccountControl")
		$results = $searcher.FindAll()
		Write-Verbose "Found $($results.Count) users"
	}
	
	process
	{
		
		for ($i = 0; $i -lt $results.Count; $i++)
		{
			$item = $results[$i]
			$samAccountName = $item.Properties["sAMAccountName"] | Select-Object -First 1
			Write-Verbose "Processing $sAMAccountName"
			
			$upn = $item.Properties["userPrincipalName"] | Select-Object -First 1
			Write-Verbose "UPN: $upn"
			
			$userAccountControl = $item.Properties["userAccountControl"] | Select-Object -First 1
			
			$outerProgressParam = @{
				Activity = "Processing $($results.Count) users"
				Status   = "Processing user $($i): $sAMAccountName"
				PercentComplete = (($i + 1) / $results.Count * 100)
			}
			
			Write-Progress @outerProgressParam
			
			$disabled = ($userAccountControl -band 2) -eq 2
			if ($disabled)
			{
				Write-Verbose "Skipping disabled account $sAMAccountName"
			}
			
			else
			{
				$innerProgressParam = @{
					ID	     = "1"
					Activity = "Processing $sAMAccountName"
					Status   = "Get User X500 Distinguished Name"
					PercentComplete = 0
				}
				
				Write-Progress @innerProgressParam
				
				$dnString = 'CN={0}\{1}' -f $domain.Name.ToString().ToUpper(), $samAccountName
				Write-Verbose "X500 DN: $dnString"
				
				$x500dn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($dnString)
				$enc = New-Object System.Text.ASCIIEncoding
				$dnBase64Encoded = [System.Convert]::ToBase64String($x500dn.RawData)
				
				$innerProgressParam = @{
					ID	     = "1"
					Activity = "Processing $sAMAccountName"
					Status   = "Get FAS User Certificate"
					PercentComplete = 10
				}
				Write-Progress @innerProgressParam
				
				# retrieve user certificate from FAS including keyinfo (we need the guid)
				$fasUserCertificate = Get-FasUserCertificate -UserPrincipalName $upn -KeyInfo:$true
				if ($null -eq $fasUserCertificate)
				{
					$innerProgressParam = @{
						ID	     = "1"
						Activity = "Processing $sAMAccountName"
						Status   = "Creating FAS User Certificate"
						PercentComplete = 20
					}
					Write-Progress @innerProgressParam
					
					Write-Verbose "Creating FAS User Certificate for $upn"
					# or create it if it didn't already exist...
					$fasUserCertificate = New-FasUserCertificate -UserPrincipalName $upn -Rule $ruleName -CertificateDefinition $definitionName
					# retrieve user certificate from FAS including keyinfo (we need the guid)
					$fasUserCertificate = Get-FasUserCertificate -UserPrincipalName $upn -KeyInfo:$true
				}
				else
				{
					Write-Verbose "Found existing FAS User Certificate for $upn"
				}
				
				$innerProgressParam = @{
					ID	     = "1"
					Activity = "Processing $sAMAccountName"
					Status   = "Convert FAS User Certificate to X509Certificate2"
					PercentComplete = 30
				}
				Write-Progress @innerProgressParam
				
				# convert the PEM certificate to .NET X509Certificate type
				$certBytes = $enc.GetBytes($fasUserCertificate.Certificate)
				$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New()
				$cert.Import($certBytes)
				
				$innerProgressParam = @{
					ID	     = "1"
					Activity = "Processing $sAMAccountName"
					Status   = "Obtain Private Key from Citrix FAS"
					PercentComplete = 40
				}
				Write-Progress @innerProgressParam
				
				# create FAS trust parameters from JSON
				# adding NoProtection so we can export with private key
				$json = [String]::Format('{{"PrivateKeyIdentifier":"{0}","KeyProtection":"NoProtection","ProviderLegacyCsp":false,"ProviderName":"Microsoft Software Key Storage Provider","KeyLength":2048,"DistinguishedName":"{1}","MachineWide":false,"EllipticCurve":false,"ProviderType":0}}', $fasUserCertificate.PrivateKeyIdentifier, $dnBase64Encoded)
				
				# build parameters
				$parameters = [Citrix.Authentication.UserCredentialServices.PkiCore.CertificateStorage.TrustAreaJoinParameters]::FromJson($json)
				
				# ask FAS for the private key please
				$privateKey = [Citrix.Authentication.UserCredentialServices.PkiCore.CertificateStorage.PrivateKey]::Create($parameters)
				if ($privateKey)
				{
					Write-Verbose "Obtained private key from FAS for user $upn"
				}
				else
				{
					return
				}
				
				$innerProgressParam = @{
					ID	     = "1"
					Activity = "Processing $sAMAccountName"
					Status   = "Assign Private Key to certificate"
					PercentComplete = 60
				}
				Write-Progress @innerProgressParam
				
				# add the private key to the cert
				$privateKey.AssignToCertificate($cert)
				Write-Verbose "Assigning private key to certificate for user $upn"
				
				$innerProgressParam = @{
					ID	     = "1"
					Activity = "Processing $sAMAccountName"
					Status   = "Export Certificate to PFX"
					PercentComplete = 80
				}
				Write-Progress @innerProgressParam
				
				# export to pfx with private key
				$pfxBytes = $cert.Export("pfx", $Password)
				$pfxFilename = Split-Path $dnString -Leaf
				$pfxFilename = [IO.Path]::Combine($Path, $pfxFilename + ".pfx")
				[IO.File]::WriteAllBytes($pfxFilename, $pfxBytes)
				Write-Verbose "Saved to $pfxFilename"
				
				$innerProgressParam = @{
					ID	     = "1"
					Activity = "Processing $sAMAccountName"
					Status   = "Finished."
					PercentComplete = 100
				}
				Write-Progress @innerProgressParam
				
			}
		}
	}
	
	
	end
	{ }
}

# load required modules
Initialize
