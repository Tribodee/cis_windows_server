####################################################################################################################################################
# $gpoName = "Test"

# $gpoSettingPath = "Computer\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Allow anonymous SID/Name translation"

# $gpo = Get-GPO -Name $gpoName

# $gpoSettingValue = Get-GPRegistryValue -Guid $gpo.Id -Key $gpoSettingPath

# if ($gpoSettingValue.RegistryValue -eq 0) {
#     Write-Host "The setting '$gpoSettingPath' in GPO '$gpoName' is already set to 'Disabled'."
# } else {
#     Set-GPRegistryValue -Guid $gpo.Id -Key $gpoSettingPath -ValueName "Value" -Type DWord -Value 0
#     Write-Host "The setting '$gpoSettingPath' in GPO '$gpoName' has been set to 'Disabled'."
# }
####################################################################################################################################################

##Get-GPRegistryValue
$GPOName ="gpresult /R /Scope Computer /v |Select-String -Pattern 'Filtering:\s*(.+)'.Trim() | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }"
$RegistryKey = "";
Get-GPRegistryValue -Name $GPO -Key $RegistryKey

Function Get-GPAllRegistryValues{
	Param(
		[Parameter(
			ValueFromPipelineByPropertyName = $true
		)]
		[Alias('DisplayName')]
		[string]$Name
	)
	Begin{
		$BaseKeys = 'HKLM\System','HKLM\Software','HKCU\Software','HKCU\System'
		Function Get-GPRecursiveRegistryValues{
			[cmdletbinding()]
			Param(
				[string]$GPOName,
				[string]$RegistryKey
			)
			$GPORegistryValues = Get-GPRegistryValue -Name $GPOName -key $RegistryKey -ErrorAction SilentlyContinue
			Foreach($item in $GPORegistryValues){
				If ($item.ValueName){
				$item
				}Else{
					Get-GPRecursiveRegistryValues -key $item.FullKeyPath -GPOName $GPOName
				}
			}
		}
	}	
	Process{
		ForEach($RegistryKey in $BaseKeys){
			Get-GPRecursiveRegistryValues -GPOName $Name -Key $RegistryKey
		}
	}
	End{}
}
Get-GPO -Name $GPOName | Get-GPAllRegistryValues