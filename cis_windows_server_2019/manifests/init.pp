class cis_windows_server_2019 (
  Array[String] $windows_server_audit_rules,
  Array[String] $exclude_rules = [],
  String        $action,
) {
  $base_rules = $action ? {'audit'   => $windows_server_audit_rules,}

  # Build rules to enforce
  $base_rules_normalized = $base_rules.map | String $line | {
    "cis_windows_server_2019::rules::${line}"
  }
  $exclude_rules_normalized = $exclude_rules.map | String $line | {
    "cis_windows_server_2019::rules::${line}"
  }
  $windows_server_enforced_rules = $base_rules_normalized - $exclude_rules_normalized
  include $windows_server_enforced_rules
}
#Check Gpresult
function cis_windows_server_2019::check_gpresult(String $policy, String $policyvalue){
  $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c (gpresult /R /Scope Computer /v | Select-String ${policy} -Context 0,10).Context.PostContext | ForEach-Object {if (\$_ -ne \$null -and \$_.Trim() -ne '') {\$_.Trim()} else {break}} | ForEach-Object {if (\$_ -match '  ${policyvalue}') {}else {exit 1}}"
  return $result
}
function cis_windows_server_2019::check_gpresult_value(String $policy){
  $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c (gpresult /R /Scope Computer /v | Select-String ${policy} -Context 0,10).Context.PostContext | ForEach-Object { if (\$_ -ne \$null -and \$_.Trim() -ne '') { \$_.Trim() } else { exit 1 } }"
  return $result
}

#Check Auditpol
function cis_windows_server_2019::check_gpo(String $policy, String $policyvalue){
  $result ="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c auditpol /get /category:* | find ${policy} | find '  ${policyvalue}'"
  return $result
}
function cis_windows_server_2019::check_gpo_value(String $policy){
  $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c auditpol /get /category:* | find '  ${policy}' ; exit 1"
  return $result
}

#########FACTS############

#Check Get-NetFireWallProfile
function cis_windows_server_2019::check_firewall(String $profile_zone, String $setting_type, String $setting_value){
  $get_netfirewallprofile_raw = $facts['get_netfirewallprofile']
  $profile_data = $get_netfirewallprofile_raw[$profile_zone][$setting_type]
  $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\" | findstr \"\<${setting_value}\>\""
  return $result
}
function cis_windows_server_2019::check_firewall_value(String $profile_zone, String $setting_type){
  $get_netfirewallprofile_raw = $facts['get_netfirewallprofile']
  $profile_data = $get_netfirewallprofile_raw[$profile_zone][$setting_type]
  $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\" ; exit 1"
  return $result
}

#Check Auditpol
function cis_windows_server_2019::check_auditpol(String $auditsetting, String $auditvalue){
  $auditpolicy_raw = $facts['auditpolicy']
  $selectpolicy= $auditpolicy_raw[$auditsetting]
  $removeempty=$auditvalue.strip()
  # $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo '${selectpolicy}' | findstr \"*${removeempty}*\" "
  $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c '${selectpolicy}' -match '${removeempty}' | findstr True"
  # if ($result == true) {
  #     return $true
  # } else {
  #     return $false
  # }
  return $result
}
function cis_windows_server_2019::check_auditpol_value(String $auditsetting){
  $auditpolicy_raw = $facts['auditpolicy']
  $selectpolicy= $auditpolicy_raw[$auditsetting]
  $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${selectpolicy}\" ; exit 1"
  return $result
}
