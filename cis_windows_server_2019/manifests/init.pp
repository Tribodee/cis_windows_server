class cis_windows_server_2019 (
  Array[String]           $exclude_rules = [],
  Enum['ensure','audit']  $action,
  Array[String]           $windows_server_audit_rules,
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
##################################################### FACTS ##########################################################
#Check Get-NetFireWallProfile
function cis_windows_server_2019::check_firewall(String $profile_zone, String $setting_type, String $setting_value){
  $get_netfirewallprofile_raw = $facts['get_netfirewallprofile']
  if $get_netfirewallprofile_raw[$profile_zone][$setting_type]{
    $profile_data = $get_netfirewallprofile_raw[$profile_zone][$setting_type]
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c '${profile_data}' -like '${setting_value}' | findstr True"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c exit 1"
    return $result
  }
}
function cis_windows_server_2019::check_firewall_value(String $profile_zone, String $setting_type){
  $get_netfirewallprofile_raw = $facts['get_netfirewallprofile']
  if $get_netfirewallprofile_raw[$profile_zone][$setting_type]{
    $profile_data = $get_netfirewallprofile_raw[$profile_zone][$setting_type]
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\" ; exit 1"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo 'This policy is not exist' ; exit 1"
    return $result
  }
}
######################################################################################################################
#Check Auditpol
function cis_windows_server_2019::check_auditpol(String $auditsetting, String $auditvalue){
  $auditpolicy_raw = $facts['auditpolicy']
  if $auditpolicy_raw[$auditsetting]{
    $selectpolicy= $auditpolicy_raw[$auditsetting]
    $removeempty = $auditvalue.strip()
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c '${selectpolicy}' -like '${removeempty}' | findstr True"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c exit 1"
    return $result
  }
}
function cis_windows_server_2019::check_auditpol_value(String $auditsetting){
  $auditpolicy_raw = $facts['auditpolicy']
  if $auditpolicy_raw[$auditsetting]{
    $selectpolicy= $auditpolicy_raw[$auditsetting]
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${selectpolicy}\" ; exit 1"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo 'This policy is not exist' ; exit 1"
    return $result
  }
}
######################################################################################################################
#Check Gpresult
function cis_windows_server_2019::check_gpresult(String $gpresultsetting, String $gpresultvalue){
  $gpresult_raw = $facts['gpresult_facts']
  if $gpresult_raw[$gpresultsetting]{
    $selectgpo = $gpresult_raw[$gpresultsetting]['Computer Setting']
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c '${selectgpo}' -like '${gpresultvalue}'| findstr True"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c exit 1"
    return $result
  }
}

function cis_windows_server_2019::check_gpresult_users(String $gpresultsetting, String $gpresultvalue) {
  $gpresult_raw = $facts['gpresult_facts']
  if $gpresult_raw[$gpresultsetting]{
    $selectgpo = $gpresult_raw[$gpresultsetting]['Computer Setting']
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c ('${gpresultvalue}' -split ',' | ForEach-Object {\$_.Trim()} | ForEach-Object { (('${selectgpo}' -split ',' | ForEach-Object {\$_.Trim()} | Sort-Object) -contains \$_) }) -notcontains \$false | findstr True"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c exit 1"
    return $result
  }
}

function cis_windows_server_2019::check_gpresult_value(String $gpresultsetting){
  $gpresult_raw = $facts['gpresult_facts']
  if $gpresult_raw[$gpresultsetting]{
    $selectgpo = $gpresult_raw[$gpresultsetting]['Computer Setting']
  $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo '${selectgpo}' ; exit 1"
  return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo 'This policy is not exist' ; exit 1"
    return $result
  }
}

function cis_windows_server_2019::check_gpresult_folder_id(String $gpresultsetting, String $gpresultvalue, String $gpresultstate){
  $gpresult_raw = $facts['gpresult_facts']
  if $gpresult_raw[$gpresultsetting]{
    $selectvalue = $gpresult_raw[$gpresultsetting]['Value']
    $selectstate = $gpresult_raw[$gpresultsetting]['State']
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c !(('${selectvalue}' -like '${gpresultvalue}') , ('${selectstate}' -like '${gpresultstate}') | findstr False) | findstr True"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c exit 1"
    return $result
  }
}
function cis_windows_server_2019::check_gpresult_folder_id_value(String $gpresultsetting){
  $gpresult_raw = $facts['gpresult_facts']
  if $gpresult_raw[$gpresultsetting]{
    $selectvalue = $gpresult_raw[$gpresultsetting]['Value']
    $selectstate = $gpresult_raw[$gpresultsetting]['State']
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo '\"[Value : ${selectvalue}]\" \"[State : ${selectstate}]\"' ; exit 1"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo 'This policy is not exist' ; exit 1"
    return $result
  }
}
function cis_windows_server_2019::check_gpresult_folder_id_value_greater(String $gpresultsetting, String $gpresultvalue, String $gpresultstate){
  $gpresult_raw = $facts['gpresult_facts']
  if $gpresult_raw[$gpresultsetting]{
    $selectvalue = $gpresult_raw[$gpresultsetting]['Value']
    $selectstate = $gpresult_raw[$gpresultsetting]['State']
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c !(!(Write-Output \$([BitConverter]::ToInt32(@(${selectvalue}), 0) -lt [BitConverter]::ToInt32(@(${gpresultvalue}), 0))) , ('${selectstate}' -like '${gpresultstate}') | findstr False) | findstr True"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c exit 1"
    return $result
  }
}
function cis_windows_server_2019::check_gpresult_folder_id_value_less(String $gpresultsetting, String $gpresultvalue, String $gpresultstate){
  $gpresult_raw = $facts['gpresult_facts']
  if $gpresult_raw[$gpresultsetting]{
    $selectvalue = $gpresult_raw[$gpresultsetting]['Value']
    $selectstate = $gpresult_raw[$gpresultsetting]['State']
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c !((Write-Output \$([BitConverter]::ToInt32(@(${selectvalue}), 0) -le [BitConverter]::ToInt32(@(${gpresultvalue}), 0))) , ('${selectstate}' -like '${gpresultstate}') | findstr False) | findstr True"
    return $result
  }else{
    $result = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c exit 1"
    return $result
  }
}
