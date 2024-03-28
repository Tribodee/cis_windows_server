class cis_windows_server_2019::rules::cis_windows_server_2019_9_2_5_audit {
  $get_netfirewallprofile_raw = $facts['get_netfirewallprofile']
  $profile_data = $get_netfirewallprofile_raw['private']['logfilename']
  $setting_value = '%systemroot%\system32\LogFiles\Firewall\privatefw\.log'
  exec { 'cis_windows_server_2019_9_2_5_audit_ensure_windows_firewall_private_logging_name_is_set_to_systemroot_system32_logfiles_firewall_privatefw_log':
    unless  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\" | findstr \"${setting_value}\"",
    command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\"; exit 1",
  }
}
