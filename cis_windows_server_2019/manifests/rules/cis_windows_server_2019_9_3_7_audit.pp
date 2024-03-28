class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_7_audit {
  $get_netfirewallprofile_raw = $facts['get_netfirewallprofile']
  $profile_data = $get_netfirewallprofile_raw['public']['logfilename']
  $setting_value = '%systemroot%\system32\LogFiles\Firewall\publicfw\.log'
  exec { 'cis_windows_server_2019_9_3_7_audit_ensure_windows_firewall_public_logging_name_is_set_to_systemroot_system32_logfiles_firewall_publicfw_log':
    unless  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\" | findstr \"${setting_value}\"",
    command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\"; exit 1",
  }
}
