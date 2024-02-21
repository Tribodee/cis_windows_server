class cis_windows_server_2019::rules::cis_windows_server_2019_9_1_7_audit{
  $get_netfirewallprofile_raw = $facts['get_netfirewallprofile']
  $profile_data = $get_netfirewallprofile_raw['domain']['logfilename']
  $setting_value = '%systemroot%\system32\logfiles\firewall\domainfw\.log' # path should add \ before .
  exec {'cis_windows_server_2019_9_1_7_audit_ensure_windows_firewall_domain_logging_name_is_set_to_systemroot_system32_logfiles_firewall_domainfw_log':
    unless => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\" | findstr \"${setting_value}\"",
    command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /c echo \"${profile_data}\" ; exit 1",
  }
}
