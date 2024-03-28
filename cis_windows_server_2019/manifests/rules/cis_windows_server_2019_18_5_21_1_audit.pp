class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_21_1_audit {
  exec {'cis_windows_server_2019_18_5_21_1_audit_ensure_minimize_the_number_of_simultaneous_connections_to_the_internet_or_a_windows_domain_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections')
  }
}
