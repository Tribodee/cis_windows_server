class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_21_2_audit {
  exec {'cis_windows_server_2019_18_5_21_2_audit_ensure_prohibit_connection_to_non_domain_networks_when_connected_to_domain_authenticated_network_is_set_to_enabled_ms_only':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain')
  }
}
