class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_11_3_audit {
  exec {'cis_windows_server_2019_18_5_11_3_audit_ensure_prohibit_use_of_internet_connection_sharing_on_your_dns_domain_network_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI')
  }
}
