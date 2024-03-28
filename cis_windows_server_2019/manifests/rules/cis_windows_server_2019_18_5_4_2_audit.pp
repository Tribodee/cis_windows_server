class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_4_2_audit {
  exec {'cis_windows_server_2019_18_5_4_2_audit_ensure_turn_off_multicast_name_resolution_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast')
  }
}
