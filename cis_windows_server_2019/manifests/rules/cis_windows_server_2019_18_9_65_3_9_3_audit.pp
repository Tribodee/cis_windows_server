class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_65_3_9_3_audit {
  exec {'cis_windows_server_2019_18_9_65_3_9_3_audit_ensure_require_use_of_specific_security_layer_for_remote_rdp_connections_is_set_to_enabled_ssl':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer', '2, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer')
  }
}
