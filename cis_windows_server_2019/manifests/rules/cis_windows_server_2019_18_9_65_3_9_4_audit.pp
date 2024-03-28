class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_65_3_9_4_audit {
  exec {'cis_windows_server_2019_18_9_65_3_9_4_audit_ensure_require_user_authentication_for_remote_connections_by_using_network_level_authentication_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication')
  }
}
