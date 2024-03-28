class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_65_3_2_1_audit {
  exec {'cis_windows_server_2019_18_9_65_3_2_1_audit_ensure_restrict_remote_desktop_services_users_to_a_single_remote_desktop_services_session_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\fSingleSessionPerUser', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\fSingleSessionPerUser')
  }
}
