class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_62_3_10_audit {
  exec {'cis_windows_server_2019_18_9_62_3_10_audit_ensure_set_time_limit_for_active_but_idle_remote_desktop_services_sessions_is_set_to_enabled_15_minutes_or_less':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime', '160, 187, 13, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime')
  }
}
