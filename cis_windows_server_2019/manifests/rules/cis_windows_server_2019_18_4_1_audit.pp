class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_1_audit {
  exec {'cis_windows_server_2019_18_4_1_audit_ensure_mss_autoadminlogon_enable_automatic_logon_not_recommended_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon')
  }
}
