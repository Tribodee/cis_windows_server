class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_6_1_audit {
  exec {'cis_windows_server_2019_18_9_6_1_audit_ensure_allow_microsoft_accounts_to_be_optional_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional')
  }
}
