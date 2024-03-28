class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_65_2_2_audit {
  exec {'cis_windows_server_2019_18_9_65_2_2_audit_ensure_do_not_allow_passwords_to_be_saved_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'),
  }
}
