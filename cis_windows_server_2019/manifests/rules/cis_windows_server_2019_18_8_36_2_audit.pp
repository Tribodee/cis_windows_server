class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_36_2_audit {
  exec {'cis_windows_server_2019_18_8_36_2_audit_ensure_configure_solicited_remote_assistance_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp')
  }
}
