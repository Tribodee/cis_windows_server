class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_27_2_2_audit {
  exec {'cis_windows_server_2019_18_9_27_2_2_audit_ensure_security_specify_the_maximum_log_file_size_kb_is_set_to_enabled_196608_or_greater':
    unless => cis_windows_server_2019::check_gpresult_folder_id_value_greater ('SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize', '0, 0, 3, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize')
  }
}
