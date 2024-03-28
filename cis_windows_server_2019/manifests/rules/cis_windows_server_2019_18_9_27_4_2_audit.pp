class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_27_4_2_audit {
  exec {'cis_windows_server_2019_18_9_27_4_2_audit_ensure_system_specify_the_maximum_log_file_size_kb_is_set_to_enabled_32768_or_greater':
    unless => cis_windows_server_2019::check_gpresult_folder_id_value_greater ('SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize', '0, 128, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize')
  }
}
