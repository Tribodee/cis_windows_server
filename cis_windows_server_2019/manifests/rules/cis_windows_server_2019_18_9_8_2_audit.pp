class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_8_2_audit {
  exec {'cis_windows_server_2019_18_9_8_2_audit_ensure_set_the_default_behavior_for_autorun_is_set_to_enabled_do_not_execute_any_autorun_commands':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun')
  }
}
