class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_27_2_1_audit {
  exec {'cis_windows_server_2019_18_9_27_2_1_audit_ensure_security_control_event_log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\Retention')
  }
}
