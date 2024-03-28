class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_3_audit {
  exec {'cis_windows_server_2019_18_8_3_audit_ensure_include_command_line_in_process_creation_events_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled')
  }
}
