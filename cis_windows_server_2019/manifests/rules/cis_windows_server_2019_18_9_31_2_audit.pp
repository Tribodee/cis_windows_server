class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_31_2_audit {
  exec {'cis_windows_server_2019_18_9_31_2_audit_ensure_turn_off_data_execution_prevention_for_explorer_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention','','disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention')
  }
}
