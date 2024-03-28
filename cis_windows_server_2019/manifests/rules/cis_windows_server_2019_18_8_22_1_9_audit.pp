class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_22_1_9_audit {
  exec {'cis_windows_server_2019_18_8_22_1_9_audit_ensure_turn_off_the_order_prints_picture_task_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoOnlinePrintsWizard', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoOnlinePrintsWizard')
  }
}
