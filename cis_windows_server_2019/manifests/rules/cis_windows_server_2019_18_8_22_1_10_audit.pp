class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_22_1_10_audit {
  exec {'cis_windows_server_2019_18_8_22_1_10_audit_ensure_turn_off_the_publish_to_web_task_for_files_and_folders_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPublishingWizard', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPublishingWizard')
  }
}
