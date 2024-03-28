class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_65_3_11_1_audit {
  exec {'cis_windows_server_2019_18_9_65_3_11_1_audit_ensure_do_not_delete_temp_folders_upon_exit_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit')
  }
}
