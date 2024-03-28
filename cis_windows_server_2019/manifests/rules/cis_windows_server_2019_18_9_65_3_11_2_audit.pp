class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_65_3_11_2_audit {
  exec {'cis_windows_server_2019_18_9_65_3_11_2_audit_ensure_do_not_use_temporary_folders_per_session_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir')
  }
}
