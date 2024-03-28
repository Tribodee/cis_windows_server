class cis_windows_server_2019::rules::cis_windows_server_2019_18_1_3_audit {
  exec {'cis_windows_server_2019_18_1_3_audit_ensure_allow_online_tips_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\AllowOnlineTips', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\AllowOnlineTips')
  }
}
