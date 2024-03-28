class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_31_2_audit {
  exec {'cis_windows_server_2019_18_8_31_2_audit_ensure_allow_upload_of_user_activities_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\UploadUserActivities', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\UploadUserActivities')
  }
}
