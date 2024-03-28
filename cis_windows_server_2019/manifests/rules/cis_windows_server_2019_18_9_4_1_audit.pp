class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_4_1_audit {
  exec {'cis_windows_server_2019_18_9_4_1_audit_ensure_allow_a_windows_app_to_share_application_data_between_users_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\AllowSharedLocalAppData')
  }
}
