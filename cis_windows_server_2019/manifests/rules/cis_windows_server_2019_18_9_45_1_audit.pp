class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_45_1_audit {
  exec {'cis_windows_server_2019_18_9_45_1_audit_ensure_allow_message_service_cloud_sync_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Messaging\AllowMessageSync', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Messaging\AllowMessageSync')
  }
}
