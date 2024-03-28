class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_67_2_audit {
  exec {'cis_windows_server_2019_18_9_67_2_audit_ensure_allow_cloud_search_is_set_to_enabled_disable_cloud_search':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCloudSearch', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCloudSearch')
  }
}
