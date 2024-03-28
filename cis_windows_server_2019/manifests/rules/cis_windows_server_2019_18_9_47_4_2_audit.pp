class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_47_4_2_audit {
  exec {'cis_windows_server_2019_18_9_47_4_2_audit_ensure_join_microsoft_maps_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting')
  }
}
