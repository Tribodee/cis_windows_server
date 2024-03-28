class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_21_4_audit {
  exec {'cis_windows_server_2019_18_8_21_4_audit_ensure_continue_experiences_on_this_device_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\EnableCdp', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\EnableCdp')
  }
}
