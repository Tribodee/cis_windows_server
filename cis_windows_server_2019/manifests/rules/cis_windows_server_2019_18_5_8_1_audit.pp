class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_8_1_audit {
  exec {'cis_windows_server_2019_18_5_8_1_audit_ensure_enable_insecure_guest_logons_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth')
  }
}
