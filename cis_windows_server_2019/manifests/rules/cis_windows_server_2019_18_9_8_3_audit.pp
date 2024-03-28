class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_8_3_audit {
  exec {'cis_windows_server_2019_18_9_8_3_audit_ensure_turn_off_autoplay_is_set_to_enabled_all_drives':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun', '255, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('')
  }
}
