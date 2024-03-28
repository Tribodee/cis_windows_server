class cis_windows_server_2019::rules::cis_windows_server_2019_18_1_1_1_audit {
  exec {'cis_windows_server_2019_18_1_1_1_audit_ensure_prevent_enabling_lock_screen_camera_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera', '1, 0, 0, 0', 'Enabled'),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'),
  }
}
