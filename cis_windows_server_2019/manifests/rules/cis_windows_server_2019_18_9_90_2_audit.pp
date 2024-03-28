class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_90_2_audit {
  exec {'cis_windows_server_2019_18_9_90_2_audit_ensure_always_install_with_elevated_privileges_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated')
  }
}
