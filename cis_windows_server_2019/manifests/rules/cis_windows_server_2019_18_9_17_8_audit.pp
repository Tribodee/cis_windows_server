class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_17_8_audit {
  exec {'cis_windows_server_2019_18_9_17_8_audit_ensure_toggle_user_control_over_insider_builds_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview')
  }
}
