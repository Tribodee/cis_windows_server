class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_5_1_audit {
  exec {'cis_windows_server_2019_18_5_5_1_audit_ensure_enable_font_providers_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\EnableFontProviders', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\EnableFontProviders')
  }
}
