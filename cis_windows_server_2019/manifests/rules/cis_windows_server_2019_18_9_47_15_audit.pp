class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_47_15_audit {
  exec {'cis_windows_server_2019_18_9_47_15_audit_ensure_configure_detection_for_potentially_unwanted_applications_is_set_to_enabled_block':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows Defender\PUAProtection', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows Defender\PUAProtection')
  }
}
