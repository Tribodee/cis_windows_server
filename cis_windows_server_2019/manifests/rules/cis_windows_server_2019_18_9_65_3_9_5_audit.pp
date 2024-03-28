class cis_windows_server_2019::rules::cis_windows_server_2019_18_9_65_3_9_5_audit {
  exec {'cis_windows_server_2019_18_9_65_3_9_5_audit_ensure_set_client_connection_encryption_level_is_set_to_enabled_high_level':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel', '3, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel')
  }
}
