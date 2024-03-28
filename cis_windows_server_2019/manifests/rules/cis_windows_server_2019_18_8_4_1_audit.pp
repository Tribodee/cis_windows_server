class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_4_1_audit {
  exec {'cis_windows_server_2019_18_8_4_1_audit_ensure_encryption_oracle_remediation_is_set_to_enabled_force_updated_clients':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle', '2, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle')
  }
}
