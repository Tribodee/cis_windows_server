class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_5_5_audit {
  exec {'cis_windows_server_2019_18_8_5_5_audit_ensure_turn_on_virtualization_based_security_credential_guard_configuration_is_set_to_enabled_with_uefi_lock_ms_only':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags')
  }
}
