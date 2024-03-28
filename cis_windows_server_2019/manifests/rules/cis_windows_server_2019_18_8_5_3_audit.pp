class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_5_3_audit {
  exec {'cis_windows_server_2019_18_8_5_3_audit_ensure_turn_on_virtualization_based_security_virtualization_based_protection_of_code_integrity_is_set_to_enabled_with_uefi_lock':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity')
  }
}
