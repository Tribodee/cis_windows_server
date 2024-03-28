class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_5_4_audit {
  exec {'cis_windows_server_2019_18_8_5_4_audit_ensure_turn_on_virtualization_based_security_require_uefi_memory_attributes_table_is_set_to_true_checked':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired')
  }
}
