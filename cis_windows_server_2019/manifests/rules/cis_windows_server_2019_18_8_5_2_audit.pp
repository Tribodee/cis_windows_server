class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_5_2_audit {
  exec {'cis_windows_server_2019_18_8_5_2_audit_ensure_turn_on_virtualization_based_security_select_platform_security_level_is_set_to_secure_boot_and_dma_protection':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures', '3, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures')
  }
}
