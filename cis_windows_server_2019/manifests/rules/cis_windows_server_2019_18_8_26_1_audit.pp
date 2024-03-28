class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_26_1_audit {
  exec {'cis_windows_server_2019_18_8_26_1_audit_ensure_enumeration_policy_for_external_devices_incompatible_with_kernel_dma_protection_is_set_to_enabled_block_all':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy', '0, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy')
  }
}
