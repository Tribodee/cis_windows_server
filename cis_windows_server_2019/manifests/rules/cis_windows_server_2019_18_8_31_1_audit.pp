class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_31_1_audit {
  exec {'cis_windows_server_2019_18_8_31_1_audit_ensure_allow_clipboard_synchronization_across_devices_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('Software\Policies\Microsoft\Windows\System\AllowCrossDeviceClipboard', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('Software\Policies\Microsoft\Windows\System\AllowCrossDeviceClipboard')
  }
}
