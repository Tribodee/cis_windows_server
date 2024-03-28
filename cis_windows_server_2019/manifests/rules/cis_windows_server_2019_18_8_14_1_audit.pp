class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_14_1_audit {
  exec {'cis_windows_server_2019_18_8_14_1_audit_ensure_boot_start_driver_initialization_policy_is_set_to_enabled_good_unknown_and_bad_but_critical':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy', '3, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy')
  }
}
