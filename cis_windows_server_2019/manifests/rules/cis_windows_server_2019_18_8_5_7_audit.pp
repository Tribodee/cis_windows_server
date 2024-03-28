class cis_windows_server_2019::rules::cis_windows_server_2019_18_8_5_7_audit {
  exec {'cis_windows_server_2019_18_8_5_7_audit_ensure_turn_on_virtualization_based_security_secure_launch_configuration_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch')
  }
}
