class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_17_6_audit {
  exec {'cis_windows_server_2019_2_3_17_6_audit_ensure_user_account_control_only_elevate_uiaccess_applications_that_are_installed_in_secure_locations_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths'),
  }
}
