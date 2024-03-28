class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_17_9_audit {
  exec {'cis_windows_server_2019_2_3_17_9_audit_ensure_user_account_control_virtualize_file_and_registry_write_failures_to_per_user_locations_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization'),
  }
}
