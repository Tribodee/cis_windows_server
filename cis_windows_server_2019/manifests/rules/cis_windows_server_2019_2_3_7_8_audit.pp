class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_8_audit {
  exec {'cis_windows_server_2019_2_3_7_8_audit_ensure_interactive_logon_require_domain_controller_authentication_to_unlock_workstation_is_set_to_enabled_ms_only':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon'),
  }
}
