class cis_windows_server_2019::rules::cis_windows_server_2019_17_5_5_audit {
  exec { 'cis_windows_server_2019_17_5_5_audit_ensure_audit_other_logon_logoff_events_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Other Logon/Logoff Events', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Other Logon/Logoff Events'),
  }
}
