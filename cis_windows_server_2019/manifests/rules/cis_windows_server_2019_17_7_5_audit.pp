class cis_windows_server_2019::rules::cis_windows_server_2019_17_7_5_audit {
  exec { 'cis_windows_server_2019_17_7_5_audit_ensure_audit_other_policy_change_events_is_set_to_include_failure':
    unless  => cis_windows_server_2019::check_auditpol('Other Policy Change Events', 'Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Other Policy Change Events'),
  }
}
