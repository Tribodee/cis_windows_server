class cis_windows_server_2019::rules::cis_windows_server_2019_17_6_3_audit {
  exec { 'cis_windows_server_2019_17_6_3_audit_ensure_audit_other_object_access_events_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Other Object Access Events', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Other Object Access Events'),
  }
}
