class cis_windows_server_2019::rules::cis_windows_server_2019_17_2_4_audit {
  exec { 'cis_windows_server_2019_17_2_4_audit_ensure_audit_other_account_management_events_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Other Account Management Events', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Other Account Management Events'),
  }
}
