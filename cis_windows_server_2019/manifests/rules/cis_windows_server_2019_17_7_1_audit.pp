class cis_windows_server_2019::rules::cis_windows_server_2019_17_7_1_audit {
  exec { 'cis_windows_server_2019_17_7_1audit_ensure_audit_audit_policy_change_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Audit Policy Change', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Audit Policy Change'),
  }
}
