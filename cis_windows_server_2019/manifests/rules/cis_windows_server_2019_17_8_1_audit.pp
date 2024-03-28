class cis_windows_server_2019::rules::cis_windows_server_2019_17_8_1_audit {
  exec { 'cis_windows_server_2019_17_8_1_audit_ensure_audit_sensitive_privilege_use_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Sensitive Privilege Use', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Sensitive Privilege Use'),
  }
}
