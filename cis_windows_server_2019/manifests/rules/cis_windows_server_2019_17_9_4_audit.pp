class cis_windows_server_2019::rules::cis_windows_server_2019_17_9_4_audit {
  exec { 'cis_windows_server_2019_17_9_4_audit_ensure_audit_security_system_extension_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Security System Extension', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Security System Extension'),
  }
}
