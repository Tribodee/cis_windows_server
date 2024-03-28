class cis_windows_server_2019::rules::cis_windows_server_2019_17_1_1_audit {
  exec { 'cis_windows_server_2019_17_1_1_audit_ensure_audit_credential_validation_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Credential Validation', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Credential Validation'),
  }
}
