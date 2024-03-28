class cis_windows_server_2019::rules::cis_windows_server_2019_17_5_1_audit {
  exec { 'cis_windows_server_2019_17_5_1_audit_ensure_audit_account_lockout_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Account Lockout', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Account Lockout'),
  }
}
