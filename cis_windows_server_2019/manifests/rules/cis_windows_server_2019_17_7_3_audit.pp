class cis_windows_server_2019::rules::cis_windows_server_2019_17_7_3_audit {
  exec { 'cis_windows_server_2019_17_7_3_audit_ensure_audit_authorization_policy_change_is_set_to_success':
    unless  => cis_windows_server_2019::check_auditpol('Authorization Policy Change', 'Success'),
    command => cis_windows_server_2019::check_auditpol_value('Authorization Policy Change'),
  }
}
