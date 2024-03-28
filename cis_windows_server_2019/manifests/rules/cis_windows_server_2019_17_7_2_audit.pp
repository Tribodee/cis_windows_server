class cis_windows_server_2019::rules::cis_windows_server_2019_17_7_2_audit{
  exec {'cis_windows_server_2019_17_7_2_audit_ensure_audit_authentication_policy_change_is_set_to_success':
    unless => cis_windows_server_2019::check_auditpol('Authentication Policy Change','Success'),
    command => cis_windows_server_2019::check_auditpol_value('Authentication Policy Change'),
  }
}
