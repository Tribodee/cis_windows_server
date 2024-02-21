class cis_windows_server_2019::rules::cis_windows_server_2019_17_9_3_audit{
  exec {'cis_windows_server_2019_17_9_3_audit_ensure_audit_security_state_change_is_set_to_success':
    unless => cis_windows_server_2019::check_auditpol('Security State Change','Success'),
    command => cis_windows_server_2019::check_auditpol_value('Security State Change'),
  }
}
