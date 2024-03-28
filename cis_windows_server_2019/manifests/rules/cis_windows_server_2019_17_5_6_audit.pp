class cis_windows_server_2019::rules::cis_windows_server_2019_17_5_6_audit{
  exec {'cis_windows_server_2019_17_5_6_audit_ensure_audit_special_logon_is_set_to_success':
    unless => cis_windows_server_2019::check_auditpol('Special Logon','Success'),
    command => cis_windows_server_2019::check_auditpol_value('Special Logon'),
  }
}
