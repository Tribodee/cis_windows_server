class cis_windows_server_2019::rules::cis_windows_server_2019_17_5_3_audit {
  exec { 'cis_windows_server_2019_17_5_3_audit_ensure_audit_logoff_is_set_to_success':
    unless  => cis_windows_server_2019::check_auditpol('Logoff', 'Success'),
    command => cis_windows_server_2019::check_auditpol_value('Logoff'),
  }
}
