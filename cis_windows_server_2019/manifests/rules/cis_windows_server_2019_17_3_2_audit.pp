class cis_windows_server_2019::rules::cis_windows_server_2019_17_3_2_audit{
  exec {'cis_windows_server_2019_17_3_2_audit_ensure_audit_process_creation_is_set_to_success':
    unless => cis_windows_server_2019::check_auditpol('Process Creation','Success'),
    command => cis_windows_server_2019::check_auditpol_value('Process Creation'),
  }
}
