class cis_windows_server_2019::rules::cis_windows_server_2019_17_3_1_audit {
  exec { 'cis_windows_server_2019_17_3_1_audit_ensure_audit_pnp_activity_is_set_to_success':
    unless  => cis_windows_server_2019::check_auditpol('Plug and Play Events', 'Success'),
    command => cis_windows_server_2019::check_auditpol_value('Plug and Play Events'),
  }
}
