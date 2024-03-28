class cis_windows_server_2019::rules::cis_windows_server_2019_17_1_3_audit {
  exec { 'cis_windows_server_2019_17_1_3_audit_ensure_audit_kerberos_service_ticket_operations_is_set_to_success_and_failure':
    unless  => cis_windows_server_2019::check_auditpol('Kerberos Service Ticket Operations', 'Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('Kerberos Service Ticket Operations'),
  }
}
