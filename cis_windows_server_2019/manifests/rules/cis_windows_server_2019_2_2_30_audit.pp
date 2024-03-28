class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_30_audit {
  exec {'cis_windows_server_2019_2_2_30_audit_ensure_generate_security_audits_is_set_to_local_service_network_service':
    unless  => cis_windows_server_2019::check_gpresult_users('AuditPrivilege','LOCAL SERVICE, NETWORK SERVICE'),
    command => cis_windows_server_2019::check_gpresult_value('AuditPrivilege'),
  }
}
