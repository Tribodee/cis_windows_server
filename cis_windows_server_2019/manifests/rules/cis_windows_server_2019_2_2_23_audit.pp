class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_23_audit {
  exec {'cis_windows_server_2019_2_2_23_audit_ensure_deny_log_on_as_a_service_to_include_guests':
    unless  => cis_windows_server_2019::check_gpresult_users('DenyServiceLogonRight','Guests'),
    command => cis_windows_server_2019::check_gpresult_value('DenyServiceLogonRight'),
  }
}
