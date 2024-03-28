class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_43_audit {
  exec {'cis_windows_server_2019_2_2_43_audit_ensure_profile_system_performance_is_set_to_administrators_nt_service_wdiservicehost':
    unless  => cis_windows_server_2019::check_gpresult_users('SystemProfilePrivilege','Administrators, NT SERVICE\WdiServiceHost'),
    command => cis_windows_server_2019::check_gpresult_value('SystemProfilePrivilege'),
  }
}
