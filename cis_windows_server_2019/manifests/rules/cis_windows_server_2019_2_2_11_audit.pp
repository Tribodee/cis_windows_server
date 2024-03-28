class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_11_audit {
  exec {'cis_windows_server_2019_2_2_11_audit_ensure_change_the_system_time_is_set_to_administrators_local_service':
    unless  => cis_windows_server_2019::check_gpresult_users('SystemtimePrivilege','LOCAL SERVICE,Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('SystemtimePrivilege'),
  }
}
