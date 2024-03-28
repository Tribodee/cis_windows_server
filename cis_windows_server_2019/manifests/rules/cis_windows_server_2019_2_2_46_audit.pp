class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_46_audit {
  exec {'cis_windows_server_2019_2_2_46_audit_ensure_shut_down_the_system_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('ShutdownPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('ShutdownPrivilege'),
  }
}
