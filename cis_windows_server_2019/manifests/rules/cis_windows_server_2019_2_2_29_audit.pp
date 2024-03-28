class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_29_audit {
  exec {'cis_windows_server_2019_2_2_29_audit_ensure_force_shutdown_from_a_remote_system_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('RemoteShutdownPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('RemoteShutdownPrivilege'),
  }
}
