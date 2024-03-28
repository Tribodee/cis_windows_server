class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_19_audit {
  exec {'cis_windows_server_2019_2_2_19_audit_ensure_debug_programs_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('DebugPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('DebugPrivilege'),
  }
}
