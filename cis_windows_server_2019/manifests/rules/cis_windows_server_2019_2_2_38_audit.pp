class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_38_audit {
  exec {'cis_windows_server_2019_2_2_38_audit_ensure_manage_auditing_and_security_log_is_set_to_administrators_ms_only':
    unless  => cis_windows_server_2019::check_gpresult_users('SecurityPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('SecurityPrivilege'),
  }
}
