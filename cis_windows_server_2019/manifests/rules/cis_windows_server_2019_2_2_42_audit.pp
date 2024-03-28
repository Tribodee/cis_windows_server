class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_42_audit {
  exec {'cis_windows_server_2019_2_2_42_audit_ensure_profile_single_process_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('ProfileSingleProcessPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('ProfileSingleProcessPrivilege'),
  }
}
