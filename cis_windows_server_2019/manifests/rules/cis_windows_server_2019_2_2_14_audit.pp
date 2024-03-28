class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_14_audit {
  exec {'cis_windows_server_2019_2_2_14_audit_ensure_create_a_token_object_is_set_to_no_one':
    unless  => cis_windows_server_2019::check_gpresult_users('CreateTokenPrivilege','N/A'),
    command => cis_windows_server_2019::check_gpresult_value('CreateTokenPrivilege'),
  }
}
