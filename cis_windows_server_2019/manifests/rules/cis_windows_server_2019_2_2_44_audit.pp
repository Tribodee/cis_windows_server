class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_44_audit {
  exec {'cis_windows_server_2019_2_2_44_audit_ensure_replace_a_process_level_token_is_set_to_local_service_network_service':
    unless  => cis_windows_server_2019::check_gpresult_users('AssignPrimaryTokenPrivilege','LOCAL SERVICE, NETWORK SERVICE'),
    command => cis_windows_server_2019::check_gpresult_value('AssignPrimaryTokenPrivilege'),
  }
}
