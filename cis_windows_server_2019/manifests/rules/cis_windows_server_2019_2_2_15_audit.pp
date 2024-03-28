class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_15_audit {
  exec {'cis_windows_server_2019_2_2_15_audit_ensure_create_global_objects_is_set_to_administrators_local_service_network_service_service':
    unless  => cis_windows_server_2019::check_gpresult_users('CreateGlobalPrivilege','SERVICE,NETWORK SERVICE,LOCAL SERVICE,Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('CreateGlobalPrivilege'),
  }
}
