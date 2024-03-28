class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_6_audit {
  exec {'cis_windows_server_2019_2_2_6_audit_ensure_adjust_memory_quotas_for_a_process_is_set_to_administrators_local_service_network_service':
    unless  => cis_windows_server_2019::check_gpresult_users('IncreaseQuotaPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('IncreaseQuotaPrivilege'),
  }
}
