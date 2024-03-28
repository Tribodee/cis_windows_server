class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_33_audit {
  exec {'cis_windows_server_2019_2_2_33_audit_ensure_increase_scheduling_priority_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('IncreaseBasePriorityPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('IncreaseBasePriorityPrivilege'),
  }
}
