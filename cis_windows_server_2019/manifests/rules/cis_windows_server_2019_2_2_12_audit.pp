class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_12_audit {
  exec {'cis_windows_server_2019_2_2_12_audit_ensure_change_the_time_zone_is_set_to_administrators_local_service':
    unless  => cis_windows_server_2019::check_gpresult_users('TimeZonePrivilege','LOCAL SERVICE,Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('TimeZonePrivilege'),
  }
}
