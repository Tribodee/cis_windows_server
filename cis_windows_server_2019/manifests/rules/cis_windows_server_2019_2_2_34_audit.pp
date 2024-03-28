class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_34_audit {
  exec {'cis_windows_server_2019_2_2_34_audit_ensure_load_and_unload_device_drivers_is_set_to_administrators':
    unless  => cis_windows_server_2019::check_gpresult_users('LoadDriverPrivilege','Administrators'),
    command => cis_windows_server_2019::check_gpresult_value('LoadDriverPrivilege'),
  }
}
