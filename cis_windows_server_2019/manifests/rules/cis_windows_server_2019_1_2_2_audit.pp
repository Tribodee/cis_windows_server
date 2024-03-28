class cis_windows_server_2019::rules::cis_windows_server_2019_1_2_2_audit {
  exec {'cis_windows_server_2019_1_2_2_audit_ensure_account_lockout_threshold_is_set_to_5_or_fewer_invalid_logon_attempts_but_not_0':
    unless => cis_windows_server_2019::check_gpresult('LockoutBadCount','5'),
    command => cis_windows_server_2019::check_gpresult_value('LockoutBadCount'),
  }
}
