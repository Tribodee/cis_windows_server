class cis_windows_server_2019::rules::cis_windows_server_2019_1_2_1_audit {
  exec {'cis_windows_server_2019_1_2_1_audit_ensure_account_lockout_duration_is_set_to_15_or_more_minutes':
    unless => cis_windows_server_2019::check_gpresult('LockoutDuration','15'),
    command => cis_windows_server_2019::check_gpresult_value('LockoutDuration'),
  }
}
