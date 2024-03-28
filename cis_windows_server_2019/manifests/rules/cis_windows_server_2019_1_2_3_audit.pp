class cis_windows_server_2019::rules::cis_windows_server_2019_1_2_3_audit {
  exec {'cis_windows_server_2019_1_2_3_audit_ensure_reset_account_lockout_counter_after_is_set_to_15_or_more_minutes':
    unless => cis_windows_server_2019::check_gpresult('ResetLockoutCount','15'),
    command => cis_windows_server_2019::check_gpresult_value('ResetLockoutCount'),
  }
}
