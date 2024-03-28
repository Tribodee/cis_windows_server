class cis_windows_server_2019::rules::cis_windows_server_2019_1_1_1_audit{
  exec {'cis_windows_server_2019_1_1_1_audit_ensure_enforce_password_history_is_set_to_24_or_more_password':
    unless => cis_windows_server_2019::check_gpresult('PasswordHistorySize','24'),
    command => cis_windows_server_2019::check_gpresult_value('PasswordHistorySize'),
  }
}
