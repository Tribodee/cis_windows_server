class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_1_3_audit {
  exec {'cis_windows_server_2019_2_3_1_3_audit_ensure_accounts_guest_account_status_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('EnableGuestAccount','Not Enabled'),
    command  => cis_windows_server_2019::check_gpresult_value('EnableGuestAccount'),
  }
}
