class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_1_4_audit {
  exec {'cis_windows_server_2019_2_3_1_4_audit_ensure_accounts_limit_local_account_use_of_blank_passwords_to_console_logon_only_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse'),
  }
}
