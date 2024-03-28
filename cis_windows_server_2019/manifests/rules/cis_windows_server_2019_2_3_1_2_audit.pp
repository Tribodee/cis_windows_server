class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_1_2_audit {
  exec {'cis_windows_server_2019_2_3_1_2_audit_ensure_accounts_block_microsoft_accounts_is_set_to_users_cant_add_or_log_on_with_microsoft_accounts':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser','3'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser'),
  }
}
