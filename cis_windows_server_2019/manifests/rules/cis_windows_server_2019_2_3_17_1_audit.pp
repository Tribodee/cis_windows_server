class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_17_1_audit {
  exec {'cis_windows_server_2019_ensure_user_account_control_admin_approval_mode_for_the_built_in_administrator_account_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken'),
  }
}
