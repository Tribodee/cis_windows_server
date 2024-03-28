class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_17_7_audit {
  exec {'cis_windows_server_2019_2_3_17_7_audit_ensure_user_account_control_run_all_administrators_in_admin_approval_mode_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'),
  }
}
