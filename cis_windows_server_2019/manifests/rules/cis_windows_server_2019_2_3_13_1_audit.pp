class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_13_1_audit {
  exec {'cis_windows_server_2019_2_3_13_1_audit_ensure_shutdown_allow_system_to_be_shut_down_without_having_to_log_on_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon'),
  }
}
