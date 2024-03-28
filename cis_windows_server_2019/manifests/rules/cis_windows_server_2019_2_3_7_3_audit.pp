class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_3_audit {
  exec {'cis_windows_server_2019_2_3_7_3_audit_ensure_interactive_logon_machine_inactivity_limit_is_set_to_900_or_fewer_seconds_but_not_0':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs','900'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'),
  }
}
