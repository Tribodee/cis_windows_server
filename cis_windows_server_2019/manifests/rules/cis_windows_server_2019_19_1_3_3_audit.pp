class cis_windows_server_2019::rules::cis_windows_server_2019_19_1_3_3_audit {
  exec {'cis_windows_server_2019_19_1_3_3_audit_ensure_screen_saver_timeout_is_set_to_enabled_900_seconds_or_fewer_but_not_0':
    unless  => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs','900'),
    command => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'),
  }
}
