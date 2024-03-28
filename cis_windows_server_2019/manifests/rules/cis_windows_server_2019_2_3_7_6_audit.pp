class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_7_6_audit {
  exec {'cis_windows_server_2019_2_3_7_6_audit_ensure_interactive_logon_number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available_is_set_to_4_or_fewer_logons_ms_only':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount','4'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount'),
  }
}
