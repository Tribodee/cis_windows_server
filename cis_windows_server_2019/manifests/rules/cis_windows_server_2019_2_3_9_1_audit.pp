class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_9_1_audit {
  exec {'cis_windows_server_2019_2_3_9_1_audit_ensure_microsoft_network_server_amount_of_idle_time_required_before_suspending_session_is_set_to_15_or_fewer_minutes_but_not_0':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect','15'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect'),
  }
}
