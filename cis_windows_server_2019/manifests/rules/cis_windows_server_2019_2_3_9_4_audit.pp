class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_9_4_audit {
  exec {'cis_windows_server_2019_2_3_9_4_audit_ensure_microsoft_network_server_disconnect_clients_when_logon_hours_expire_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff'),
  }
}
