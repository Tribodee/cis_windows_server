class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_5_audit {
  exec {'cis_windows_server_2019_18_4_5_audit_ensure_mss_keepalivetime_how_often_keep_alive_packets_are_sent_in_milliseconds_is_set_to_enabled_300000_or_5_minutes_recommended':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime', '224, 147, 4, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime')
  }
}
