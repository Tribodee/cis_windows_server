class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_11_audit {
  exec {'cis_windows_server_2019_18_4_11_audit_ensure_mss_tcpmaxdataretransmissions_how_many_times_unacknowledged_data_is_retransmitted_is_set_to_enabled_3':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions', '3, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions')
  }
}
