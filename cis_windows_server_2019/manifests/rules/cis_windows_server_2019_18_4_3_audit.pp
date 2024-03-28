class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_3_audit {
  exec {'cis_windows_server_2019_18_4_3_audit_ensure_mss_disableipsourcerouting_ip_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_enabled_highest_protection_source_routing_is_completely_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting', '2, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting')
  }
}
