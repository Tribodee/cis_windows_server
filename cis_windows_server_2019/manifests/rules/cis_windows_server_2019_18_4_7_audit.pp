class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_7_audit {
  exec {'cis_windows_server_2019_18_4_7_audit_ensure_mss_performrouterdiscovery_allow_irdp_to_detect_and_configure_default_gateway_addresses_could_lead_to_dos_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery')
  }
}
