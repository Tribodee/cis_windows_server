class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_4_audit {
  exec {'cis_windows_server_2019_18_4_4_audit_ensure_mss_enableicmpredirect_allow_icmp_redirects_to_override_ospf_generated_routes_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect', '', 'disabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect')
  }
}
