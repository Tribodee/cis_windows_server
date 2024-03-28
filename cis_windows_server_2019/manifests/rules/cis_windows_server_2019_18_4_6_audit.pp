class cis_windows_server_2019::rules::cis_windows_server_2019_18_4_6_audit {
  exec {'cis_windows_server_2019_18_4_6_audit_ensure_mss_nonamereleaseondemand_allow_the_computer_to_ignore_netbios_name_release_requests_except_from_wins_servers_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand')
  }
}
