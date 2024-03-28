class cis_windows_server_2019::rules::cis_windows_server_2019_18_5_11_4_audit {
  exec {'cis_windows_server_2019_18_5_11_4_audit_ensure_require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_enabled':
    unless => cis_windows_server_2019::check_gpresult_folder_id ('SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation', '1, 0, 0, 0', 'Enabled',),
    command => cis_windows_server_2019::check_gpresult_folder_id_value ('SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation')
  }
}

