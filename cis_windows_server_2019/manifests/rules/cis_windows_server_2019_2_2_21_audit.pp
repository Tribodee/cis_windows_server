class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_21_audit {
  exec {'cis_windows_server_2019_2_2_21_audit_ensure_deny_access_to_this_computer_from_the_network_to_include_guests_ms_only':
    unless  => cis_windows_server_2019::check_gpresult_users('DenyNetworkLogonRight','Guests'),
    command => cis_windows_server_2019::check_gpresult_value('DenyNetworkLogonRight'),
  }
}
