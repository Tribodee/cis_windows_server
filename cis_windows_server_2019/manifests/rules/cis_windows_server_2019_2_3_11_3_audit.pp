class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_11_3_audit {
  exec {'cis_windows_server_2019_2_3_11_3_audit_ensure_network_security_allow_pku2u_authentication_requests_to_this_computer_to_use_online_identities_is_set_to_disabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID','0'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID'),
  }
}
