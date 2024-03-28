class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_3_audit {
  exec {'cis_windows_server_2019_2_2_3_audit_ensure_access_this_computer_from_the_network_is_set_to_administrators_authenticated_users_member_server_only':
    unless  => cis_windows_server_2019::check_gpresult_users("NetworkLogonRight", "Administrators,Authenticated Users"),
    command => cis_windows_server_2019::check_gpresult_value("NetworkLogonRight"),
  }
}
