class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_10_4_audit {
  exec {'cis_windows_server_2019_2_3_10_4_audit_ensure_network_access_do_not_allow_storage_of_passwords_and_credentials_for_network_authentication_is_set_to_enabled':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds'),
  }
}
