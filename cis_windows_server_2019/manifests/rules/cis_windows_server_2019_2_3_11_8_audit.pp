class cis_windows_server_2019::rules::cis_windows_server_2019_2_3_11_8_audit {
  exec {'cis_windows_server_2019_2_3_11_8_audit_ensure_network_security_ldap_client_signing_requirements_is_set_to_negotiate_signing_or_higher':
    unless   => cis_windows_server_2019::check_gpresult('MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity','1'),
    command  => cis_windows_server_2019::check_gpresult_value('MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity'),
  }
}
