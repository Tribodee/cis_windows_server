class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_32_audit {
  exec {'cis_windows_server_2019_2_2_32_audit_ensure_impersonate_a_client_after_authentication_is_set_to_administrators_local_service_network_service_service_and_when_the_web_server_iis_role_with_web_services_role_service_is_installed_iis_iusrs_member_server_only':
    unless  => cis_windows_server_2019::check_gpresult_users('ImpersonatePrivilege','Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'),
    command => cis_windows_server_2019::check_gpresult_value('ImpersonatePrivilege'),
  }
}
