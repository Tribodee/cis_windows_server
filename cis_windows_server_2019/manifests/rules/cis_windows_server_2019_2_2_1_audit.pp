class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_1_audit {
  exec {'cis_windows_server_2019_2_2_1_audit_ensure_access_credential_manager_as_a_trusted_caller_is_set_to_no_one':
    unless  => cis_windows_server_2019::check_gpresult_users("TrustedCredManAccessPrivilege","N/A"),
    command => cis_windows_server_2019::check_gpresult_value("TrustedCredManAccessPrivilege"),
  }
}
