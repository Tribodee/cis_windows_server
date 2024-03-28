class cis_windows_server_2019::rules::cis_windows_server_2019_1_1_6_audit{
  exec {'cis_windows_server_2019_1_1_6_audit_ensure_store_passwords_using_reversible_encryption_is_set_to_disabled':
    unless => cis_windows_server_2019::check_gpresult('ClearTextPassword','Not Enabled'),
    command => cis_windows_server_2019::check_gpresult_value('ClearTextPassword'),
  }
}
