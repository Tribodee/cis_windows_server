class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_28_audit {
  exec {'cis_windows_server_2019_2_2_28_audit_ensure_enable_computer_and_user_accounts_to_be_trusted_for_delegation_is_set_to_no_one_member_server_only':
    unless  => cis_windows_server_2019::check_gpresult_users('EnableDelegationPrivilege','N/A'),
    command => cis_windows_server_2019::check_gpresult_value('EnableDelegationPrivilege'),
  }
}
