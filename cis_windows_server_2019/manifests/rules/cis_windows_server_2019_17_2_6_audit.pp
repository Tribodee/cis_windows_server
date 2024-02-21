class cis_windows_server_2019::rules::cis_windows_server_2019_17_2_6_audit{
  exec {'cis_windows_server_2019_17_2_6_audit_ensure_audit_user_account_management_is_set_to_success_and_failure':
    unless => cis_windows_server_2019::check_auditpol('User Account Management','Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('User Account Management'),
  }  
}
