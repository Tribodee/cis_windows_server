class cis_windows_server_2019::rules::cis_windows_server_2019_17_5_2_audit{
  exec {'cis_windows_server_2019_17_5_2_audit_ensure_audit_group_membership_is_set_to_success':
    unless => cis_windows_server_2019::check_auditpol('Group Membership','Success'),
    command => cis_windows_server_2019::check_auditpol_value('Group Membership'),
  }
}
