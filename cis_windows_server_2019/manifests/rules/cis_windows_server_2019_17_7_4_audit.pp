class cis_windows_server_2019::rules::cis_windows_server_2019_17_7_4_audit{
  exec {'cis_windows_server_2019_17_7_4_audit_ensure_audit_mpssvc_rule_level_policy_change_is_set_to_success_and_failure':
    unless => cis_windows_server_2019::check_auditpol('MPSSVC Rule-Level Policy Change','Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('MPSSVC Rule-Level Policy Change'),
  }
}
