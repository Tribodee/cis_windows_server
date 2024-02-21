class cis_windows_server_2019::rules::cis_windows_server_2019_17_9_1_audit{
  exec {'cis_windows_server_2019_17_9_1_audit_ensure_audit_ipsec_driver_is_set_to_success_and_failure':
    unless => cis_windows_server_2019::check_auditpol('IPsec Driver','Success and Failure'),
    command => cis_windows_server_2019::check_auditpol_value('IPsec Driver'),
  }
}
