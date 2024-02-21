class cis_windows_server_2019::rules::cis_windows_server_2019_9_1_1_audit{
  exec {'cis_windows_server_2019_9_1_1_audit_ensure_windows_firewall_domain_firewall_state_is_set_to_on_recommended':
    unless => cis_windows_server_2019::check_firewall('domain','enabled','True'),
    command => cis_windows_server_2019::check_firewall_value('domain','enabled'),
  }
}
