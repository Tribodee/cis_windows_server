class cis_windows_server_2019::rules::cis_windows_server_2019_9_1_3_audit {
  exec {'cis_windows_server_2019_9_1_3_audit_ensure_windows_firewall_domain_outbound_connections_is_set_to_allow_default':
    unless => cis_windows_server_2019::check_firewall('domain','defaultoutboundaction','Allow'),
    command => cis_windows_server_2019::check_firewall_value('domain','defaultoutboundaction'),
  }
}
