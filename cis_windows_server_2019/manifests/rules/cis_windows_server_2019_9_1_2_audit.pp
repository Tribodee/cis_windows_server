class cis_windows_server_2019::rules::cis_windows_server_2019_9_1_2_audit {
  exec {'cis_windows_server_2019_9_1_2_audit_ensure_windows_firewall_domain_inbound_connections_is_set_to_block_default':
    unless => cis_windows_server_2019::check_firewall('domain','defaultinboundaction','Block'),
    command => cis_windows_server_2019::check_firewall_value('domain','defaultinboundaction'),
  }
}
