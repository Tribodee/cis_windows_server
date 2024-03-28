class cis_windows_server_2019::rules::cis_windows_server_2019_9_2_2_audit {
  exec {'cis_windows_server_2019_9_2_2_audit_ensure_windows_firewall_private_inbound_connections_is_set_to_block_default':
    unless => cis_windows_server_2019::check_firewall('private','defaultinboundaction','Block'),
    command => cis_windows_server_2019::check_firewall_value('private','defaultinboundaction'),
  }
}
