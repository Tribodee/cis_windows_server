class cis_windows_server_2019::rules::cis_windows_server_2019_9_2_3_audit {
  exec {'cis_windows_server_2019_9_2_3_audit_ensure_windows_firewall_private_outbound_connections_is_set_to_allow_default':
    unless => cis_windows_server_2019::check_firewall('private','defaultoutboundaction','Allow'),
    command => cis_windows_server_2019::check_firewall_value('private','defaultoutboundaction'),
  }
}
