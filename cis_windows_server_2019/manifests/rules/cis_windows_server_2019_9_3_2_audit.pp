class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_2_audit {
  exec { 'cis_windows_server_2019_9_3_2_audit_ensure_windows_firewall_public_inbound_connections_is_set_to_block_default':
    unless  => cis_windows_server_2019::check_firewall('public', 'defaultinboundaction', 'Block'),
    command => cis_windows_server_2019::check_firewall_value('public', 'defaultinboundaction'),
  }
}
