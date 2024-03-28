class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_3_audit {
  exec { 'cis_windows_server_2019_9_3_3_audit_ensure_windows_firewall_public_outbound_connections_is_set_to_allow_default':
    unless  => cis_windows_server_2019::check_firewall('public', 'defaultoutboundaction', 'Allow'),
    command => cis_windows_server_2019::check_firewall_value('public', 'defaultoutboundaction'),
  }
}
