class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_1_audit {
  exec { 'cis_windows_server_2019_9_3_1_audit_ensure_windows_firewall_public_firewall_state_is_set_to_on_recommended':
    unless  => cis_windows_server_2019::check_firewall('public', 'enabled', 'True'),
    command => cis_windows_server_2019::check_firewall_value('public', 'enabled'),
  }
}
