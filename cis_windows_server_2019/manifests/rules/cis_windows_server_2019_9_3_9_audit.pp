class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_9_audit {
  exec { 'cis_windows_server_2019_9_3_9_audit_ensure_windows_firewall_public_logging_log_dropped_packets_is_set_to_yes':
    unless  => cis_windows_server_2019::check_firewall('public', 'logblocked', 'True'),
    command => cis_windows_server_2019::check_firewall_value('public', 'logblocked'),
  }
}
