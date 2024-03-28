class cis_windows_server_2019::rules::cis_windows_server_2019_9_2_7_audit {
  exec { 'cis_windows_server_2019_9_2_7_audit_ensure_windows_firewall_private_logging_log_dropped_packets_is_set_to_yes':
    unless  => cis_windows_server_2019::check_firewall('private', 'logblocked', 'True'),
    command => cis_windows_server_2019::check_firewall_value('private', 'logblocked'),
  }
}
