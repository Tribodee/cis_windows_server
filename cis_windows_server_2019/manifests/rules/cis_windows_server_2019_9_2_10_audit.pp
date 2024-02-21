class cis_windows_server_2019::rules::cis_windows_server_2019_9_2_10_audit {
  exec {'cis_windows_server_2019_9_2_10_audit_ensure_windows_firewall_private_logging_log_successful_connections_is_set_to_yes':
    unless => cis_windows_server_2019::check_firewall('private','logallowed','True'),
    command => cis_windows_server_2019::check_firewall_value('private','logallowed'),
  }
}
