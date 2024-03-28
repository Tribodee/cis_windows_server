class cis_windows_server_2019::rules::cis_windows_server_2019_9_1_7_audit{
  exec {'cis_windows_server_2019_9_1_7_audit_ensure_windows_firewall_domain_logging_log_dropped_packets_is_set_to_yes':
    unless => cis_windows_server_2019::check_firewall('domain','logblocked','True'),
    command => cis_windows_server_2019::check_firewall_value('domain','logblocked'),
  }
}
