class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_10_audit {
  exec { 'cis_windows_server_2019_9_3_10_audit_ensure_windows_firewall_public_logging_log_successful_connections_is_set_to_yes':
    unless  => cis_windows_server_2019::check_firewall('public', 'logallowed', 'True'),
    command => cis_windows_server_2019::check_firewall_value('public', 'logallowed'),
  }
}
