class cis_windows_server_2019::rules::cis_windows_server_2019_9_1_6_audit {
  exec {'cis_windows_server_2019_9_1_6_audit_ensure_windows_firewall_domain_logging_size_limit_kb_or_greater':
    unless => cis_windows_server_2019::check_firewall('domain','logmaxsizekilobytes','16384'),
    command => cis_windows_server_2019::check_firewall_value('domain','logmaxsizekilobytes'),
  }
}
