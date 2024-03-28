class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_8_audit {
  exec { 'cis_windows_server_2019_9_3_8_audit_ensure_windows_firewall_public_logging_size_limit_kb_is_set_to_16384_kb_or_greater':
    unless  => cis_windows_server_2019::check_firewall('public', 'logmaxsizekilobytes', '16384'),
    command => cis_windows_server_2019::check_firewall_value('public', 'logmaxsizekilobytes'),
  }
}
