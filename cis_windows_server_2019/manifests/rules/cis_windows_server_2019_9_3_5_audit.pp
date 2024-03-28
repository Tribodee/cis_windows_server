class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_5_audit {
  exec { 'cis_windows_server_2019_9_3_5_audit_ensure_windows_firewall_public_settings_apply_local_firewall_rules_is_set_to_no':
    unless  => cis_windows_server_2019::check_firewall('public', 'allowlocalfirewallrules', 'False'),
    command => cis_windows_server_2019::check_firewall_value('public', 'allowlocalfirewallrules'),
  }
}
