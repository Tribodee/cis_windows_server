class cis_windows_server_2019::rules::cis_windows_server_2019_9_3_4_audit {
  exec { 'cis_windows_server_2019_9_3_4_audit_ensure_windows_firewall_public_settings_display_a_notification_is_set_to_yes':
    unless  => cis_windows_server_2019::check_firewall('public', 'notifyonlisten', 'True'),
    command => cis_windows_server_2019::check_firewall_value('public', 'notifyonlisten'),
  }
}
