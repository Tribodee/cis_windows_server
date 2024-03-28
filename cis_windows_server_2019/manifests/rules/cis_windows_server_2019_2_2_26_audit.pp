class cis_windows_server_2019::rules::cis_windows_server_2019_2_2_26_audit {
  exec {'cis_windows_server_2019_2_2_26_audit_ensure_deny_log_on_through_remote_desktop_services_is_set_to_guests':
    unless  => cis_windows_server_2019::check_gpresult_users('DenyRemoteInteractiveLogonRight','Guests'),
    command => cis_windows_server_2019::check_gpresult_value('DenyRemoteInteractiveLogonRight'),
  }
}
